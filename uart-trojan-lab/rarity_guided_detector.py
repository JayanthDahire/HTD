#!/usr/bin/env python3
"""Beginner-friendly, rarity-guided UART Trojan test generator.

This tool compares clean and suspect RTL sources, flags suspicious added/changed
lines, extracts candidate input bytes and named trigger sequences, estimates the
probability of each *specific byte sequence at one window* under IID uniform
8-bit inputs, and generates an SV header consumed by trojan_rarity_tb.sv.

The probability model is an explicit assumption, not a measurement of a real
workload. Exact sequences inferred from the suspect source are always tested.
Additional Cartesian-product searches are enabled for lengths whose per-window
probability is at or below --rarity-threshold. This is a source-assisted
prototype, not a general Verilog parser or a universal Trojan detector.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
MODULE_RE = re.compile(r"\bmodule\s+(?:automatic\s+|static\s+)?([A-Za-z_$][\w$]*)\b(.*?)\bendmodule\b", re.I | re.S)
LOCALPARAM_RE = re.compile(r"\blocalparam\b(.*?);", re.I | re.S)
ASSIGN_LHS_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*=", re.I)
PARAM_LITERAL_RE = re.compile(
    r"\b(?:parameter|localparam)\s+(?:\[[^\]]+\]\s*)?"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:\d+\s*)?'\s*(?P<base>[bBoOdDhH])\s*(?P<digits>[0-9a-fA-F_xXzZ?]+)",
    re.I | re.S,
)
DIRECT_COMPARE_RE = re.compile(
    r"\b(?:rx_data_in|rx_data|data|byte_in)\s*==\s*"
    r"(?:\d+\s*)?'\s*(?P<base>[bBoOdDhH])\s*(?P<digits>[0-9a-fA-F_xXzZ?]+)",
    re.I,
)
TRIGGER_NAME_RE = re.compile(
    r"(?:INPUT|FIRST|SECOND|THIRD|FOURTH|FIFTH|SIXTH|SEVENTH|EIGHTH|TRIGGER|TOKEN[0-9]*)$", re.I
)
ORDINALS = ["FIRST", "SECOND", "THIRD", "FOURTH", "FIFTH", "SIXTH", "SEVENTH", "EIGHTH"]
ORDINAL_INDEX = {name: i for i, name in enumerate(ORDINALS)}
MAX_STAGE_COMBINATIONS = 2_000_000


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def strip_comments(text: str) -> str:
    return COMMENT_RE.sub(" ", text)


def parse_literal(base: str, digits: str) -> int | None:
    digits = digits.replace("_", "")
    if not digits or any(c in digits.lower() for c in "xz?"):
        return None
    radix = {"b": 2, "o": 8, "d": 10, "h": 16}.get(base.lower())
    if radix is None:
        return None
    try:
        return int(digits, radix) & 0xFF
    except ValueError:
        return None


def parse_candidate_list(value: str) -> list[int]:
    values: set[int] = set()
    for item in value.split(","):
        token = item.strip().replace("_", "")
        if not token:
            continue
        try:
            number = int(token, 0)
        except ValueError:
            number = int(token, 16) if not re.fullmatch(r"[0-9]+", token) else int(token, 10)
        if not 0 <= number <= 255:
            raise ValueError(f"candidate byte {token!r} is outside 0..255")
        values.add(number)
    if not values:
        raise ValueError("candidate byte list is empty")
    return sorted(values)


def extract_modules(text: str) -> list[dict[str, Any]]:
    modules: list[dict[str, Any]] = []
    for match in MODULE_RE.finditer(strip_comments(text)):
        name, body = match.group(1), match.group(2)
        groups: list[dict[str, Any]] = []
        for lm in LOCALPARAM_RE.finditer(body):
            labels = ASSIGN_LHS_RE.findall(lm.group(1))
            upper = [x.upper() for x in labels]
            if labels and any(any(word in label for word in ("IDLE", "GOT", "ACTIVE", "START", "STOP", "DATA", "FIRST", "SECOND", "THIRD", "FOURTH")) for label in upper):
                groups.append({"labels": labels})
        modules.append({"module": name, "state_groups": groups})
    return modules


def extract_parameter_values(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for m in PARAM_LITERAL_RE.finditer(strip_comments(text)):
        value = parse_literal(m.group("base"), m.group("digits"))
        if value is not None:
            result[m.group("name").upper()] = value
    return result


def extract_candidates(text: str) -> list[int]:
    clean = strip_comments(text)
    found: set[int] = set()
    for m in PARAM_LITERAL_RE.finditer(clean):
        name = m.group("name").upper()
        trigger_namespace = any(token in name for token in ("TROJAN", "TRIGGER", "TOKEN", "SEQUENCE", "SECRET"))
        if trigger_namespace and TRIGGER_NAME_RE.search(name) and not name.endswith(("OUTPUT", "RESULT", "REPLACEMENT", "MASK")):
            value = parse_literal(m.group("base"), m.group("digits"))
            if value is not None:
                found.add(value)
    for m in DIRECT_COMPARE_RE.finditer(clean):
        value = parse_literal(m.group("base"), m.group("digits"))
        if value is not None:
            found.add(value)
    return sorted(found)


def _comparison_value(rhs: str, parameters: dict[str, int]) -> int | None:
    token = rhs.strip()
    if token.upper() in parameters:
        return parameters[token.upper()]
    literal = re.fullmatch(r"(?:\d+\s*)?'\s*([bBoOdDhH])\s*([0-9a-fA-F_xXzZ?]+)", token)
    if literal:
        return parse_literal(literal.group(1), literal.group(2))
    return None


def extract_direct_fsm_payload_sequences(text: str) -> list[dict[str, Any]]:
    """Best-effort extraction for simple case(state) FSMs with input comparisons.

    This mainly supports designs that compare rx_data_in directly with literals
    rather than giving the values parameter names. It is deliberately not a full
    Verilog parser and only handles simple, named-state case branches.
    """
    clean = strip_comments(text)
    parameters = extract_parameter_values(clean)
    found: list[dict[str, Any]] = []
    branch_re = re.compile(
        r"\bif\s*\(\s*rx_data_in\s*==\s*(?P<rhs>[^)]+)\)\s*"
        r"(?P<branch>.*?)(?=\belse\b|\Z)", re.I | re.S
    )
    state_assign_re = re.compile(r"\bstate\s*<=\s*([A-Za-z_$][\w$]*)", re.I)
    payload_re = re.compile(r"\b(?:trojan_side_effect|rx_data_out|trigger_active|trojan_enable)\s*<=\s*(?!rx_data_in\b)[^;]+", re.I)
    arm_re = re.compile(
        r"^[ \t]*(?P<state>[A-Za-z_$][\w$]*)[ \t]*:[ \t]*begin\b(?P<body>.*?)"
        r"(?=^[ \t]*(?:[A-Za-z_$][\w$]*|default)[ \t]*:[ \t]*(?:begin\b|$)|\Z)",
        re.I | re.M | re.S,
    )

    for module_match in MODULE_RE.finditer(clean):
        module_name, module_body = module_match.group(1), module_match.group(2)
        for case_match in re.finditer(r"\bcase\s*\(\s*state\s*\)(.*?)\bendcase\b", module_body, re.I | re.S):
            case_body = case_match.group(1)
            arms = {m.group("state").upper(): m.group("body") for m in arm_re.finditer(case_body)}
            if not arms:
                continue
            start_state = "IDLE" if "IDLE" in arms else next(iter(arms))
            edges: list[dict[str, Any]] = []
            for src, arm_body in arms.items():
                for branch_match in branch_re.finditer(arm_body):
                    byte_value = _comparison_value(branch_match.group("rhs"), parameters)
                    if byte_value is None:
                        continue
                    branch = branch_match.group("branch")
                    next_match = state_assign_re.search(branch)
                    next_state = next_match.group(1).upper() if next_match else None
                    has_payload = bool(payload_re.search(branch))
                    if next_state or has_payload:
                        edges.append({"src": src, "byte": byte_value, "dst": next_state, "payload": has_payload})

            def path_to(target: str) -> list[int] | None:
                if target == start_state:
                    return []
                queue: list[tuple[str, list[int]]] = [(start_state, [])]
                visited = {start_state}
                cursor = 0
                while cursor < len(queue):
                    current, path = queue[cursor]
                    cursor += 1
                    for edge in edges:
                        if edge["src"] != current or not edge["dst"]:
                            continue
                        dest = edge["dst"]
                        new_path = path + [edge["byte"]]
                        if dest == target:
                            return new_path
                        if dest not in visited:
                            visited.add(dest)
                            queue.append((dest, new_path))
                return None

            for edge in edges:
                if not edge["payload"]:
                    continue
                prefix = path_to(edge["src"])
                if prefix is None:
                    continue
                sequence = prefix + [edge["byte"]]
                if sequence:
                    found.append({
                        "name": f"{module_name}:{edge['src']} payload path",
                        "bytes": sequence,
                        "source": "inferred from simple case(state) transitions and a payload assignment",
                    })
    return found


def extract_exact_sequences(text: str) -> list[dict[str, Any]]:
    """Infer common named parameter sequences; this is intentionally heuristic."""
    params = extract_parameter_values(text)
    sequences: list[dict[str, Any]] = []
    seen: set[tuple[int, ...]] = set()

    # Explicit single-byte input parameter patterns.
    for name, value in params.items():
        has_trigger_namespace = any(token in name for token in ("TROJAN", "TRIGGER", "TOKEN", "SEQUENCE", "SECRET"))
        if has_trigger_namespace and (("SINGLE" in name and name.endswith("INPUT")) or name.endswith("TRIGGER_BYTE")):
            seq = (value,)
            if seq not in seen:
                sequences.append({"name": name, "bytes": list(seq), "source": "named single-byte parameter"})
                seen.add(seq)

    # Group parameters like TROJAN_TWO_FIRST/SECOND or TRIGGER_FIRST/SECOND/THIRD.
    grouped: dict[str, dict[int, tuple[str, int]]] = defaultdict(dict)
    for name, value in params.items():
        match = re.match(r"^(.*)_([A-Z]+)$", name)
        if not match or match.group(2) not in ORDINAL_INDEX:
            continue
        prefix, ordinal = match.group(1), match.group(2)
        if not any(token in prefix for token in ("TROJAN", "TRIGGER", "TOKEN", "SEQUENCE", "SECRET")):
            continue
        grouped[prefix][ORDINAL_INDEX[ordinal]] = (name, value)

    for prefix, slots in sorted(grouped.items()):
        if 0 not in slots or 1 not in slots:
            continue
        vals: list[int] = []
        names: list[str] = []
        idx = 0
        while idx in slots:
            pname, pvalue = slots[idx]
            vals.append(pvalue)
            names.append(pname)
            idx += 1
        if len(vals) >= 2:
            seq = tuple(vals)
            if seq not in seen:
                sequences.append({"name": prefix, "bytes": vals, "source": "ordered parameter family: " + ", ".join(names)})
                seen.add(seq)

    # Also recover simple FSM paths whose byte comparisons are numeric literals,
    # e.g. IDLE --AA--> GOT_AA --BB--> GOT_BB --CC--> ACTIVE.
    for item in extract_direct_fsm_payload_sequences(text):
        seq = tuple(item["bytes"])
        if seq not in seen:
            sequences.append(item)
            seen.add(seq)

    # Sort by sequence length then name to keep deterministic test order.
    sequences.sort(key=lambda item: (len(item["bytes"]), item["name"], item["bytes"]))
    return sequences


def normalize_lines(text: str) -> list[str]:
    return [s for line in strip_comments(text).splitlines() if (s := re.sub(r"\s+", " ", line).strip())]


def source_diff(clean_text: str, suspect_text: str, clean_name: str, suspect_name: str) -> tuple[str, str]:
    raw = "".join(difflib.unified_diff(clean_text.splitlines(keepends=True), suspect_text.splitlines(keepends=True), fromfile=clean_name, tofile=suspect_name, lineterm="\n"))
    a = [line + "\n" for line in normalize_lines(clean_text)]
    b = [line + "\n" for line in normalize_lines(suspect_text)]
    normalized = "".join(difflib.unified_diff(a, b, fromfile=clean_name + " (normalized)", tofile=suspect_name + " (normalized)", lineterm="\n"))
    return raw or "No textual differences.\n", normalized or "No normalized code differences detected.\n"


def extract_added_suspicious_lines(normalized_diff: str) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw_line in normalized_diff.splitlines():
        if not raw_line.startswith("+") or raw_line.startswith("+++"):
            continue
        line = raw_line[1:].strip()
        if not line or line in seen:
            continue
        seen.add(line)
        reasons = []
        if re.search(r"\b(if|else if|case|casez|casex)\b", line, re.I): reasons.append("conditional/control flow")
        if re.search(r"==|!=|<=|>=", line): reasons.append("comparison or assignment")
        if re.search(r"\b(state|counter|count|prev|history|got|active)\w*\b", line, re.I): reasons.append("state/history/counter reference")
        if re.search(r"\b(rx_data|rx_valid|tx_data|data_out|side_effect|output)\w*\b", line, re.I): reasons.append("possible observable data/control path")
        if re.search(r"\b(trojan|trigger|token|first|second|third|fourth)\w*\b", line, re.I): reasons.append("trigger-related naming")
        if reasons:
            score = 0
            if "trigger-related naming" in reasons: score += 3
            if "possible observable data/control path" in reasons: score += 2
            if "conditional/control flow" in reasons: score += 1
            if "comparison or assignment" in reasons: score += 1
            if "state/history/counter reference" in reasons: score += 1
            priority = "HIGH" if score >= 4 else "MEDIUM" if score >= 2 else "LOW"
            candidates.append({"line": line, "reasons": "; ".join(reasons), "score": score, "priority": priority})
    return candidates


def infer_max_len(suspect_modules: list[dict[str, Any]], exact_sequences: list[dict[str, Any]]) -> int:
    max_len = max((len(s["bytes"]) for s in exact_sequences), default=1)
    for module in suspect_modules:
        for group in module["state_groups"]:
            labels = [label.upper() for label in group["labels"]]
            # Naming-based search hint: FOUR_FIRST implies four, etc.
            for label in labels:
                for word, value in (("TWO", 2), ("THREE", 3), ("FOUR", 4), ("FIVE", 5), ("SIX", 6), ("SEVEN", 7), ("EIGHT", 8)):
                    if re.search(rf"(?:^|_){word}_FIRST(?:_|$)", label):
                        max_len = max(max_len, value)
            got_count = sum(bool(re.search(r"(?:^|_)GOT(?:_|$)", label)) for label in labels)
            if got_count >= 1:
                max_len = max(max_len, got_count + 1)
    return min(max_len, 6)


def exact_seq_probability(length: int) -> float:
    return 1.0 / (256 ** length)


def make_header(candidates: list[int], exact_sequences: list[dict[str, Any]], max_len: int, threshold: float, path: Path) -> None:
    # Deduplicate exact multi-byte sequences and omit targets beyond the search bound.
    exact_items: list[dict[str, Any]] = []
    seen: set[tuple[int, ...]] = set()
    for item in exact_sequences:
        seq = tuple(item["bytes"])
        if 2 <= len(seq) <= max_len and seq not in seen:
            exact_items.append({"name": item["name"], "bytes": list(seq), "source": item["source"]})
            seen.add(seq)
    lines = [
        "// Auto-generated by rarity_guided_detector.py; do not edit manually.",
        f"// Rarity threshold is probability per fixed window under IID uniform byte inputs: {threshold:.12g}.",
        f"localparam integer SEARCH_MAX_LEN = {max_len};",
        f"localparam integer CANDIDATE_COUNT = {len(candidates)};",
        f"localparam integer EXACT_SEQUENCE_COUNT = {len(exact_items)};",
        f"localparam integer ENUMERATE_LEN_1 = {int(exact_seq_probability(1) <= threshold)}; // P(byte)=1/256",
    ]
    for n in range(2, 7):
        p = exact_seq_probability(n)
        enable = int(n <= max_len and p <= threshold and (len(candidates) ** n) <= MAX_STAGE_COMBINATIONS)
        lines.append(f"localparam integer ENUMERATE_LEN_{n} = {enable}; // p={p:.12g} per fixed window")
    lines.extend(["", "function automatic [7:0] candidate_at;", "    input integer idx;", "    begin", "        case (idx)"])
    for i, b in enumerate(candidates):
        lines.append(f"            {i}: candidate_at = 8'h{b:02X};")
    lines.extend(["            default: candidate_at = 8'h00;", "        endcase", "    end", "endfunction", ""])
    lines.extend(["function automatic integer exact_length;", "    input integer idx;", "    begin", "        case (idx)"])
    for idx, item in enumerate(exact_items):
        lines.append(f"            {idx}: exact_length = {len(item['bytes'])}; // {item['name']}: {item['bytes']}")
    lines.extend(["            default: exact_length = 0;", "        endcase", "    end", "endfunction", ""])
    lines.extend(["function automatic [7:0] exact_byte;", "    input integer idx;", "    input integer pos;", "    begin", "        exact_byte = 8'h00;", "        case (idx)"])
    for idx, item in enumerate(exact_items):
        lines.append(f"            {idx}: begin")
        lines.append("                case (pos)")
        for pos, byte in enumerate(item["bytes"]):
            lines.append(f"                    {pos}: exact_byte = 8'h{byte:02X};")
        lines.extend(["                    default: exact_byte = 8'h00;", "                endcase", "            end"])
    lines.extend(["            default: exact_byte = 8'h00;", "        endcase", "    end", "endfunction", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def write_reports(out: Path, clean_path: Path, suspect_path: Path, clean_text: str, suspect_text: str,
                 normalized_diff: str, candidates: list[int], sequences: list[dict[str, Any]],
                 exact_multi: list[dict[str, Any]], suspicious_lines: list[dict[str, str]],
                 max_len: int, threshold: float) -> dict[str, Any]:
    enumerate_single_bytes = exact_seq_probability(1) <= threshold
    single_byte_test_count = 256 if enumerate_single_bytes else len(candidates)
    single_byte_method = (
        "Exhaustively test all 256 byte values because P(byte)=1/256 is at or below the rarity threshold."
        if enumerate_single_bytes else
        "Test candidate byte values extracted from trigger-like parameters/direct comparisons; a full sweep is above the rarity threshold."
    )
    staged: dict[str, Any] = {"1": {
        "tested": single_byte_test_count,
        "enumerate_all_byte_values": enumerate_single_bytes,
        "method": single_byte_method,
    }}
    total_estimate = single_byte_test_count
    exact_by_len: dict[int, list[tuple[int, ...]]] = defaultdict(list)
    candidate_set = set(candidates)
    for item in exact_multi:
        seq = tuple(item["bytes"])
        if seq not in exact_by_len[len(seq)]:
            exact_by_len[len(seq)].append(seq)
    for n in range(2, max_len + 1):
        p = exact_seq_probability(n)
        do_enum = p <= threshold and len(candidates) ** n <= MAX_STAGE_COMBINATIONS
        if do_enum:
            product_total = len(candidates) ** n
            exact_in_product = sum(1 for seq in exact_by_len[n] if all(b in candidate_set for b in seq))
            tested = product_total + len(exact_by_len[n]) - exact_in_product
            method = f"Enumerate candidate-byte combinations ({len(candidates)}^{n}), with exact source-derived sequences tested separately only when outside the product alphabet."
        else:
            product_total = 0
            tested = len(exact_by_len[n])
            method = "Rarity threshold disables broad enumeration; test source-derived exact sequences only."
        staged[str(n)] = {
            "per_window_probability": p,
            "per_window_probability_percent": p * 100.0,
            "rarity_threshold": threshold,
            "enumerate_candidate_combinations": do_enum,
            "candidate_product_space": product_total,
            "exact_sequences": [list(x) for x in exact_by_len[n]],
            "estimated_test_cases": tested,
            "method": method,
        }
        total_estimate += tested
    report = {
        "clean_file": str(clean_path),
        "suspect_file": str(suspect_path),
        "clean_sha256": sha256_text(clean_text),
        "suspect_sha256": sha256_text(suspect_text),
        "candidate_bytes_decimal": candidates,
        "candidate_bytes_hex": [f"0x{b:02X}" for b in candidates],
        "candidate_count": len(candidates),
        "exact_trigger_sequences": [
            {"name": s["name"], "bytes": s["bytes"], "length": len(s["bytes"]),
             "source": s["source"], "probability_per_uniform_window": exact_seq_probability(len(s["bytes"])),
             "probability_percent_per_uniform_window": exact_seq_probability(len(s["bytes"])) * 100.0,
             "below_rarity_threshold": exact_seq_probability(len(s["bytes"])) <= threshold}
            for s in sequences
        ],
        "rarity_threshold_probability": threshold,
        "rarity_threshold_percent": threshold * 100.0,
        "search_max_len": max_len,
        "stage_plan": staged,
        "estimated_total_test_cases": total_estimate,
        "suspicious_added_lines": suspicious_lines,
        "important_assumptions": [
            "Probability is per fixed window under independent uniformly random 8-bit bytes, not a universal or workload-specific activation probability.",
            "If P(byte)=1/256 is at or below the threshold, Stage 1 tests all 256 values; otherwise it tests extracted candidates only.",
            "Exact multi-byte sequences inferred from named parameters are always tested; broad candidate-product enumeration is enabled only when the sequence's theoretical per-window probability is below the threshold.",
            "Source-based extraction is regex-based and may miss computed, encoded, indirect, or obfuscated triggers.",
            "The testbench uses a pass-through clean model at the byte-level Trojan insertion point; it does not instantiate the user's entire clean UART top-level design.",
            "A mismatch indicates behaviour that differs from the reference model, not proof of malicious intent. No findings do not prove Trojan absence."
        ],
    }
    (out / "analysis_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = [
        "# Rarity-guided UART Trojan test plan", "",
        f"- Clean source: `{clean_path}`", f"- Suspect source: `{suspect_path}`",
        f"- Candidate byte alphabet ({len(candidates)}): " + ", ".join(f"0x{x:02X}" for x in candidates),
        f"- Maximum sequence length: {max_len}",
        f"- Rarity threshold: {threshold:g} probability ({threshold*100:g}% per fixed window)",
        f"- Estimated test cases: **{total_estimate:,}**", "",
        "## Rarity model", "",
        "For a specific n-byte sequence at one fixed window, under independent uniformly random bytes, P = (1/256)^n. This is not automatically the probability under your real application traffic.", "",
        "| Length | Probability per window | Percent | Broad combinations? | Estimated tests |",
        "|---:|---:|---:|---|---:|"
    ]
    for n, info in staged.items():
        if n == "1":
            single_method = "All 256 byte values" if info.get("enumerate_all_byte_values") else "Candidate-byte literals only"
            md.append(f"| 1 | 1/256 = {1/256:.8g} | {100/256:.6g}% | {single_method} | {info['tested']:,} |")
        else:
            p = info["per_window_probability"]
            md.append(f"| {n} | {p:.8g} | {p*100:.6g}% | {'Yes' if info['enumerate_candidate_combinations'] else 'No'} | {info['estimated_test_cases']:,} |")
    md.extend(["", "## Source-derived trigger sequence hints", ""])
    if sequences:
        for s in sequences:
            seq_str = " → ".join(f"{x} (0x{x:02X})" for x in s["bytes"])
            p = exact_seq_probability(len(s["bytes"]))
            md.append(f"- **{s['name']}**: `{seq_str}`; length={len(s['bytes'])}; per-window probability={p:.8g} ({p*100:.6g}%); below threshold={'yes' if p <= threshold else 'no'}. Source: {s['source']}")
    else:
        md.append("No multi-byte named parameter sequences were extracted. Longer search may rely on candidate combinations only.")
    md.extend(["", "## Suspicious changed-line hints", "", "These are code-diff heuristics, not a verdict:"])
    if suspicious_lines:
        for item in suspicious_lines[:200]:
            md.append(f"- **{item['priority']} (score {item['score']})** `{item['line']}` — {item['reasons']}")
    else:
        md.append("No added lines matched the simple suspicious-line heuristics, or no normalized differences were detected.")
    md.extend(["", "## Limitations", ""] + [f"- {item}" for item in report["important_assumptions"]])
    (out / "analysis_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return report


def run_simulation(out: Path, suspect_path: Path, tb_path: Path, clean_model_path: Path) -> int:
    iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
    if not iverilog or not vvp:
        print("Icarus Verilog not found. Install iverilog and rerun with --run.", file=sys.stderr)
        return 3
    if not tb_path.is_file():
        print(f"Testbench not found: {tb_path}", file=sys.stderr)
        return 2
    suspect = suspect_path.read_text(encoding="utf-8", errors="replace")
    sources = [str(suspect_path)]
    if not re.search(r"\bmodule\s+uart_trojan_clean\b", strip_comments(suspect)):
        if not clean_model_path.is_file():
            print(f"Clean insertion-boundary model not found: {clean_model_path}", file=sys.stderr)
            return 2
        sources.append(str(clean_model_path))
    sources.append(str(tb_path))
    binary = out / "trojan_rarity_test.vvp"
    cmd = [iverilog, "-g2012", f"-I{out}", "-s", "trojan_rarity_tb", "-o", str(binary), *sources]
    compiled = subprocess.run(cmd, cwd=out, text=True, capture_output=True, check=False)
    (out / "compile.log").write_text("COMMAND: " + " ".join(cmd) + "\n\nSTDOUT:\n" + compiled.stdout + "\nSTDERR:\n" + compiled.stderr, encoding="utf-8")
    if compiled.returncode != 0:
        print(f"Compilation failed. See {out / 'compile.log'}", file=sys.stderr)
        return compiled.returncode or 1
    started = time.time()
    sim = subprocess.run([vvp, str(binary)], cwd=out, text=True, capture_output=True, check=False)
    elapsed = time.time() - started
    log = f"ELAPSED_SECONDS: {elapsed:.3f}\n\nSTDOUT:\n{sim.stdout}\nSTDERR:\n{sim.stderr}"
    (out / "simulation.log").write_text(log, encoding="utf-8")
    print(sim.stdout, end="")
    if sim.stderr:
        print(sim.stderr, file=sys.stderr, end="")
    print(f"\nSimulation log: {out / 'simulation.log'}")
    return sim.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Diff clean/suspect RTL, rank changed logic, estimate trigger rarity, and generate rarity-guided Verilog tests.")
    parser.add_argument("--clean", required=True, type=Path, help="trusted clean/reference RTL (source comparison input)")
    parser.add_argument("--suspect", required=True, type=Path, help="suspect RTL containing uart_trojan and side_effect_trojan")
    parser.add_argument("--out", type=Path, default=Path("rarity_detection_output"), help="output directory")
    parser.add_argument("--candidate-bytes", default="", help="optional candidate byte list; unions with source-derived candidates, e.g. 5,27,49,21,36,37,94,0xAA,0xBB,0xCC")
    parser.add_argument("--max-search-len", type=int, default=None, help="maximum sequence length (1..6), inferred by default")
    parser.add_argument("--rarity-threshold", type=float, default=1e-2, help="per-window probability threshold as a fraction (default 0.01 = 1%%); broad combination search is enabled for lengths at/below threshold")
    parser.add_argument("--run", action="store_true", help="compile and run the generated testbench using Icarus Verilog")
    parser.add_argument("--testbench", type=Path, default=Path(__file__).with_name("trojan_rarity_tb.sv"), help="testbench source")
    parser.add_argument("--clean-model", type=Path, default=Path(__file__).with_name("clean_byte_model.sv"), help="pass-through expected-behaviour model at the byte boundary")
    args = parser.parse_args()

    clean_path = args.clean.expanduser().resolve()
    suspect_path = args.suspect.expanduser().resolve()
    out = args.out.expanduser().resolve()
    tb_path = args.testbench.expanduser().resolve()
    clean_model = args.clean_model.expanduser().resolve()
    if not clean_path.is_file(): parser.error(f"clean file does not exist: {clean_path}")
    if not suspect_path.is_file(): parser.error(f"suspect file does not exist: {suspect_path}")
    if clean_path == suspect_path: parser.error("--clean and --suspect must be different files")
    if args.max_search_len is not None and not 1 <= args.max_search_len <= 6: parser.error("--max-search-len must be 1..6")
    if not (0.0 < args.rarity_threshold <= 1.0): parser.error("--rarity-threshold must be in (0, 1]")

    clean_text = clean_path.read_text(encoding="utf-8", errors="replace")
    suspect_text = suspect_path.read_text(encoding="utf-8", errors="replace")
    clean_modules, suspect_modules = extract_modules(clean_text), extract_modules(suspect_text)
    candidates = set(extract_candidates(suspect_text))
    try:
        if args.candidate_bytes.strip():
            candidates.update(parse_candidate_list(args.candidate_bytes))
    except ValueError as exc:
        parser.error(str(exc))
    candidates_list = sorted(candidates)
    if not candidates_list:
        parser.error("No candidate input bytes found. Use --candidate-bytes explicitly.")

    exact_sequences = extract_exact_sequences(suspect_text)
    max_inferred = infer_max_len(suspect_modules, exact_sequences)
    max_len = args.max_search_len if args.max_search_len is not None else max_inferred
    # If explicit max is lower than an extracted trigger, the exact trigger still deserves a test,
    # so extend the maximum rather than silently dropping it.
    longest_exact = max((len(s["bytes"]) for s in exact_sequences), default=1)
    if max_len < longest_exact:
        print(f"Warning: requested max length {max_len} is below a source-derived sequence length {longest_exact}; extending search length.")
        max_len = longest_exact
    max_len = min(max_len, 6)

    for n in range(2, max_len + 1):
        if exact_seq_probability(n) <= args.rarity_threshold and candidates_list.__len__() ** n > MAX_STAGE_COMBINATIONS:
            parser.error(f"Length {n} is rare enough for broad enumeration, but candidate product space {len(candidates_list)**n:,} exceeds safety limit {MAX_STAGE_COMBINATIONS:,}. Increase threshold to disable that stage or reduce candidate bytes.")

    out.mkdir(parents=True, exist_ok=True)
    raw_diff, normalized_diff = source_diff(clean_text, suspect_text, str(clean_path), str(suspect_path))
    (out / "source_diff.diff").write_text(raw_diff, encoding="utf-8")
    (out / "code_diff.diff").write_text(normalized_diff, encoding="utf-8")
    suspicious_lines = extract_added_suspicious_lines(normalized_diff)
    # Only sequences no longer than configured search bound are retained in reports/header.
    sequences_for_search = [s for s in exact_sequences if len(s["bytes"]) <= max_len]
    multi_for_search = [s for s in sequences_for_search if len(s["bytes"]) >= 2]
    (out / "suspicious_code.json").write_text(json.dumps(suspicious_lines, indent=2), encoding="utf-8")
    make_header(candidates_list, multi_for_search, max_len, args.rarity_threshold, out / "trojan_search_config.svh")
    report = write_reports(out, clean_path, suspect_path, clean_text, suspect_text, normalized_diff, candidates_list,
                          sequences_for_search, multi_for_search, suspicious_lines, max_len, args.rarity_threshold)
    print(f"Candidate alphabet ({len(candidates_list)} bytes): {', '.join(f'0x{x:02X}' for x in candidates_list)}")
    print(f"Maximum sequence length: {max_len}")
    print(f"Rarity threshold: {args.rarity_threshold:g} probability = {args.rarity_threshold*100:g}% per fixed byte window")
    print(f"Estimated test cases: {report['estimated_total_test_cases']:,}")
    for n, info in report["stage_plan"].items():
        if n == "1": print(f"Stage 1: {info['tested']:,} input-byte tests; exhaustive={info.get('enumerate_all_byte_values', False)}")
        else: print(f"Stage {n}: {info['estimated_test_cases']:,} tests; enumerate combinations={info['enumerate_candidate_combinations']}; P(window)={info['per_window_probability']:.4g}")
    print(f"Report: {out / 'analysis_report.md'}")
    print(f"Generated configuration: {out / 'trojan_search_config.svh'}")
    if args.run:
        return run_simulation(out, suspect_path, tb_path, clean_model)
    print("Analysis complete. Add --run to compile and simulate (requires iverilog and vvp).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
