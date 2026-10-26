# Rarity-guided UART Trojan test plan

- Clean source: `/home/vboxuser/uart-trojan-lab/uart_clean_reference.sv`
- Suspect source: `/home/vboxuser/uart-trojan-lab/uart_trojan_fsm.sv`
- Candidate byte alphabet (13): 0x05, 0x15, 0x1B, 0x1D, 0x22, 0x24, 0x25, 0x31, 0x40, 0x5E, 0xAA, 0xBB, 0xCC
- Maximum sequence length: 4
- Rarity threshold: 0.01 probability (1% per fixed window)
- Estimated test cases: **31,183**

## Rarity model

For a specific n-byte sequence at one fixed window, under independent uniformly random bytes, P = (1/256)^n. This is not automatically the probability under your real application traffic.

| Length | Probability per window | Percent | Broad combinations? | Estimated tests |
|---:|---:|---:|---|---:|
| 1 | 1/256 = 0.00390625 | 0.390625% | All 256 byte values | 256 |
| 2 | 1.5258789e-05 | 0.00152588% | Yes | 169 |
| 3 | 5.9604645e-08 | 5.96046e-06% | Yes | 2,197 |
| 4 | 2.3283064e-10 | 2.32831e-08% | Yes | 28,561 |

## Source-derived trigger sequence hints

- **TROJAN_SINGLE_INPUT**: `94 (0x5E)`; length=1; per-window probability=0.00390625 (0.390625%); below threshold=yes. Source: named single-byte parameter
- **TROJAN_TWO**: `36 (0x24) → 37 (0x25)`; length=2; per-window probability=1.5258789e-05 (0.00152588%); below threshold=yes. Source: ordered parameter family: TROJAN_TWO_FIRST, TROJAN_TWO_SECOND
- **TRIGGER**: `170 (0xAA) → 187 (0xBB) → 204 (0xCC)`; length=3; per-window probability=5.9604645e-08 (5.96046e-06%); below threshold=yes. Source: ordered parameter family: TRIGGER_FIRST, TRIGGER_SECOND, TRIGGER_THIRD
- **TROJAN_FOUR**: `5 (0x05) → 27 (0x1B) → 49 (0x31) → 21 (0x15)`; length=4; per-window probability=2.3283064e-10 (2.32831e-08%); below threshold=yes. Source: ordered parameter family: TROJAN_FOUR_FIRST, TROJAN_FOUR_SECOND, TROJAN_FOUR_THIRD, TROJAN_FOUR_FOURTH

## Suspicious changed-line hints

These are code-diff heuristics, not a verdict:
- **MEDIUM (score 3)** `parameter [7:0] TROJAN_SINGLE_INPUT = 8'd34,` — trigger-related naming
- **MEDIUM (score 3)** `parameter [7:0] TROJAN_SINGLE_OUTPUT = 8'd95,` — trigger-related naming
- **MEDIUM (score 3)** `parameter [7:0] TROJAN_TWO_FIRST = 8'd36,` — trigger-related naming
- **MEDIUM (score 3)** `parameter [7:0] TROJAN_TWO_SECOND = 8'd37,` — trigger-related naming
- **MEDIUM (score 3)** `parameter [7:0] TROJAN_TWO_OUTPUT = 8'd38,` — trigger-related naming
- **MEDIUM (score 3)** `parameter [7:0] TROJAN_FOUR_FIRST = 8'd64,` — trigger-related naming
- **MEDIUM (score 3)** `parameter [7:0] TROJAN_FOUR_SECOND = 8'd27,` — trigger-related naming
- **MEDIUM (score 3)** `parameter [7:0] TROJAN_FOUR_THIRD = 8'd49,` — trigger-related naming
- **MEDIUM (score 3)** `parameter [7:0] TROJAN_FOUR_FOURTH = 8'd29,` — trigger-related naming
- **MEDIUM (score 3)** `parameter [7:0] TROJAN_FOUR_OUTPUT = 8'd22` — trigger-related naming
- **MEDIUM (score 3)** `wire single_hit = rx_valid_in && (single_state == S_IDLE) &&` — comparison or assignment; possible observable data/control path
- **HIGH (score 6)** `(rx_data_in == TROJAN_SINGLE_INPUT);` — comparison or assignment; possible observable data/control path; trigger-related naming
- **MEDIUM (score 3)** `wire two_hit = rx_valid_in && (two_state == T_GOT_FIRST) &&` — comparison or assignment; possible observable data/control path
- **HIGH (score 6)** `(rx_data_in == TROJAN_TWO_SECOND);` — comparison or assignment; possible observable data/control path; trigger-related naming
- **MEDIUM (score 3)** `wire four_hit = rx_valid_in && (four_state == F_GOT_THIRD) &&` — comparison or assignment; possible observable data/control path
- **HIGH (score 6)** `(rx_data_in == TROJAN_FOUR_FOURTH);` — comparison or assignment; possible observable data/control path; trigger-related naming
- **LOW (score 1)** `single_state <= S_IDLE;` — comparison or assignment
- **LOW (score 1)** `two_state <= T_IDLE;` — comparison or assignment
- **LOW (score 1)** `four_state <= F_IDLE;` — comparison or assignment
- **MEDIUM (score 3)** `if (rx_valid_in) begin` — conditional/control flow; possible observable data/control path
- **LOW (score 1)** `if (single_hit)` — conditional/control flow
- **HIGH (score 6)** `rx_data_out <= TROJAN_SINGLE_OUTPUT;` — comparison or assignment; possible observable data/control path; trigger-related naming
- **LOW (score 1)** `else if (two_hit)` — conditional/control flow
- **HIGH (score 6)** `rx_data_out <= TROJAN_TWO_OUTPUT;` — comparison or assignment; possible observable data/control path; trigger-related naming
- **LOW (score 1)** `else if (four_hit)` — conditional/control flow
- **HIGH (score 6)** `rx_data_out <= TROJAN_FOUR_OUTPUT;` — comparison or assignment; possible observable data/control path; trigger-related naming
- **LOW (score 1)** `case (single_state)` — conditional/control flow
- **LOW (score 1)** `single_state <= S_ACTIVE;` — comparison or assignment
- **LOW (score 1)** `S_ACTIVE: single_state <= S_IDLE;` — comparison or assignment
- **LOW (score 1)** `default: single_state <= S_IDLE;` — comparison or assignment
- **MEDIUM (score 2)** `if (two_state == T_ACTIVE) begin` — conditional/control flow; comparison or assignment
- **HIGH (score 7)** `if (rx_valid_in && (rx_data_in == TROJAN_TWO_FIRST))` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **LOW (score 1)** `two_state <= T_GOT_FIRST;` — comparison or assignment
- **MEDIUM (score 3)** `end else if (rx_valid_in) begin` — conditional/control flow; possible observable data/control path
- **LOW (score 1)** `case (two_state)` — conditional/control flow
- **HIGH (score 7)** `if (rx_data_in == TROJAN_TWO_FIRST)` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **HIGH (score 7)** `if (rx_data_in == TROJAN_TWO_SECOND)` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **LOW (score 1)** `two_state <= T_ACTIVE;` — comparison or assignment
- **HIGH (score 7)** `else if (rx_data_in == TROJAN_TWO_FIRST)` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **LOW (score 1)** `default: two_state <= T_IDLE;` — comparison or assignment
- **MEDIUM (score 2)** `if (four_state == F_ACTIVE) begin` — conditional/control flow; comparison or assignment
- **HIGH (score 7)** `if (rx_valid_in && (rx_data_in == TROJAN_FOUR_FIRST))` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **LOW (score 1)** `four_state <= F_GOT_FIRST;` — comparison or assignment
- **LOW (score 1)** `case (four_state)` — conditional/control flow
- **HIGH (score 7)** `if (rx_data_in == TROJAN_FOUR_FIRST)` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **HIGH (score 7)** `if (rx_data_in == TROJAN_FOUR_SECOND)` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **LOW (score 1)** `four_state <= F_GOT_SECOND;` — comparison or assignment
- **HIGH (score 7)** `else if (rx_data_in == TROJAN_FOUR_FIRST)` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **HIGH (score 7)** `if (rx_data_in == TROJAN_FOUR_THIRD)` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **LOW (score 1)** `four_state <= F_GOT_THIRD;` — comparison or assignment
- **HIGH (score 7)** `if (rx_data_in == TROJAN_FOUR_FOURTH)` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **LOW (score 1)** `four_state <= F_ACTIVE;` — comparison or assignment
- **LOW (score 1)** `default: four_state <= F_IDLE;` — comparison or assignment
- **MEDIUM (score 2)** `module side_effect_trojan #(` — possible observable data/control path
- **MEDIUM (score 3)** `parameter [7:0] TRIGGER_FIRST = 8'hAA,` — trigger-related naming
- **MEDIUM (score 3)** `parameter [7:0] TRIGGER_SECOND = 8'hBB,` — trigger-related naming
- **MEDIUM (score 3)** `parameter [7:0] TRIGGER_THIRD = 8'hCC` — trigger-related naming
- **MEDIUM (score 2)** `input [7:0] rx_data_in,` — possible observable data/control path
- **MEDIUM (score 2)** `input rx_valid_in,` — possible observable data/control path
- **HIGH (score 5)** `output reg trojan_side_effect` — possible observable data/control path; trigger-related naming
- **LOW (score 1)** `GOT_FIRST = 2'd1,` — state/history/counter reference
- **LOW (score 1)** `GOT_SECOND = 2'd2,` — state/history/counter reference
- **LOW (score 1)** `ACTIVE = 2'd3;` — state/history/counter reference
- **LOW (score 1)** `reg [1:0] state;` — state/history/counter reference
- **LOW (score 1)** `if (!reset) begin` — conditional/control flow
- **MEDIUM (score 2)** `state <= IDLE;` — comparison or assignment; state/history/counter reference
- **HIGH (score 4)** `trojan_side_effect <= 1'b0;` — comparison or assignment; trigger-related naming
- **MEDIUM (score 2)** `case (state)` — conditional/control flow; state/history/counter reference
- **HIGH (score 7)** `if (rx_data_in == TRIGGER_FIRST)` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **MEDIUM (score 2)** `state <= GOT_FIRST;` — comparison or assignment; state/history/counter reference
- **LOW (score 1)** `GOT_FIRST: begin` — state/history/counter reference
- **HIGH (score 7)** `if (rx_data_in == TRIGGER_SECOND)` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **MEDIUM (score 2)** `state <= GOT_SECOND;` — comparison or assignment; state/history/counter reference
- **HIGH (score 7)** `else if (rx_data_in == TRIGGER_FIRST)` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **LOW (score 1)** `GOT_SECOND: begin` — state/history/counter reference
- **HIGH (score 7)** `if (rx_data_in == TRIGGER_THIRD) begin` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **MEDIUM (score 2)** `state <= ACTIVE;` — comparison or assignment; state/history/counter reference
- **HIGH (score 4)** `trojan_side_effect <= 1'b1;` — comparison or assignment; trigger-related naming
- **HIGH (score 7)** `end else if (rx_data_in == TRIGGER_FIRST) begin` — conditional/control flow; comparison or assignment; possible observable data/control path; trigger-related naming
- **LOW (score 1)** `ACTIVE: begin` — state/history/counter reference
- **MEDIUM (score 3)** `parameter [7:0] TROJAN_SINGLE_INPUT = 8'd94,` — trigger-related naming
- **MEDIUM (score 3)** `parameter [7:0] TROJAN_FOUR_FIRST = 8'd5,` — trigger-related naming
- **MEDIUM (score 3)** `parameter [7:0] TROJAN_FOUR_FOURTH = 8'd21,` — trigger-related naming
- **MEDIUM (score 3)** `.TROJAN_SINGLE_INPUT(TROJAN_SINGLE_INPUT),` — trigger-related naming
- **MEDIUM (score 3)** `.TROJAN_SINGLE_OUTPUT(TROJAN_SINGLE_OUTPUT),` — trigger-related naming
- **MEDIUM (score 3)** `.TROJAN_TWO_FIRST(TROJAN_TWO_FIRST),` — trigger-related naming
- **MEDIUM (score 3)** `.TROJAN_TWO_SECOND(TROJAN_TWO_SECOND),` — trigger-related naming
- **MEDIUM (score 3)** `.TROJAN_TWO_OUTPUT(TROJAN_TWO_OUTPUT),` — trigger-related naming
- **MEDIUM (score 3)** `.TROJAN_FOUR_FIRST(TROJAN_FOUR_FIRST),` — trigger-related naming
- **MEDIUM (score 3)** `.TROJAN_FOUR_SECOND(TROJAN_FOUR_SECOND),` — trigger-related naming
- **MEDIUM (score 3)** `.TROJAN_FOUR_THIRD(TROJAN_FOUR_THIRD),` — trigger-related naming
- **MEDIUM (score 3)** `.TROJAN_FOUR_FOURTH(TROJAN_FOUR_FOURTH),` — trigger-related naming
- **MEDIUM (score 3)** `.TROJAN_FOUR_OUTPUT(TROJAN_FOUR_OUTPUT)` — trigger-related naming
- **MEDIUM (score 3)** `) trojan (` — trigger-related naming

## Limitations

- Probability is per fixed window under independent uniformly random 8-bit bytes, not a universal or workload-specific activation probability.
- If P(byte)=1/256 is at or below the threshold, Stage 1 tests all 256 values; otherwise it tests extracted candidates only.
- Exact multi-byte sequences inferred from named parameters are always tested; broad candidate-product enumeration is enabled only when the sequence's theoretical per-window probability is below the threshold.
- Source-based extraction is regex-based and may miss computed, encoded, indirect, or obfuscated triggers.
- The testbench uses a pass-through clean model at the byte-level Trojan insertion point; it does not instantiate the user's entire clean UART top-level design.
- A mismatch indicates behaviour that differs from the reference model, not proof of malicious intent. No findings do not prove Trojan absence.
