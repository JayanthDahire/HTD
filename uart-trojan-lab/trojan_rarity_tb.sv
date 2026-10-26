`timescale 1ns/1ps

// Rarity-guided testbench for the byte-level Trojan insertion point.
// The Python tool generates trojan_search_config.svh before compilation.
module trojan_rarity_tb;
    `include "trojan_search_config.svh"

    localparam integer MAX_FOUND = 512;

    reg clk;
    reg reset;
    reg [7:0] rx_data_in;
    reg rx_valid_in;

    wire [7:0] clean_data_out;
    wire clean_valid_out;
    wire [7:0] suspect_data_out;
    wire suspect_valid_out;
    wire side_effect_out;

    reg [7:0] candidate_sequence [0:SEARCH_MAX_LEN-1];
    reg [7:0] found_sequence [0:MAX_FOUND*SEARCH_MAX_LEN-1];
    integer found_length [0:MAX_FOUND-1];
    reg found_data_effect [0:MAX_FOUND-1];
    reg found_side_effect_effect [0:MAX_FOUND-1];

    reg test_mismatch;
    reg test_side_effect;
    reg side_effect_previous;

    integer i, j, k, combo, tmp;
    integer stage_len;
    integer total_for_stage;
    integer total_tests;
    integer stage_tests;
    integer found_count;
    integer found_overflow;
    integer detections_before_stage;
    integer fd;

    always #5 clk = ~clk;

    uart_trojan_clean clean_path (
        .clk(clk), .reset(reset), .rx_data_in(rx_data_in),
        .rx_valid_in(rx_valid_in), .rx_data_out(clean_data_out),
        .rx_valid_out(clean_valid_out)
    );

    uart_trojan suspect_path (
        .clk(clk), .reset(reset), .rx_data_in(rx_data_in),
        .rx_valid_in(rx_valid_in), .rx_data_out(suspect_data_out),
        .rx_valid_out(suspect_valid_out)
    );

    side_effect_trojan side_effect_path (
        .clk(clk), .reset(reset), .rx_data_in(rx_data_in),
        .rx_valid_in(rx_valid_in), .trojan_side_effect(side_effect_out)
    );

    function integer integer_power;
        input integer base;
        input integer exponent;
        integer p;
        begin
            integer_power = 1;
            for (p = 0; p < exponent; p = p + 1)
                integer_power = integer_power * base;
        end
    endfunction

    function integer enumerate_length;
        input integer length_value;
        begin
            case (length_value)
                2: enumerate_length = ENUMERATE_LEN_2;
                3: enumerate_length = ENUMERATE_LEN_3;
                4: enumerate_length = ENUMERATE_LEN_4;
                5: enumerate_length = ENUMERATE_LEN_5;
                6: enumerate_length = ENUMERATE_LEN_6;
                default: enumerate_length = 0;
            endcase
        end
    endfunction

    // True when the current sequence was explicitly extracted from the RTL.
    // Product enumeration skips these because they were already tested directly.
    function integer is_exact_sequence;
        input integer sequence_length;
        integer e, p, same;
        begin
            is_exact_sequence = 0;
            for (e = 0; e < EXACT_SEQUENCE_COUNT; e = e + 1) begin
                if (exact_length(e) == sequence_length) begin
                    same = 1;
                    for (p = 0; p < sequence_length; p = p + 1) begin
                        if (candidate_sequence[p] !== exact_byte(e, p))
                            same = 0;
                    end
                    if (same)
                        is_exact_sequence = 1;
                end
            end
        end
    endfunction

    // Ignore a shorter trigger's already-known effect at the exact byte where
    // that trigger completes. Other positions/effect types remain observable.
    function integer explained_by_known_trigger;
        input integer byte_position;
        input integer effect_kind; // 1=data/valid, 2=side effect
        integer h, start_pos, offset, same, effect_matches;
        begin
            explained_by_known_trigger = 0;
            for (h = 0; h < found_count; h = h + 1) begin
                effect_matches = 0;
                if ((effect_kind == 1) && found_data_effect[h]) effect_matches = 1;
                if ((effect_kind == 2) && found_side_effect_effect[h]) effect_matches = 1;
                if (effect_matches && found_length[h] > 0 &&
                    found_length[h] < stage_len && found_length[h] <= byte_position + 1) begin
                    start_pos = byte_position + 1 - found_length[h];
                    same = 1;
                    for (offset = 0; offset < found_length[h]; offset = offset + 1) begin
                        if (candidate_sequence[start_pos + offset] !==
                            found_sequence[h*SEARCH_MAX_LEN + offset])
                            same = 0;
                    end
                    if (same)
                        explained_by_known_trigger = 1;
                end
            end
        end
    endfunction

    task reset_candidate;
        begin
            test_mismatch = 1'b0;
            test_side_effect = 1'b0;
            side_effect_previous = 1'b0;
            rx_data_in = 8'd0;
            rx_valid_in = 1'b0;
            reset = 1'b0;
            repeat (2) @(negedge clk);
            reset = 1'b1;
            @(negedge clk);
        end
    endtask

    task send_byte;
        input [7:0] byte_value;
        input integer byte_position;
        begin
            @(negedge clk);
            rx_data_in = byte_value;
            rx_valid_in = 1'b1;
            @(posedge clk);
            #1;

            if ((clean_valid_out !== suspect_valid_out) ||
                ((clean_valid_out === 1'b1) && (suspect_valid_out === 1'b1) &&
                 (clean_data_out !== suspect_data_out))) begin
                if (!explained_by_known_trigger(byte_position, 1))
                    test_mismatch = 1'b1;
            end

            if ((side_effect_out === 1'b1) && (side_effect_previous !== 1'b1)) begin
                if (!explained_by_known_trigger(byte_position, 2))
                    test_side_effect = 1'b1;
            end
            side_effect_previous = side_effect_out;

            @(negedge clk);
            rx_data_in = 8'd0;
            rx_valid_in = 1'b0;
            @(posedge clk);
            #1;
            if ((side_effect_out === 1'b1) && (side_effect_previous !== 1'b1)) begin
                if (!explained_by_known_trigger(byte_position, 2))
                    test_side_effect = 1'b1;
            end
            side_effect_previous = side_effect_out;
        end
    endtask

    task run_sequence;
        input integer sequence_length;
        integer pos;
        begin
            reset_candidate();
            for (pos = 0; pos < sequence_length; pos = pos + 1)
                send_byte(candidate_sequence[pos], pos);
        end
    endtask

    task record_detection;
        input integer sequence_length;
        integer h, offset, same, duplicate_index;
        begin
            duplicate_index = -1;
            for (h = 0; h < found_count; h = h + 1) begin
                if (found_length[h] == sequence_length) begin
                    same = 1;
                    for (offset = 0; offset < sequence_length; offset = offset + 1)
                        if (found_sequence[h*SEARCH_MAX_LEN + offset] !== candidate_sequence[offset]) same = 0;
                    if (same) duplicate_index = h;
                end
            end

            if (duplicate_index >= 0) begin
                if (test_mismatch) found_data_effect[duplicate_index] = 1'b1;
                if (test_side_effect) found_side_effect_effect[duplicate_index] = 1'b1;
            end else if (found_count < MAX_FOUND) begin
                found_length[found_count] = sequence_length;
                found_data_effect[found_count] = test_mismatch;
                found_side_effect_effect[found_count] = test_side_effect;
                for (offset = 0; offset < sequence_length; offset = offset + 1)
                    found_sequence[found_count*SEARCH_MAX_LEN + offset] = candidate_sequence[offset];
                found_count = found_count + 1;

                $write("DETECTED length=%0d sequence=[", sequence_length);
                for (offset = 0; offset < sequence_length; offset = offset + 1) begin
                    $write("%0d", candidate_sequence[offset]);
                    if (offset + 1 < sequence_length) $write(", ");
                end
                $write("] effects=");
                if (test_mismatch) $write("DATA/VALID ");
                if (test_side_effect) $write("SIDE_EFFECT ");
                $display("");
                $fwrite(fd, "DETECTED length=%0d sequence=[", sequence_length);
                for (offset = 0; offset < sequence_length; offset = offset + 1) begin
                    $fwrite(fd, "%0d", candidate_sequence[offset]);
                    if (offset + 1 < sequence_length) $fwrite(fd, ", ");
                end
                $fwrite(fd, "] effects=");
                if (test_mismatch) $fwrite(fd, "DATA/VALID ");
                if (test_side_effect) $fwrite(fd, "SIDE_EFFECT ");
                $fwrite(fd, "\n");
            end else begin
                found_overflow = 1;
            end
        end
    endtask

    initial begin
        clk = 1'b0;
        reset = 1'b1;
        rx_data_in = 8'd0;
        rx_valid_in = 1'b0;
        found_count = 0;
        found_overflow = 0;
        total_tests = 0;

        for (i = 0; i < MAX_FOUND; i = i + 1) begin
            found_length[i] = 0;
            found_data_effect[i] = 1'b0;
            found_side_effect_effect[i] = 1'b0;
        end

        fd = $fopen("detection_summary.txt", "w");
        if (fd == 0) begin
            $display("ERROR: cannot write detection_summary.txt");
            $finish;
        end

        $display("====================================================");
        $display("RARITY-GUIDED UART TROJAN TESTING");
        $display("Candidate input bytes: %0d", CANDIDATE_COUNT);
        $display("Exact source-derived multi-byte sequences: %0d", EXACT_SEQUENCE_COUNT);
        $display("Maximum search length: %0d", SEARCH_MAX_LEN);
        $display("A specific n-byte sequence has P=(1/256)^n per fixed window under uniform IID bytes.");
        $display("Stage 1 tests suspicious candidate bytes; later stages use rarity-threshold-guided search.");
        $display("====================================================");
        $fdisplay(fd, "Rarity-guided UART Trojan detection results");
        $fdisplay(fd, "Candidate input bytes: %0d", CANDIDATE_COUNT);
        $fdisplay(fd, "Exact source-derived multi-byte sequences: %0d", EXACT_SEQUENCE_COUNT);

        // Stage 1: with the default 1% threshold, P(byte)=1/256 (0.390625%)
        // is below the threshold, so test all 256 possible byte values. A stricter
        // threshold falls back to the RTL-derived candidate-byte set.
        stage_len = 1;
        detections_before_stage = found_count;
        stage_tests = 0;
        if (ENUMERATE_LEN_1) begin
            $display("\n--- STAGE 1: exhaustive single-byte search (256 values) ---");
            for (i = 0; i < 256; i = i + 1) begin
                candidate_sequence[0] = i[7:0];
                run_sequence(1);
                total_tests = total_tests + 1;
                stage_tests = stage_tests + 1;
                if (test_mismatch || test_side_effect) record_detection(1);
            end
        end else begin
            $display("\n--- STAGE 1: candidate single-byte values ---");
            for (i = 0; i < CANDIDATE_COUNT; i = i + 1) begin
                candidate_sequence[0] = candidate_at(i);
                run_sequence(1);
                total_tests = total_tests + 1;
                stage_tests = stage_tests + 1;
                if (test_mismatch || test_side_effect) record_detection(1);
            end
        end
        $display("Stage 1 tests: %0d; new findings: %0d", stage_tests, found_count - detections_before_stage);
        $fdisplay(fd, "Stage 1 tests: %0d; new findings: %0d", stage_tests, found_count - detections_before_stage);

        // Stages 2..N. Direct source-derived patterns are always tested. Broader
        // combinations are tested only when their fixed-window probability is
        // below the configured threshold.
        for (stage_len = 2; stage_len <= SEARCH_MAX_LEN; stage_len = stage_len + 1) begin
            detections_before_stage = found_count;
            stage_tests = 0;
            $display("\n--- STAGE %0d ---", stage_len);

            for (i = 0; i < EXACT_SEQUENCE_COUNT; i = i + 1) begin
                if (exact_length(i) == stage_len) begin
                    for (j = 0; j < stage_len; j = j + 1)
                        candidate_sequence[j] = exact_byte(i, j);
                    run_sequence(stage_len);
                    total_tests = total_tests + 1;
                    stage_tests = stage_tests + 1;
                    if (test_mismatch || test_side_effect) record_detection(stage_len);
                end
            end

            if (enumerate_length(stage_len)) begin
                total_for_stage = integer_power(CANDIDATE_COUNT, stage_len);
                $display("Rarity threshold allows candidate-alphabet enumeration: %0d combinations", total_for_stage);
                for (combo = 0; combo < total_for_stage; combo = combo + 1) begin
                    tmp = combo;
                    for (k = stage_len - 1; k >= 0; k = k - 1) begin
                        candidate_sequence[k] = candidate_at(tmp % CANDIDATE_COUNT);
                        tmp = tmp / CANDIDATE_COUNT;
                    end
                    if (!is_exact_sequence(stage_len)) begin
                        run_sequence(stage_len);
                        total_tests = total_tests + 1;
                        stage_tests = stage_tests + 1;
                        if (test_mismatch || test_side_effect) record_detection(stage_len);
                    end
                end
            end else begin
                $display("Broad enumeration skipped by rarity threshold; exact source-derived sequences still tested.");
            end
            $display("Stage %0d tests: %0d; new findings: %0d", stage_len, stage_tests, found_count - detections_before_stage);
            $fdisplay(fd, "Stage %0d tests: %0d; new findings: %0d; broad enumeration=%0d", stage_len, stage_tests, found_count - detections_before_stage, enumerate_length(stage_len));
        end

        $display("\n====================================================");
        $display("FINISHED: %0d candidate tests, %0d unique findings", total_tests, found_count);
        $display("Results: detection_summary.txt");
        $fdisplay(fd, "\nTotal candidate tests: %0d", total_tests);
        $fdisplay(fd, "Unique findings: %0d", found_count);
        if (found_overflow) begin
            $display("WARNING: result buffer filled; some findings may be missing.");
            $fdisplay(fd, "WARNING: result buffer filled; some findings may be missing.");
        end
        $fdisplay(fd, "Important: no finding does not prove the design is Trojan-free.");
        $fclose(fd);
        $finish;
    end
endmodule
