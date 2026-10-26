`timescale 1ns/1ps
module uart_tx #(
    parameter CLKS_PER_BIT = 5208
)
(
    input clk,reset,tx_start,
    input [7:0] tx_data,
    output reg tx,tx_busy,tx_done
);

    localparam IDLE  = 2'd0,
               START = 2'd1,
               DATA  = 2'd2,
               STOP  = 2'd3;

  reg [1:0] state;// size is 2^(i+1) not 2^i
    reg [15:0] clk_count;
    reg [2:0] bit_index;
    reg [7:0] tx_shift;

  always @(posedge clk or negedge reset) begin // falling from 1 to 0 waveform then we execute this
        if (!reset) begin
          // No = only <= Non blocking only
            state     <= IDLE;
            tx         <= 1'b1;
            tx_busy    <= 1'b0;
            tx_done    <= 1'b0;
            clk_count  <= 0;
            bit_index  <= 0;
            tx_shift   <= 0;
        end
        else begin
            tx_done <= 1'b0;
          case (state) // switch case of verilog
                IDLE: begin
                    tx        <= 1'b1;
                    tx_busy   <= 1'b0;
                    clk_count <= 0;
                    bit_index <= 0;

                    if (tx_start) begin
                        tx_shift <= tx_data;
                        tx       <= 1'b0;
                        tx_busy  <= 1'b1;
                        state    <= START;
                    end
                end

                START: begin // go from 0 to 5207 fir execute  so one clock cycle
                    if (clk_count == CLKS_PER_BIT - 1) begin
                        clk_count <= 0;
                        bit_index <= 0;
                        tx        <= tx_shift[0];
                        state     <= DATA;
                    end
                    else
                      clk_count <= clk_count + 1;// multiple line begin end is like brackets signle line no need
                end

                DATA: begin
                    if (clk_count == CLKS_PER_BIT - 1) begin
                        clk_count <= 0;
                      if (bit_index == 7) begin // 7 not 8 bit_index+1 segmentation error
                      tx    <= 1'b1;
                      state <= STOP;
                        end
                        else begin
                         bit_index <= bit_index + 1;
                            tx <= tx_shift[bit_index + 1];
                        end
                    end
                    else
                        clk_count <= clk_count + 1;
                end
                STOP: begin
                    if (clk_count == CLKS_PER_BIT - 1) begin
                        clk_count <= 0;
                        tx_done   <= 1'b1;
                        tx_busy   <= 1'b0;
                        state     <= IDLE;
                    end
                    else
                        clk_count <= clk_count + 1;
                end
                default: state <= IDLE;
            endcase
        		 end
    		end

endmodule


module uart_rx #(
    parameter CLKS_PER_BIT = 5208
)(
    input clk,reset,rx,
    output reg [7:0] rx_data,
    output reg rx_valid,rx_busy,rx_error
);

    localparam IDLE  = 2'd0,
               START = 2'd1,
               DATA  = 2'd2,
               STOP  = 2'd3;

    reg [1:0] state;
    reg [15:0] clk_count;
    reg [2:0] bit_index;
    reg [7:0] rx_shift;

    reg rx_sync1, rx_sync2;

    always @(posedge clk or negedge reset) begin
        if (!reset) begin
            rx_sync1 <= 1'b1;
            rx_sync2 <= 1'b1;
        end
        else begin
            rx_sync1 <= rx;
            rx_sync2 <= rx_sync1; // <= not = need parallel assignment otherwise we get new value instead of old
        end
    	end

    always @(posedge clk or negedge reset) begin
        if (!reset) begin
            state     <= IDLE;
            clk_count <= 0;
            bit_index <= 0;
            rx_shift  <= 0;
            rx_data   <= 0;
            rx_valid  <= 0;
            rx_busy   <= 0;
            rx_error  <= 0;
        end
        else begin
            rx_valid <= 1'b0;
            rx_error <= 1'b0;

            case (state)
         	IDLE: begin
                 rx_busy   <= 1'b0;
                 clk_count <= 0;
                 bit_index <= 0;

                 if (rx_sync2 == 1'b0) begin
                    rx_busy <= 1'b1;
                    state   <= START;
                    end
                	end

                START: begin
                    
                  if (clk_count == (CLKS_PER_BIT - 1)/2) // mid value needed here or edge issues
                      begin
                        clk_count <= 0;

                    if (rx_sync2 == 1'b0)
                            state <= DATA;
                  else begin
                       state    <= IDLE;
                            rx_error <= 1'b1;
                        end
                    end
                    else
                        clk_count <= clk_count + 1;
                end

                DATA: begin
                  if (clk_count == CLKS_PER_BIT - 1) // no /2 needed here this is after verification /2 frequency issue
                      begin
                        clk_count <= 0;
                      rx_shift[bit_index] <= rx_sync2; // bit_index not bit_index+! here

                        if (bit_index == 7)
                            state <= STOP;
                        else
                            bit_index <= bit_index + 1;
                    end
                    else
                        clk_count <= clk_count + 1;
                end

                STOP: begin
                  if (clk_count == CLKS_PER_BIT - 1)
                      begin
                        clk_count <= 0;
                        rx_busy   <= 1'b0;
                        state     <= IDLE;

                        if (rx_sync2 == 1'b1) // valididty check
                          begin
                            rx_data  <= rx_shift;
                            rx_valid <= 1'b1;
                        end
                      
                        else begin
                            rx_error <= 1'b1;
                        end
                    end
                    else
                        clk_count <= clk_count + 1;
                end

                default: state <= IDLE;

            endcase
        	end
    	end

endmodule

// -----------------------------------------------------------------------------
// Clean byte-path reference. This models the intended behaviour at the point
// immediately after uart_rx: valid bytes pass through unchanged.
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// Trojan payloads expressed as independent finite-state machines (FSMs).
// The state names make the progress through each trigger explicit.
// Priority remains: single-byte, then two-byte, then four-byte payload.
// -----------------------------------------------------------------------------
module uart_trojan #(
    parameter [7:0] TROJAN_SINGLE_INPUT   = 8'd94,
    parameter [7:0] TROJAN_SINGLE_OUTPUT  = 8'd95,

    parameter [7:0] TROJAN_TWO_FIRST      = 8'd36,
    parameter [7:0] TROJAN_TWO_SECOND     = 8'd37,
    parameter [7:0] TROJAN_TWO_OUTPUT     = 8'd38,

    parameter [7:0] TROJAN_FOUR_FIRST     = 8'd5,
    parameter [7:0] TROJAN_FOUR_SECOND    = 8'd27,
    parameter [7:0] TROJAN_FOUR_THIRD     = 8'd49,
    parameter [7:0] TROJAN_FOUR_FOURTH    = 8'd21,
    parameter [7:0] TROJAN_FOUR_OUTPUT    = 8'd22
)(
    input              clk,
    input              reset,
    input      [7:0]   rx_data_in,
    input              rx_valid_in,
    output reg [7:0]   rx_data_out,
    output reg         rx_valid_out
);
    localparam S_IDLE       = 1'b0,
               S_ACTIVE     = 1'b1;

    localparam T_IDLE       = 2'd0,
               T_GOT_FIRST  = 2'd1,
               T_ACTIVE     = 2'd2;

    localparam F_IDLE       = 3'd0,
               F_GOT_FIRST  = 3'd1,
               F_GOT_SECOND = 3'd2,
               F_GOT_THIRD  = 3'd3,
               F_ACTIVE     = 3'd4;

    reg       single_state;
    reg [1:0] two_state;
    reg [2:0] four_state;

    wire single_hit = rx_valid_in && (single_state == S_IDLE) &&
                      (rx_data_in == TROJAN_SINGLE_INPUT);

    wire two_hit = rx_valid_in && (two_state == T_GOT_FIRST) &&
                   (rx_data_in == TROJAN_TWO_SECOND);

    wire four_hit = rx_valid_in && (four_state == F_GOT_THIRD) &&
                    (rx_data_in == TROJAN_FOUR_FOURTH);

    always @(posedge clk or negedge reset) begin
        if (!reset) begin
            single_state <= S_IDLE;
            two_state    <= T_IDLE;
            four_state   <= F_IDLE;
            rx_data_out  <= 8'd0;
            rx_valid_out <= 1'b0;
        end else begin
            rx_valid_out <= rx_valid_in;

            // The observable payload effect is applied to the byte that
            // completes a trigger, not to the following byte.
            if (rx_valid_in) begin
                if (single_hit)
                    rx_data_out <= TROJAN_SINGLE_OUTPUT;
                else if (two_hit)
                    rx_data_out <= TROJAN_TWO_OUTPUT;
                else if (four_hit)
                    rx_data_out <= TROJAN_FOUR_OUTPUT;
                else
                    rx_data_out <= rx_data_in;
            end

            // One-byte trigger FSM.
            case (single_state)
                S_IDLE: begin
                    if (single_hit)
                        single_state <= S_ACTIVE;
                end
                S_ACTIVE: single_state <= S_IDLE;
                default:  single_state <= S_IDLE;
            endcase

            // Two-byte trigger FSM. ACTIVE is a one-clock completion state.
            if (two_state == T_ACTIVE) begin
                if (rx_valid_in && (rx_data_in == TROJAN_TWO_FIRST))
                    two_state <= T_GOT_FIRST;
                else
                    two_state <= T_IDLE;
            end else if (rx_valid_in) begin
                case (two_state)
                    T_IDLE: begin
                        if (rx_data_in == TROJAN_TWO_FIRST)
                            two_state <= T_GOT_FIRST;
                    end
                    T_GOT_FIRST: begin
                        if (rx_data_in == TROJAN_TWO_SECOND)
                            two_state <= T_ACTIVE;
                        else if (rx_data_in == TROJAN_TWO_FIRST)
                            two_state <= T_GOT_FIRST;
                        else
                            two_state <= T_IDLE;
                    end
                    default: two_state <= T_IDLE;
                endcase
            end

            // Four-byte trigger FSM. Prefixes are retained only while the
            // next expected byte arrives; seeing the first byte restarts it.
            if (four_state == F_ACTIVE) begin
                if (rx_valid_in && (rx_data_in == TROJAN_FOUR_FIRST))
                    four_state <= F_GOT_FIRST;
                else
                    four_state <= F_IDLE;
            end else if (rx_valid_in) begin
                case (four_state)
                    F_IDLE: begin
                        if (rx_data_in == TROJAN_FOUR_FIRST)
                            four_state <= F_GOT_FIRST;
                    end
                    F_GOT_FIRST: begin
                        if (rx_data_in == TROJAN_FOUR_SECOND)
                            four_state <= F_GOT_SECOND;
                        else if (rx_data_in == TROJAN_FOUR_FIRST)
                            four_state <= F_GOT_FIRST;
                        else
                            four_state <= F_IDLE;
                    end
                    F_GOT_SECOND: begin
                        if (rx_data_in == TROJAN_FOUR_THIRD)
                            four_state <= F_GOT_THIRD;
                        else if (rx_data_in == TROJAN_FOUR_FIRST)
                            four_state <= F_GOT_FIRST;
                        else
                            four_state <= F_IDLE;
                    end
                    F_GOT_THIRD: begin
                        if (rx_data_in == TROJAN_FOUR_FOURTH)
                            four_state <= F_ACTIVE;
                        else if (rx_data_in == TROJAN_FOUR_FIRST)
                            four_state <= F_GOT_FIRST;
                        else
                            four_state <= F_IDLE;
                    end
                    default: four_state <= F_IDLE;
                endcase
            end
        end
    end
endmodule


// Separate stateful side-effect Trojan from the supplied source. This module
// is tested against the clean expectation that no such side effect exists.
module side_effect_trojan #(
    parameter [7:0] TRIGGER_FIRST  = 8'hAA,
    parameter [7:0] TRIGGER_SECOND = 8'hBB,
    parameter [7:0] TRIGGER_THIRD  = 8'hCC
)(
    input            clk,
    input            reset,
    input      [7:0] rx_data_in,
    input            rx_valid_in,
    output reg       trojan_side_effect
);
    localparam IDLE       = 2'd0,
               GOT_FIRST  = 2'd1,
               GOT_SECOND = 2'd2,
               ACTIVE     = 2'd3;

    reg [1:0] state;

    always @(posedge clk or negedge reset) begin
        if (!reset) begin
            state              <= IDLE;
            trojan_side_effect <= 1'b0;
        end else if (rx_valid_in) begin
            case (state)
                IDLE: begin
                    if (rx_data_in == TRIGGER_FIRST)
                        state <= GOT_FIRST;
                end
                GOT_FIRST: begin
                    if (rx_data_in == TRIGGER_SECOND)
                        state <= GOT_SECOND;
                    else if (rx_data_in == TRIGGER_FIRST)
                        state <= GOT_FIRST;
                    else
                        state <= IDLE;
                end
                GOT_SECOND: begin
                    if (rx_data_in == TRIGGER_THIRD) begin
                        state              <= ACTIVE;
                        trojan_side_effect <= 1'b1;
                    end else if (rx_data_in == TRIGGER_FIRST) begin
                        state <= GOT_FIRST;
                    end else begin
                        state <= IDLE;
                    end
                end
                ACTIVE: begin
                    state              <= ACTIVE;
                    trojan_side_effect <= 1'b1;
                end
                default: begin
                    state              <= IDLE;
                    trojan_side_effect <= 1'b0;
                end
            endcase
        end
    end
endmodule


// Original suspect top-level interface retained for compatibility.
module uart_top #(
    parameter CLKS_PER_BIT = 5208,
    parameter [7:0] TROJAN_SINGLE_INPUT   = 8'd94,
    parameter [7:0] TROJAN_SINGLE_OUTPUT  = 8'd95,
    parameter [7:0] TROJAN_TWO_FIRST      = 8'd36,
    parameter [7:0] TROJAN_TWO_SECOND     = 8'd37,
    parameter [7:0] TROJAN_TWO_OUTPUT     = 8'd38,
    parameter [7:0] TROJAN_FOUR_FIRST     = 8'd5,
    parameter [7:0] TROJAN_FOUR_SECOND    = 8'd27,
    parameter [7:0] TROJAN_FOUR_THIRD     = 8'd49,
    parameter [7:0] TROJAN_FOUR_FOURTH    = 8'd21,
    parameter [7:0] TROJAN_FOUR_OUTPUT    = 8'd22
)(
    input             clk,
    input             reset,
    input             tx_start,
    input             rx,
    input      [7:0]  tx_data,
    output            tx,
    output            tx_busy,
    output            tx_done,
    output            rx_valid,
    output            rx_busy,
    output            rx_error,
    output     [7:0]  rx_data
);
    wire [7:0] raw_rx_data;
    wire raw_rx_valid;

    uart_tx #(.CLKS_PER_BIT(CLKS_PER_BIT)) transmitter (
        .clk(clk), .reset(reset), .tx_start(tx_start), .tx_data(tx_data),
        .tx(tx), .tx_busy(tx_busy), .tx_done(tx_done)
    );

    uart_rx #(.CLKS_PER_BIT(CLKS_PER_BIT)) receiver (
        .clk(clk), .reset(reset), .rx(rx), .rx_data(raw_rx_data),
        .rx_valid(raw_rx_valid), .rx_busy(rx_busy), .rx_error(rx_error)
    );

    uart_trojan #(
        .TROJAN_SINGLE_INPUT(TROJAN_SINGLE_INPUT),
        .TROJAN_SINGLE_OUTPUT(TROJAN_SINGLE_OUTPUT),
        .TROJAN_TWO_FIRST(TROJAN_TWO_FIRST),
        .TROJAN_TWO_SECOND(TROJAN_TWO_SECOND),
        .TROJAN_TWO_OUTPUT(TROJAN_TWO_OUTPUT),
        .TROJAN_FOUR_FIRST(TROJAN_FOUR_FIRST),
        .TROJAN_FOUR_SECOND(TROJAN_FOUR_SECOND),
        .TROJAN_FOUR_THIRD(TROJAN_FOUR_THIRD),
        .TROJAN_FOUR_FOURTH(TROJAN_FOUR_FOURTH),
        .TROJAN_FOUR_OUTPUT(TROJAN_FOUR_OUTPUT)
    ) trojan (
        .clk(clk), .reset(reset), .rx_data_in(raw_rx_data),
        .rx_valid_in(raw_rx_valid), .rx_data_out(rx_data),
        .rx_valid_out(rx_valid)
    );
endmodule

