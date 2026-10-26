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

module uart_trojan_clean (
    input clk,
    input reset,
    input [7:0] rx_data_in,
    input rx_valid_in,
    output reg [7:0] rx_data_out,
    output reg rx_valid_out
);
    always @(posedge clk or negedge reset) begin
        if (!reset) begin
            rx_data_out <= 8'd0;
            rx_valid_out <= 1'b0;
        end else begin
            rx_valid_out <= rx_valid_in;
            if (rx_valid_in)
                rx_data_out <= rx_data_in;
        end
    end
endmodule

module uart_top_clean #(
    parameter CLKS_PER_BIT = 5208
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

    uart_tx #(.CLKS_PER_BIT(CLKS_PER_BIT)) transmitter (
        .clk(clk), .reset(reset), .tx_start(tx_start), .tx_data(tx_data),
        .tx(tx), .tx_busy(tx_busy), .tx_done(tx_done)
    );

    uart_rx #(.CLKS_PER_BIT(CLKS_PER_BIT)) receiver (
        .clk(clk), .reset(reset), .rx(rx), .rx_data(raw_rx_data),
        .rx_valid(raw_rx_valid), .rx_busy(rx_busy), .rx_error(rx_error)
    );

    uart_trojan_clean pass_through (
        .clk(clk), .reset(reset), .rx_data_in(raw_rx_data),
        .rx_valid_in(raw_rx_valid), .rx_data_out(rx_data),
        .rx_valid_out(rx_valid)
    );
endmodule
