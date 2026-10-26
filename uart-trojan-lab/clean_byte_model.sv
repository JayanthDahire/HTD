`timescale 1ns/1ps
// Clean expected behaviour at the Trojan insertion boundary:
// every valid received byte is passed through unchanged.
module uart_trojan_clean (
    input wire clk,
    input wire reset,
    input wire [7:0] rx_data_in,
    input wire rx_valid_in,
    output reg [7:0] rx_data_out,
    output reg rx_valid_out
);
    always @(posedge clk or negedge reset) begin
        if (!reset) begin
            rx_data_out  <= 8'd0;
            rx_valid_out <= 1'b0;
        end else begin
            rx_valid_out <= rx_valid_in;
            if (rx_valid_in)
                rx_data_out <= rx_data_in;
        end
    end
endmodule
