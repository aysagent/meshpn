#pragma once

/* Waveshare ESP32-P4-WIFI6 (ESP32-P4NRW32 + on-board ESP32-C6).
 * The only on-board LED is connected directly to 5 V and cannot be controlled
 * by the P4. USB-UART uses the P4 UART0 pins shown in the board schematic. */

#define MESHVPN_BOARD_NAME "waveshare_esp32_p4_wifi6"
#define MESHVPN_PIN_LED         -1
#define MESHVPN_PIN_UART_TX     37
#define MESHVPN_PIN_UART_RX     38
#define MESHVPN_PIN_UART_BAUD   115200
#define MESHVPN_PIN_BOOT        35

/* USB 2.0 HS uses the dedicated USBD_N/USBD_P signals on the four-pin
 * connector. They are fixed-function pins and need no GPIO assignment. */
