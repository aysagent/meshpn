#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESHVPN_BOARD_NAME "xiao_esp32s3"

/* User LED (active low on XIAO ESP32-S3) */
#define MESHVPN_PIN_LED         21

/* UART debug: D6=TX GPIO43, D7=RX GPIO44 */
#define MESHVPN_PIN_UART_TX     43
#define MESHVPN_PIN_UART_RX     44
#define MESHVPN_PIN_UART_BAUD   115200

/* Boot button */
#define MESHVPN_PIN_BOOT        0

/* USB OTG D+/D- are fixed on ESP32-S3 (GPIO19/20) — no board-specific pins */

#ifdef __cplusplus
}
#endif
