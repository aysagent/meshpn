#pragma once

#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *name;
    int pin_led;
    int pin_uart_tx;
    int pin_uart_rx;
    int uart_baud;
    int pin_boot;
} meshvpn_board_config_t;

esp_err_t meshvpn_board_init(void);
const meshvpn_board_config_t *meshvpn_board_get_config(void);
void meshvpn_board_led_set(bool on);
/* Gate normal status indication, without changing its requested state.
 * Task-safe; disabling immediately drives the active-low user LED off. */
void meshvpn_board_led_enable(bool enabled);
bool meshvpn_board_led_enabled(void);

/** True while the BOOT button is held down. */
bool meshvpn_board_boot_pressed(void);
bool meshvpn_board_temperature(float *celsius);

#ifdef __cplusplus
}
#endif
