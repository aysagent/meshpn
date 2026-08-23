#include "meshvpn_board.h"

#include <string.h>

#include "driver/gpio.h"
#include "esp_log.h"
#include "sdkconfig.h"

#if CONFIG_MESHVPN_BOARD_XIAO_ESP32S3
#include "pins.h"
#elif CONFIG_MESHVPN_BOARD_M5_STAMP_P4_C6
#include "pins.h"
#else
#error "No board selected in menuconfig"
#endif

static const char *TAG = "meshvpn_board";

static meshvpn_board_config_t s_board = {
    .name = MESHVPN_BOARD_NAME,
    .pin_led = MESHVPN_PIN_LED,
    .pin_uart_tx = MESHVPN_PIN_UART_TX,
    .pin_uart_rx = MESHVPN_PIN_UART_RX,
    .uart_baud = MESHVPN_PIN_UART_BAUD,
    .pin_boot = MESHVPN_PIN_BOOT,
};

esp_err_t meshvpn_board_init(void)
{
    ESP_LOGI(TAG, "Board: %s", s_board.name);

    if (s_board.pin_led >= 0) {
        gpio_config_t io = {
            .pin_bit_mask = 1ULL << s_board.pin_led,
            .mode = GPIO_MODE_OUTPUT,
            .pull_up_en = GPIO_PULLUP_DISABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type = GPIO_INTR_DISABLE,
        };
        ESP_ERROR_CHECK(gpio_config(&io));
        meshvpn_board_led_set(false);
    }

    if (s_board.pin_boot >= 0) {
        gpio_config_t io = {
            .pin_bit_mask = 1ULL << s_board.pin_boot,
            .mode = GPIO_MODE_INPUT,
            .pull_up_en = GPIO_PULLUP_ENABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type = GPIO_INTR_DISABLE,
        };
        ESP_ERROR_CHECK(gpio_config(&io));
    }

    return ESP_OK;
}

bool meshvpn_board_boot_pressed(void)
{
    if (s_board.pin_boot < 0) {
        return false;
    }
    return gpio_get_level(s_board.pin_boot) == 0;
}

const meshvpn_board_config_t *meshvpn_board_get_config(void)
{
    return &s_board;
}

void meshvpn_board_led_set(bool on)
{
    if (s_board.pin_led < 0) {
        return;
    }
    gpio_set_level(s_board.pin_led, on ? 0 : 1);
}
