#include "meshvpn_board.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"

static portMUX_TYPE s_led_lock = portMUX_INITIALIZER_UNLOCKED;
static bool s_enabled = true, s_requested;

static void apply_locked(void)
{
    int pin = meshvpn_board_get_config()->pin_led;
    if (pin >= 0) gpio_set_level(pin, s_enabled && s_requested ? 0 : 1);
}

void meshvpn_board_led_set(bool on)
{
    portENTER_CRITICAL(&s_led_lock);
    s_requested = on;
    apply_locked();
    portEXIT_CRITICAL(&s_led_lock);
}

void meshvpn_board_led_status_tick(bool sta_connected, bool vpn_enabled, bool vpn_connected)
{
    portENTER_CRITICAL(&s_led_lock);
    bool online = sta_connected && (!vpn_enabled || vpn_connected);
    s_requested = online ? true : !s_requested;
    apply_locked();
    portEXIT_CRITICAL(&s_led_lock);
}

void meshvpn_board_led_enable(bool enabled)
{
    portENTER_CRITICAL(&s_led_lock);
    s_enabled = enabled;
    apply_locked();
    portEXIT_CRITICAL(&s_led_lock);
}

bool meshvpn_board_led_enabled(void)
{
    portENTER_CRITICAL(&s_led_lock);
    bool enabled = s_enabled;
    portEXIT_CRITICAL(&s_led_lock);
    return enabled;
}
