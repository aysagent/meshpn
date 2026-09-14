#include "meshvpn_wifi_diag.h"
#include <stdbool.h>
#include "esp_private/wifi.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"

static portMUX_TYPE s_tx_lock = portMUX_INITIALIZER_UNLOCKED;
static meshvpn_wifi_tx_diag_t s_tx[2];

static void record(wifi_interface_t ifx, size_t len, int err, uint64_t us, bool ref)
{
    if (ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) return;
    portENTER_CRITICAL(&s_tx_lock);
    meshvpn_wifi_tx_diag_t *s = &s_tx[ifx == WIFI_IF_AP];
    s->calls++;
    if (ref) s->ref_calls++; else s->copy_calls++;
    if (err == ESP_OK) { s->accepted++; s->bytes_accepted += len; }
    else {
        s->last_error = err;
        switch (err) {
        case ESP_ERR_NO_MEM: s->no_mem++; break;
        case ESP_ERR_INVALID_ARG: s->invalid_arg++; break;
        case ESP_ERR_WIFI_IF:
        case ESP_ERR_WIFI_CONN:
        case ESP_ERR_WIFI_NOT_INIT:
        case ESP_ERR_WIFI_NOT_STARTED:
        case ESP_ERR_WIFI_STATE:
        case ESP_ERR_WIFI_NOT_ASSOC: s->not_ready++; break;
        case ESP_ERR_WIFI_TX_DISALLOW: s->tx_disallow++; break;
        case ESP_ERR_WIFI_POST: s->post_failed++; break;
        default: s->other_error++; break;
        }
    }
    s->call_us += us;
    if (us > s->call_max_us) s->call_max_us = us;
    if (us <= 100) s->call_le_100us++;
    else if (us <= 1000) s->call_100_1000us++;
    else if (us <= 5000) s->call_1_5ms++;
    else s->call_gt_5ms++;
    portEXIT_CRITICAL(&s_tx_lock);
}

int __real_esp_wifi_internal_tx(wifi_interface_t ifx, void *buffer, uint16_t len);
esp_err_t __real_esp_wifi_internal_tx_by_ref(wifi_interface_t ifx, void *buffer, size_t len, void *netstack_buf);

int __wrap_esp_wifi_internal_tx(wifi_interface_t ifx, void *buffer, uint16_t len)
{
    int64_t start = esp_timer_get_time();
    int err = __real_esp_wifi_internal_tx(ifx, buffer, len);
    record(ifx, len, err, esp_timer_get_time() - start, false);
    return err;
}

esp_err_t __wrap_esp_wifi_internal_tx_by_ref(wifi_interface_t ifx, void *buffer, size_t len, void *netstack_buf)
{
    int64_t start = esp_timer_get_time();
    esp_err_t err = __real_esp_wifi_internal_tx_by_ref(ifx, buffer, len, netstack_buf);
    record(ifx, len, err, esp_timer_get_time() - start, true);
    return err;
}

void meshvpn_wifi_tx_snapshot(meshvpn_wifi_tx_diag_t out[2])
{
    portENTER_CRITICAL(&s_tx_lock);
    out[0] = s_tx[0]; out[1] = s_tx[1];
    portEXIT_CRITICAL(&s_tx_lock);
}
