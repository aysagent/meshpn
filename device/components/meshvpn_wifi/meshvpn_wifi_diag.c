#include "meshvpn_wifi_diag.h"
#include <stdbool.h>
#include "esp_private/wifi.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "meshvpn_vpn_egress.h"
#include "sdkconfig.h"

static portMUX_TYPE s_tx_lock = portMUX_INITIALIZER_UNLOCKED;
static meshvpn_wifi_tx_diag_t s_tx[2];
static meshvpn_sdio_call_t s_sdio[4];
static meshvpn_sdio_drop_t s_sdio_drops[4];

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
        case ESP_ERR_ESP_NETIF_TX_FAILED: s->netif_tx_failed++; break;
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
    if (ifx == WIFI_IF_AP) meshvpn_vpn_lan_egress(buffer, len, false);
    int64_t start = esp_timer_get_time();
    int err = ifx == WIFI_IF_STA && !meshvpn_vpn_sta_egress_allowed(buffer, len) ?
              ESP_ERR_WIFI_TX_DISALLOW : __real_esp_wifi_internal_tx(ifx, buffer, len);
    record(ifx, len, err, esp_timer_get_time() - start, false);
    return err;
}

esp_err_t __wrap_esp_wifi_internal_tx_by_ref(wifi_interface_t ifx, void *buffer, size_t len, void *netstack_buf)
{
    if (ifx == WIFI_IF_AP) meshvpn_vpn_lan_egress(buffer, len, false);
    int64_t start = esp_timer_get_time();
    esp_err_t err = ifx == WIFI_IF_STA && !meshvpn_vpn_sta_egress_allowed(buffer, len) ?
                   ESP_ERR_WIFI_TX_DISALLOW : __real_esp_wifi_internal_tx_by_ref(ifx, buffer, len, netstack_buf);
    record(ifx, len, err, esp_timer_get_time() - start, true);
    return err;
}

void meshvpn_wifi_tx_snapshot(meshvpn_wifi_tx_diag_t out[2])
{
    portENTER_CRITICAL(&s_tx_lock);
    out[0] = s_tx[0]; out[1] = s_tx[1];
    portEXIT_CRITICAL(&s_tx_lock);
}

void meshvpn_wifi_sdio_snapshot(meshvpn_sdio_call_t out[4])
{
    portENTER_CRITICAL(&s_tx_lock);
    for (unsigned i = 0; i < 4; i++) out[i] = s_sdio[i];
    portEXIT_CRITICAL(&s_tx_lock);
}

void meshvpn_hosted_rx_drop(unsigned reason, unsigned bytes)
{
    if (reason >= 4) return;
    portENTER_CRITICAL(&s_tx_lock);
    s_sdio_drops[reason].events++; s_sdio_drops[reason].bytes += bytes;
    portEXIT_CRITICAL(&s_tx_lock);
}
void meshvpn_wifi_sdio_drop_snapshot(meshvpn_sdio_drop_t out[4])
{
    portENTER_CRITICAL(&s_tx_lock);
    for (unsigned i = 0; i < 4; i++) out[i] = s_sdio_drops[i];
    portEXIT_CRITICAL(&s_tx_lock);
}

#if CONFIG_ESP_HOSTED_SDIO_HOST_INTERFACE
/* ESP-Hosted 1.4.x public port ABI. Count completed host calls, including
 * lock wait and preemption, not RF retransmissions or application delivery. */
static void sdio_record(unsigned kind, uint16_t size, int result, int64_t elapsed)
{
    portENTER_CRITICAL(&s_tx_lock);
    meshvpn_sdio_call_t *v = &s_sdio[kind];
    v->calls++; v->time_us += elapsed;
    if (elapsed > v->max_us) v->max_us = elapsed;
    if (result) { v->failed++; v->last_error = result; }
    else v->bytes += size;
    portEXIT_CRITICAL(&s_tx_lock);
}
#define SDIO_WRAP(name, index) \
int __real_hosted_sdio_##name(void *, uint32_t, uint8_t *, uint16_t, bool); \
int __wrap_hosted_sdio_##name(void *ctx, uint32_t reg, uint8_t *data, uint16_t size, bool lock) { \
    int64_t start = esp_timer_get_time(); \
    int result = __real_hosted_sdio_##name(ctx, reg, data, size, lock); \
    sdio_record(index, size, result, esp_timer_get_time() - start); return result; \
}
SDIO_WRAP(read_block, 0)
SDIO_WRAP(write_block, 1)
SDIO_WRAP(read_reg, 2)
SDIO_WRAP(write_reg, 3)
#undef SDIO_WRAP
#endif
