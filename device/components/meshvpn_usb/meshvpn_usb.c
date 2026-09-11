#include "meshvpn_usb.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "tinyusb.h"
#include "tinyusb_net.h"
#if CONFIG_TINYUSB_CDC_ENABLED
#include "tusb_cdc_acm.h"
#endif

static const char *TAG = "meshvpn_usb";

static meshvpn_usb_stats_t s_stats;
static portMUX_TYPE s_stats_lock = portMUX_INITIALIZER_UNLOCKED;

static void record_tx(esp_err_t err, size_t len, uint32_t attempts,
                      uint32_t busy, int64_t started)
{
    uint64_t elapsed = (uint64_t)(esp_timer_get_time() - started);
    /* No driver calls, allocations or waits while holding this lock. TX is
     * serialized by lwIP; readers run on either core. Publish once per frame. */
    portENTER_CRITICAL(&s_stats_lock);
    s_stats.tx_calls++;
    s_stats.tx_attempts += attempts;
    s_stats.tx_busy += busy;
    if (attempts > s_stats.tx_attempts_max) s_stats.tx_attempts_max = attempts;
    s_stats.tx_wait_us += elapsed;
    if (elapsed > s_stats.tx_wait_max_us) s_stats.tx_wait_max_us = elapsed;
    if (elapsed <= 1000) s_stats.tx_wait_le_1ms++;
    else if (elapsed <= 5000) s_stats.tx_wait_1_5ms++;
    else if (elapsed <= 25000) s_stats.tx_wait_5_25ms++;
    else s_stats.tx_wait_gt_25ms++;

    if (err == ESP_OK) {
        s_stats.tx_ok++;
        if (attempts > 1) s_stats.tx_retried++;
        s_stats.tx_bytes += len;
        if (len > s_stats.tx_max_len) s_stats.tx_max_len = (uint16_t)len;
    } else if (attempts == 0) {
        s_stats.tx_no_host++;
    } else if (err == ESP_ERR_TIMEOUT) {
        s_stats.tx_timeout++;
    } else {
        s_stats.tx_dropped++;
        if (err == ESP_FAIL) s_stats.tx_busy_exhausted++;
        else if (err == ESP_ERR_NO_MEM) s_stats.tx_no_mem++;
        else if (err == ESP_ERR_INVALID_STATE) s_stats.tx_invalid_state++;
        else s_stats.tx_other_error++;
    }
    portEXIT_CRITICAL(&s_stats_lock);
}

static esp_err_t meshvpn_usb_transmit(void *h, void *buffer, size_t len)
{
    (void)h;
    int64_t started = esp_timer_get_time();

    if (!tud_ready()) {
        record_tx(ESP_ERR_INVALID_STATE, len, 0, 0, started);
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = ESP_FAIL;
    uint32_t attempts = 0, busy = 0;

    /* Retry without vTaskDelay — tinyusb_net_send_sync blocks on the USB task.
     * Single-shot TX (phase 3 tune) drove tx_dropped into thousands. */
    for (int attempt = 0; attempt < 64; attempt++) {
        attempts++;
        err = tinyusb_net_send_sync(buffer, (uint16_t)len, NULL, pdMS_TO_TICKS(25));
        if (err == ESP_OK) {
            record_tx(err, len, attempts, busy, started);
            return ESP_OK;
        }
        if (err != ESP_FAIL) {
            break;
        }
        busy++;
        taskYIELD();
    }

    record_tx(err, len, attempts, busy, started);
    return ESP_FAIL;
}

static esp_err_t meshvpn_usb_transmit_wrap(void *h, void *buffer, size_t len, void *netstack_buf)
{
    (void)netstack_buf;
    return meshvpn_usb_transmit(h, buffer, len);
}

static void meshvpn_usb_free_rx_buffer(void *h, void *buffer)
{
    (void)h;
    if (buffer) {
        free(buffer);
    }
}

esp_err_t meshvpn_usb_attach_netif(esp_netif_t *netif)
{
    if (!netif) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_netif_driver_ifconfig_t ifconfig = {
        .handle = "USB",
        .transmit = meshvpn_usb_transmit,
        .transmit_wrap = meshvpn_usb_transmit_wrap,
        .driver_free_rx_buffer = meshvpn_usb_free_rx_buffer,
    };

    esp_err_t err = esp_netif_set_driver_config(netif, &ifconfig);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to install USB transmit path: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "USB sync TX installed (64 attempts, 25ms event wait per attempt)");

#if CONFIG_TINYUSB_CDC_ENABLED
    const tinyusb_config_cdcacm_t acm_cfg = {
        .usb_dev = TINYUSB_USBDEV_0,
        .cdc_port = TINYUSB_CDC_ACM_0,
    };
    /* ACM interface stays in the descriptor for iOS/macOS NCM binding; do not
     * route ESP_LOG to it — console traffic contends with NCM TX on FS USB. */
    err = tusb_cdc_acm_init(&acm_cfg);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "USB CDC-ACM init failed: %s", esp_err_to_name(err));
    }
#endif

    return ESP_OK;
}

void meshvpn_usb_get_stats(meshvpn_usb_stats_t *out)
{
    if (!out) return;
    portENTER_CRITICAL(&s_stats_lock);
    memcpy(out, &s_stats, sizeof(*out));
    portEXIT_CRITICAL(&s_stats_lock);
    out->host_ready = tud_ready();
    /* Never call tud_network_can_xmit here: NCM allocates/queues NTBs and may
     * start an endpoint transfer. Only the TinyUSB task may do that. */
}

esp_err_t meshvpn_usb_init(void)
{
    ESP_LOGI(TAG, "USB profile: %s", meshvpn_usb_profile_name());
    return ESP_OK;
}

#if CONFIG_MESHVPN_USB_PROFILE_NCM
const char *meshvpn_usb_profile_name(void)
{
    return "ncm";
}
#elif CONFIG_MESHVPN_USB_PROFILE_RNDIS
const char *meshvpn_usb_profile_name(void)
{
    return "rndis";
}
#elif CONFIG_MESHVPN_USB_PROFILE_ECM
const char *meshvpn_usb_profile_name(void)
{
    return "ecm";
}
#else
const char *meshvpn_usb_profile_name(void)
{
    return "unknown";
}
#endif
