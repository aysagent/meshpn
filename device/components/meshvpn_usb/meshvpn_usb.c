#include "meshvpn_usb.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
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

static esp_err_t meshvpn_usb_transmit(void *h, void *buffer, size_t len)
{
    (void)h;

    if (!tud_ready()) {
        s_stats.tx_no_host++;
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = ESP_FAIL;

    /* Retry without vTaskDelay — tinyusb_net_send_sync blocks on the USB task.
     * Single-shot TX (phase 3 tune) drove tx_dropped into thousands. */
    for (int attempt = 0; attempt < 64; attempt++) {
        err = tinyusb_net_send_sync(buffer, (uint16_t)len, NULL, pdMS_TO_TICKS(25));
        if (err == ESP_OK) {
            if (attempt > 0) {
                s_stats.tx_retried++;
            }
            s_stats.tx_ok++;
            s_stats.tx_bytes += len;
            if (len > s_stats.tx_max_len) {
                s_stats.tx_max_len = (uint16_t)len;
            }
            return ESP_OK;
        }
        if (err != ESP_FAIL) {
            break;
        }
        taskYIELD();
    }

    if (err == ESP_ERR_TIMEOUT) {
        s_stats.tx_timeout++;
    } else {
        s_stats.tx_dropped++;
    }
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

    ESP_LOGI(TAG, "USB sync TX installed (64x25ms retry)");

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
    memcpy(out, &s_stats, sizeof(*out));
    out->host_ready = tud_ready();
    out->can_xmit = out->host_ready && tud_network_can_xmit(1514);
    out->tx_queue_depth = 0;
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
