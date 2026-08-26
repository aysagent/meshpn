#include "meshvpn_usb.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "tinyusb.h"
#include "tinyusb_net.h"
#if CONFIG_TINYUSB_CDC_ENABLED
#include "tusb_cdc_acm.h"
#endif

static const char *TAG = "meshvpn_usb";

#define USB_TX_QUEUE_DEPTH 16
#define USB_TX_MAX_LEN     1514
#define USB_TX_RETRY_MAX   64
#define USB_TX_RETRY_MS    25

typedef struct {
    uint8_t *buf;
    uint16_t len;
} meshvpn_usb_tx_job_t;

static meshvpn_usb_stats_t s_stats;
static QueueHandle_t s_tx_queue;
static bool s_tx_async_ready;

/** Sync path: may increment tx_dropped on final failure. */
static esp_err_t meshvpn_usb_send_with_retry(void *buffer, uint16_t len, bool allow_drop)
{
    esp_err_t err = ESP_FAIL;

    for (int attempt = 0; attempt < USB_TX_RETRY_MAX; attempt++) {
        err = tinyusb_net_send_sync(buffer, len, NULL, pdMS_TO_TICKS(USB_TX_RETRY_MS));
        if (err == ESP_OK) {
            if (attempt > 0) {
                s_stats.tx_retried++;
            }
            s_stats.tx_ok++;
            s_stats.tx_bytes += len;
            if (len > s_stats.tx_max_len) {
                s_stats.tx_max_len = len;
            }
            return ESP_OK;
        }
        if (err != ESP_FAIL) {
            break;
        }
        taskYIELD();
    }

    if (!allow_drop) {
        return ESP_FAIL;
    }

    if (err == ESP_ERR_TIMEOUT) {
        s_stats.tx_timeout++;
    } else {
        s_stats.tx_dropped++;
    }
    return ESP_FAIL;
}

/** Queued path: lwIP already got ESP_OK — keep trying until sent or host gone. */
static void meshvpn_usb_send_until_ok(void *buffer, uint16_t len)
{
    while (tud_ready()) {
        if (meshvpn_usb_send_with_retry(buffer, len, false) == ESP_OK) {
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    s_stats.tx_no_host++;
}

static void meshvpn_usb_tx_worker(void *arg)
{
    meshvpn_usb_tx_job_t job;

    (void)arg;
    while (true) {
        if (xQueueReceive(s_tx_queue, &job, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        meshvpn_usb_send_until_ok(job.buf, job.len);
        free(job.buf);
    }
}

static esp_err_t meshvpn_usb_tx_async_start(void)
{
    if (s_tx_async_ready) {
        return ESP_OK;
    }

    s_tx_queue = xQueueCreate(USB_TX_QUEUE_DEPTH, sizeof(meshvpn_usb_tx_job_t));
    if (!s_tx_queue) {
        ESP_LOGE(TAG, "USB TX queue alloc failed");
        return ESP_ERR_NO_MEM;
    }

    BaseType_t ok = xTaskCreatePinnedToCore(meshvpn_usb_tx_worker, "usb_tx", 4096, NULL, 7,
                                            NULL, 1);
    if (ok != pdPASS) {
        vQueueDelete(s_tx_queue);
        s_tx_queue = NULL;
        ESP_LOGE(TAG, "USB TX worker task failed");
        return ESP_ERR_NO_MEM;
    }

    s_tx_async_ready = true;
    ESP_LOGI(TAG, "USB async TX v2 (queue %d, sync fallback, no post-OK drop)",
             USB_TX_QUEUE_DEPTH);
    return ESP_OK;
}

static esp_err_t meshvpn_usb_transmit(void *h, void *buffer, size_t len)
{
    (void)h;

    if (!tud_ready()) {
        s_stats.tx_no_host++;
        return ESP_ERR_INVALID_STATE;
    }

    if (len == 0 || len > USB_TX_MAX_LEN) {
        s_stats.tx_dropped++;
        return ESP_FAIL;
    }

    if (s_tx_async_ready && s_tx_queue) {
        uint8_t *copy = malloc(len);
        if (copy) {
            memcpy(copy, buffer, len);
            meshvpn_usb_tx_job_t job = {
                .buf = copy,
                .len = (uint16_t)len,
            };
            if (xQueueSend(s_tx_queue, &job, 0) == pdTRUE) {
                return ESP_OK;
            }
            free(copy);
        }
    }

    /* Queue full or OOM: fall back to sync TX (honest ESP_OK/ESP_FAIL for lwIP). */
    return meshvpn_usb_send_with_retry(buffer, (uint16_t)len, true);
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

    esp_err_t err = meshvpn_usb_tx_async_start();
    if (err != ESP_OK) {
        return err;
    }

    esp_netif_driver_ifconfig_t ifconfig = {
        .handle = "USB",
        .transmit = meshvpn_usb_transmit,
        .transmit_wrap = meshvpn_usb_transmit_wrap,
        .driver_free_rx_buffer = meshvpn_usb_free_rx_buffer,
    };

    err = esp_netif_set_driver_config(netif, &ifconfig);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to install USB transmit path: %s", esp_err_to_name(err));
        return err;
    }

#if CONFIG_TINYUSB_CDC_ENABLED
    const tinyusb_config_cdcacm_t acm_cfg = {
        .usb_dev = TINYUSB_USBDEV_0,
        .cdc_port = TINYUSB_CDC_ACM_0,
    };
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
    out->can_xmit = out->host_ready && tud_network_can_xmit(USB_TX_MAX_LEN);
    if (s_tx_queue) {
        out->tx_queue_depth = (uint16_t)uxQueueMessagesWaiting(s_tx_queue);
    } else {
        out->tx_queue_depth = 0;
    }
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
