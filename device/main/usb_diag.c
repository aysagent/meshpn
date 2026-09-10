#include "sdkconfig.h"

#if CONFIG_MESHVPN_USB_DIAGNOSTICS
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "meshvpn_log.h"
#include "meshvpn_web.h"
#include "tusb.h"
#include "tusb_cdc_acm.h"

static TaskHandle_t s_task;
#define DIAG_CAPACITY 16384

/* Never print/log/allocate/wait inside the TinyUSB callback. */
static void receive(int itf, cdcacm_event_t *event)
{
    (void)event;
    uint8_t bytes[64]; size_t count = 0;
    if (tinyusb_cdcacm_read(itf, bytes, sizeof(bytes), &count) != ESP_OK) return;
    for (size_t i = 0; i < count; i++) {
        if (bytes[i] == '?' && s_task) {
            xTaskNotifyGive(s_task);
            break;
        }
    }
}

static bool send_bytes(const char *bytes, size_t len)
{
    int64_t deadline = esp_timer_get_time() + 5000000;
    while (len && tud_cdc_n_connected(0) && esp_timer_get_time() < deadline) {
        size_t n = tinyusb_cdcacm_write_queue(0, (const uint8_t *)bytes, len > 64 ? 64 : len);
        bytes += n; len -= n;
        tinyusb_cdcacm_write_flush(0, 0);
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    tinyusb_cdcacm_write_flush(0, 0);
    return len == 0;
}

static void worker(void *arg)
{
    (void)arg;
    for (;;) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        if (!tud_cdc_n_connected(0)) continue;
        /* One bounded snapshot on request; no permanent log buffer or polling. */
        char *buffer = heap_caps_malloc(DIAG_CAPACITY, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!buffer) {
            const char *failure = "MESHPN_DIAG_BEGIN\nerror=no-PSRAM-buffer\nMESHPN_DIAG_END\n";
            send_bytes(failure, strlen(failure));
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        int n = snprintf(buffer, DIAG_CAPACITY,
            "MESHPN_DIAG_BEGIN\nbuild=%s usb_diagnostics=1 uptime_sec=%" PRIi64 " reset_reason=%d\n"
            "internal_free=%u internal_min=%u internal_largest=%u\n",
            esp_app_get_description()->version, esp_timer_get_time() / 1000000,
            (int)esp_reset_reason(), (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
            (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
            (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
        size_t used = n > 0 ? (size_t)n : 0;
        used += meshvpn_web_diag_snapshot(buffer + used, DIAG_CAPACITY - used);
        used += meshvpn_log_copy(buffer + used, DIAG_CAPACITY - used - 32);
        const char *end = "\nMESHPN_DIAG_END\n";
        size_t end_len = strlen(end);
        memcpy(buffer + used, end, end_len); used += end_len;
        send_bytes(buffer, used);
        free(buffer);
        /* Coalesce/rate-limit repeated requests from the physically attached host. */
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void meshvpn_usb_diag_start(void)
{
    if (!tusb_cdc_acm_initialized(0)) {
        ESP_LOGW("usb_diag", "CDC not initialized; diagnostics unavailable");
        return;
    }
    if (xTaskCreate(worker, "usb_diag", 4096, NULL, 1, &s_task) != pdPASS) {
        ESP_LOGW("usb_diag", "Cannot create diagnostics task");
        return;
    }
    tinyusb_cdcacm_register_callback(0, CDC_EVENT_RX, receive);
    ESP_LOGW("usb_diag", "Diagnostic firmware: USB host may read logs; send '?' over CDC");
}
#else
void meshvpn_usb_diag_start(void) {}
#endif
