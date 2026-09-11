#include "meshvpn_usb_tx_queue.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "tinyusb.h"

typedef struct {
    int64_t queued_us;
    uint32_t epoch;
    uint16_t len;
    uint8_t data[MESHVPN_USB_TX_FRAME_MAX];
} tx_slot_t;
static tx_slot_t *s_pool;
static QueueHandle_t s_free, s_pending;
static TaskHandle_t s_task;
static meshvpn_usb_tx_send_fn s_send;
static portMUX_TYPE s_queue_lock = portMUX_INITIALIZER_UNLOCKED;
static meshvpn_usb_tx_queue_stats_t s_queue_stats;
static uint32_t s_epoch;

uint32_t meshvpn_usb_tx_queue_epoch(void)
{
    portENTER_CRITICAL(&s_queue_lock);
    uint32_t value = s_epoch;
    portEXIT_CRITICAL(&s_queue_lock);
    return value;
}

#if CONFIG_MESHVPN_USB_TX_QUEUE
/* NCM/CDC only: Kconfig excludes MSC, whose dependency supplies these hooks.
 * TinyUSB task context, never ISR. Mount also invalidates pre-reset frames
 * even when a bus reset did not call umount. No queued pointer is freed here. */
void tud_mount_cb(void)
{
    portENTER_CRITICAL(&s_queue_lock);
    s_epoch++;
    portEXIT_CRITICAL(&s_queue_lock);
}
void tud_umount_cb(void) { tud_mount_cb(); }
#endif

static void release_slot(uint8_t slot)
{
    portENTER_CRITICAL(&s_queue_lock);
    s_queue_stats.in_use--;
    portEXIT_CRITICAL(&s_queue_lock);
    BaseType_t released = xQueueSend(s_free, &slot, 0);
    /* A slot has exactly one owner; the free queue cannot be full here. */
    assert(released == pdTRUE);
    (void)released;
}

static bool process_one(TickType_t wait)
{
    uint8_t index;
    if (xQueueReceive(s_pending, &index, wait) != pdTRUE) return false;
    tx_slot_t *slot = &s_pool[index];
    int64_t now = esp_timer_get_time();
    uint64_t age = (uint64_t)(now - slot->queued_us);
    bool stale = slot->epoch != meshvpn_usb_tx_queue_epoch() || !tud_ready();
    bool expired = !stale && age > MESHVPN_USB_TX_MAX_AGE_US;
    portENTER_CRITICAL(&s_queue_lock);
    s_queue_stats.worker_active = true;
    portEXIT_CRITICAL(&s_queue_lock);

    /* This is the sole sync sender once queue mode is enabled. The dependency
     * returns only after its callback can no longer read our payload, including
     * its timeout cleanup. Never release the slot on an independent timer. */
    esp_err_t result = ESP_FAIL;
    if (!stale && !expired) result = s_send(slot->data, slot->len, slot->epoch);
    uint64_t residence = (uint64_t)(esp_timer_get_time() - slot->queued_us);
    portENTER_CRITICAL(&s_queue_lock);
    s_queue_stats.completed++;
    s_queue_stats.queue_wait_us += age;
    if (age > s_queue_stats.queue_wait_max_us) s_queue_stats.queue_wait_max_us = age;
    if (stale) s_queue_stats.stale++;
    else if (expired) s_queue_stats.expired++;
    else if (result == ESP_OK) s_queue_stats.sent++;
    else s_queue_stats.send_failed++;
    s_queue_stats.residence_us += residence;
    if (residence > s_queue_stats.residence_max_us) s_queue_stats.residence_max_us = residence;
    s_queue_stats.worker_active = false;
    portEXIT_CRITICAL(&s_queue_lock);
    release_slot(index);
    return true;
}

static void tx_worker(void *arg)
{
    (void)arg;
    for (;;) process_one(portMAX_DELAY);
}

esp_err_t meshvpn_usb_tx_queue_init(meshvpn_usb_tx_send_fn send)
{
    if (!send) return ESP_ERR_INVALID_ARG;
    if (s_task) return ESP_OK;
    /* Do not steal scarce internal RAM if PSRAM allocation fails. */
    s_pool = heap_caps_calloc(MESHVPN_USB_TX_SLOTS, sizeof(*s_pool), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_pool) goto failed;
    s_free = xQueueCreate(MESHVPN_USB_TX_SLOTS, sizeof(uint8_t));
    s_pending = xQueueCreate(MESHVPN_USB_TX_SLOTS, sizeof(uint8_t));
    if (!s_free || !s_pending) goto failed;
    for (uint8_t i = 0; i < MESHVPN_USB_TX_SLOTS; i++) {
        if (xQueueSend(s_free, &i, 0) != pdTRUE) goto failed;
    }
    s_send = send;
    /* Below TinyUSB priority (6 in this build); no CPU affinity change.
     * Keep the small task stack in internal RAM for flash/cache safety. */
    if (xTaskCreate(tx_worker, "usb_tx", 3072, NULL, 5, &s_task) != pdPASS) goto failed;
    portENTER_CRITICAL(&s_queue_lock);
    s_queue_stats.enabled = true;
    portEXIT_CRITICAL(&s_queue_lock);
    return ESP_OK;

failed:
    if (s_pending) vQueueDelete(s_pending);
    if (s_free) vQueueDelete(s_free);
    free(s_pool);
    s_pool = NULL; s_free = s_pending = NULL; s_task = NULL; s_send = NULL;
    portENTER_CRITICAL(&s_queue_lock);
    s_queue_stats.init_failed++;
    portEXIT_CRITICAL(&s_queue_lock);
    return ESP_ERR_NO_MEM;
}

esp_err_t meshvpn_usb_tx_queue_submit(const void *buffer, size_t len)
{
    uint32_t epoch = meshvpn_usb_tx_queue_epoch();
    bool ready = tud_ready();
    portENTER_CRITICAL(&s_queue_lock);
    s_queue_stats.submitted++;
    esp_err_t rejected = ESP_OK;
    if (!s_queue_stats.enabled) { s_queue_stats.not_ready++; rejected = ESP_ERR_INVALID_STATE; }
    else if (!buffer || !len || len > MESHVPN_USB_TX_FRAME_MAX) { s_queue_stats.invalid_length++; rejected = ESP_ERR_INVALID_ARG; }
    else if (!ready) { s_queue_stats.no_host++; rejected = ESP_ERR_INVALID_STATE; }
    portEXIT_CRITICAL(&s_queue_lock);
    if (rejected != ESP_OK) return rejected;
    uint8_t index;
    if (xQueueReceive(s_free, &index, 0) != pdTRUE) {
        portENTER_CRITICAL(&s_queue_lock);
        s_queue_stats.full++;
        portEXIT_CRITICAL(&s_queue_lock);
        return ESP_ERR_NO_MEM;
    }
    portENTER_CRITICAL(&s_queue_lock);
    s_queue_stats.in_use++;
    if (s_queue_stats.in_use > s_queue_stats.high_water) s_queue_stats.high_water = s_queue_stats.in_use;
    portEXIT_CRITICAL(&s_queue_lock);
    tx_slot_t *slot = &s_pool[index];
    slot->queued_us = esp_timer_get_time();
    slot->epoch = epoch;
    slot->len = (uint16_t)len;
    memcpy(slot->data, buffer, len);
    /* Publish accounting before the queue: a higher-priority worker may consume
     * immediately. No shared stats lock around memcpy or FreeRTOS queue calls. */
    portENTER_CRITICAL(&s_queue_lock);
    s_queue_stats.enqueued++;
    s_queue_stats.bytes_copied += len;
    portEXIT_CRITICAL(&s_queue_lock);
    if (xQueueSend(s_pending, &index, 0) != pdTRUE) {
        portENTER_CRITICAL(&s_queue_lock);
        s_queue_stats.enqueued--;
        s_queue_stats.enqueue_failed++;
        portEXIT_CRITICAL(&s_queue_lock);
        release_slot(index);
        return ESP_FAIL;
    }
    return ESP_OK; /* queued, NOT delivered */
}

void meshvpn_usb_tx_queue_get_stats(meshvpn_usb_tx_queue_stats_t *out)
{
    if (!out) return;
    portENTER_CRITICAL(&s_queue_lock);
    *out = s_queue_stats;
    portEXIT_CRITICAL(&s_queue_lock);
    /* Instantaneous pending depth may differ from the stats snapshot by a
     * concurrent enqueue/dequeue. Includes no driver access or side effects. */
    out->pending = out->enabled ? (uint16_t)uxQueueMessagesWaiting(s_pending) : 0;
}
