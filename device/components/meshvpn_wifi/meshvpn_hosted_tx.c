#include "meshvpn_hosted_tx.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "meshvpn_vpn_egress.h"

/* Includes every policy/endpoint transition, not individual probe requests. */
extern uint32_t meshvpn_vpn_dns_epoch(void);
#if CONFIG_IDF_TARGET_ESP32P4
extern void meshvpn_ap_probe_tx(unsigned ifx, const void *frame, size_t len);
#define TRACE_TX(ifx, frame, len, err) do { if ((err) == ESP_OK) meshvpn_ap_probe_tx(ifx, frame, len); } while (0)
#else
#define TRACE_TX(ifx, frame, len, err) ((void)0)
#endif
_Static_assert(MESHVPN_HOSTED_TX_SLOTS > 0 && MESHVPN_HOSTED_TX_SLOTS < 256, "slot indices must fit uint8_t");
typedef struct {
    uint64_t queued_us;
    uint32_t generation, policy;
    uint16_t len;
    void *channel;
    meshvpn_hosted_send_fn send;
    uint8_t frame[MESHVPN_HOSTED_TX_FRAME_MAX];
} tx_slot_t;
static tx_slot_t *s_pool;
static QueueHandle_t s_free[2], s_pending[2];
static TaskHandle_t s_task;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static meshvpn_hosted_tx_stats_t s_stats;
static uint32_t s_generation[2];
static uint64_t s_throttle_since, s_worker_since;
static int s_head[2] = {-1, -1}; /* worker-owned; one FIFO head per interface */
static bool s_direct[2]; /* reserves per-interface order for a nonblocking fast call */

static bool retryable(esp_err_t err)
{ return err == ESP_ERR_ESP_NETIF_TX_FAILED || err == ESP_ERR_ESP_NETIF_NO_MEM || err == ESP_ERR_NO_MEM; }
static void release_direct(unsigned ifx)
{
    portENTER_CRITICAL(&s_lock); s_direct[ifx] = false; portEXIT_CRITICAL(&s_lock);
    meshvpn_hosted_tx_capacity();
}

void meshvpn_hosted_tx_capacity(void)
{
    portENTER_CRITICAL(&s_lock);
    /* Fast-path SDIO completions need no worker/TCP-IP round trip. */
    TaskHandle_t task = (s_stats.queue[0].in_use || s_stats.queue[1].in_use) ? s_task : NULL;
    portEXIT_CRITICAL(&s_lock);
    if (task) xTaskNotifyGive(task);
}
void meshvpn_hosted_tx_throttle(bool active)
{
    uint64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_lock);
    if (active != s_stats.throttled) {
        if (active) { s_stats.throttle_starts++; s_throttle_since = now; }
        else {
            uint64_t held = now - s_throttle_since;
            s_stats.throttle_stops++; s_stats.throttle_us += held;
            if (held > s_stats.throttle_max_us) s_stats.throttle_max_us = held;
        }
        s_stats.throttled = active;
    }
    portEXIT_CRITICAL(&s_lock);
    meshvpn_hosted_tx_capacity();
}
void meshvpn_hosted_tx_link(unsigned ifx, bool up)
{
    if (ifx > 1) return;
    portENTER_CRITICAL(&s_lock);
    if (!up || s_stats.link_up[ifx] != up) s_generation[ifx]++;
    s_stats.link_up[ifx] = up;
    portEXIT_CRITICAL(&s_lock);
    meshvpn_hosted_tx_capacity();
}
void meshvpn_hosted_tx_sdio(unsigned ifx, uint64_t us, bool full)
{
    if (ifx > 1) return;
    portENTER_CRITICAL(&s_lock);
    s_stats.sdio_calls[ifx]++; s_stats.sdio_enqueue_us[ifx] += us;
    if (us > s_stats.sdio_enqueue_max_us[ifx]) s_stats.sdio_enqueue_max_us[ifx] = us;
    if (full) s_stats.sdio_full[ifx]++;
    portEXIT_CRITICAL(&s_lock);
}
void meshvpn_hosted_tx_snapshot(meshvpn_hosted_tx_stats_t *out)
{
    uint64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_lock);
    *out = s_stats;
    if (out->throttled) {
        out->throttle_age_us = now - s_throttle_since;
        out->throttle_us += out->throttle_age_us;
        if (out->throttle_age_us > out->throttle_max_us) out->throttle_max_us = out->throttle_age_us;
    }
    if (out->worker_active) out->worker_age_us = now - s_worker_since;
    portEXIT_CRITICAL(&s_lock);
}
void meshvpn_hosted_tx_buffers(uint64_t us, bool unavailable)
{
    portENTER_CRITICAL(&s_lock);
    s_stats.slave_buffer_calls++; s_stats.slave_buffer_us += us;
    if (us > s_stats.slave_buffer_max_us) s_stats.slave_buffer_max_us = us;
    if (unavailable) s_stats.slave_buffer_unavailable++;
    portEXIT_CRITICAL(&s_lock);
}
void meshvpn_hosted_rx_wait(unsigned result)
{
    portENTER_CRITICAL(&s_lock);
    if (result == 0) s_stats.rx_interrupts++;
    else if (result == 1) s_stats.rx_wait_timeouts++;
    else s_stats.rx_wait_errors++;
    portEXIT_CRITICAL(&s_lock);
}
void meshvpn_hosted_rx_pending(unsigned bytes, bool irq, bool timeout)
{
    portENTER_CRITICAL(&s_lock);
    if (bytes > s_stats.rx_pending_max) s_stats.rx_pending_max = bytes;
    if (bytes && !irq) s_stats.rx_without_new_packet++;
    if (bytes && timeout) s_stats.rx_poll_data++;
    portEXIT_CRITICAL(&s_lock);
}
void meshvpn_hosted_rx_complete(unsigned bytes, bool failed)
{
    uint64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_lock);
    if (failed) s_stats.rx_read_errors++;
    else { s_stats.rx_reads++; s_stats.rx_bytes += bytes; s_stats.rx_last_read_us = now; }
    portEXIT_CRITICAL(&s_lock);
}

/* All calls, including retry and queue publication, have zero queue wait.
 * The owned copy survives a failed direct call, which frees only its own DMA
 * copy. Every accepted slot is returned exactly once by this worker. */
esp_err_t meshvpn_hosted_tx_submit(unsigned ifx, void *channel, const void *frame,
                                  size_t len, meshvpn_hosted_send_fn send)
{
    if (ifx > 1) return ESP_ERR_INVALID_ARG;
    uint8_t slot;
    uint32_t generation;
    portENTER_CRITICAL(&s_lock);
    meshvpn_hosted_queue_stats_t *q = &s_stats.queue[ifx];
    q->submitted++;
    if (!frame || !len || len > MESHVPN_HOSTED_TX_FRAME_MAX || !channel || !send) {
        q->invalid++; portEXIT_CRITICAL(&s_lock); return ESP_ERR_INVALID_ARG;
    }
    if (!s_stats.enabled || !s_stats.link_up[ifx]) {
        q->not_ready++; portEXIT_CRITICAL(&s_lock); return ESP_ERR_INVALID_STATE;
    }
    generation = s_generation[ifx];
    bool direct = !q->in_use && !s_direct[ifx] && (ifx || !s_stats.throttled);
    if (direct) s_direct[ifx] = true;
    portEXIT_CRITICAL(&s_lock);
    uint32_t policy = meshvpn_vpn_dns_epoch();
    if (direct) {
        /* The patched SDIO handoff has zero queue wait. Keep the uncontended
         * path in the original caller context: no PSRAM copy or worker hop.
         * Later submissions may stage, but the worker cannot overtake us. */
        int64_t start = esp_timer_get_time();
        esp_err_t err = !ifx && !meshvpn_vpn_sta_egress_allowed(frame, len) ? ESP_ERR_INVALID_STATE :
                        send(channel, (void *)frame, len);
        uint64_t elapsed = esp_timer_get_time() - start;
        TRACE_TX(ifx, frame, len, err);
        portENTER_CRITICAL(&s_lock);
        q->send_us += elapsed;
        if (elapsed > q->send_max_us) q->send_max_us = elapsed;
        if (err == ESP_OK) { q->sent++; q->direct_sent++; q->bytes_sent += len; q->last_send_us = esp_timer_get_time(); }
        else if (retryable(err)) { q->retries++; q->last_error = err; }
        else { q->failed++; q->last_error = err; }
        portEXIT_CRITICAL(&s_lock);
        if (!retryable(err)) { release_direct(ifx); return err; }
    }
    if (xQueueReceive(s_free[ifx], &slot, 0) != pdTRUE) {
        portENTER_CRITICAL(&s_lock); q->full++; portEXIT_CRITICAL(&s_lock);
        if (direct) release_direct(ifx);
        return ESP_ERR_ESP_NETIF_NO_MEM;
    }
    tx_slot_t *p = &s_pool[ifx * MESHVPN_HOSTED_TX_SLOTS + slot];
    p->queued_us = esp_timer_get_time(); p->generation = generation; p->policy = policy;
    p->channel = channel; p->send = send; p->len = len;
    memcpy(p->frame, frame, len);
    portENTER_CRITICAL(&s_lock);
    q->in_use++;
    if (q->in_use > q->high_water) q->high_water = q->in_use;
    q->enqueued++;
    portEXIT_CRITICAL(&s_lock);
    /* A fast call that failed must precede frames staged while it ran. */
    BaseType_t queued = direct ? xQueueSendToFront(s_pending[ifx], &slot, 0) : xQueueSend(s_pending[ifx], &slot, 0);
    if (queued != pdTRUE) {
        portENTER_CRITICAL(&s_lock); q->in_use--; q->enqueued--; q->failed++; portEXIT_CRITICAL(&s_lock);
        BaseType_t returned = xQueueSend(s_free[ifx], &slot, 0); assert(returned == pdTRUE);
        if (direct) release_direct(ifx);
        return ESP_ERR_ESP_NETIF_NO_MEM;
    }
    if (direct) release_direct(ifx);
    meshvpn_hosted_tx_capacity();
    return ESP_OK;
}

/* One turn per interface prevents STA backpressure from starving AP TCP ACKs.
 * Retry only failures for which the direct transport did NOT accept ownership.
 * A nonblocking SDIO enqueue makes the same ownership rule true for queue-full. */
static bool service(unsigned ifx)
{
    uint8_t slot;
    portENTER_CRITICAL(&s_lock);
    bool direct = s_direct[ifx];
    portEXIT_CRITICAL(&s_lock);
    if (direct) return false;
    if (s_head[ifx] < 0) {
        if (xQueueReceive(s_pending[ifx], &slot, 0) != pdTRUE) return false;
        s_head[ifx] = slot;
    }
    slot = s_head[ifx];
    tx_slot_t *p = &s_pool[ifx * MESHVPN_HOSTED_TX_SLOTS + slot];
    uint64_t now = esp_timer_get_time();
    uint32_t policy = meshvpn_vpn_dns_epoch();
    portENTER_CRITICAL(&s_lock);
    meshvpn_hosted_queue_stats_t *q = &s_stats.queue[ifx];
    bool stale = p->generation != s_generation[ifx] || !s_stats.link_up[ifx];
    bool expired = now - p->queued_us >= MESHVPN_HOSTED_TX_MAX_AGE_US;
    bool changed = p->policy != policy;
    bool blocked = !ifx && s_stats.throttled;
    if (stale) q->stale++;
    else if (changed) q->policy_changed++;
    else if (expired) q->expired++;
    portEXIT_CRITICAL(&s_lock);
    if (!stale && !changed && !expired) {
        if (blocked) return false;
        esp_err_t err;
        if (!ifx && !meshvpn_vpn_sta_egress_allowed(p->frame, p->len)) err = ESP_ERR_INVALID_STATE;
        else {
            portENTER_CRITICAL(&s_lock);
            s_stats.worker_active = true; s_stats.worker_interface = ifx; s_worker_since = now;
            portEXIT_CRITICAL(&s_lock);
            err = p->send(p->channel, p->frame, p->len);
            uint64_t us = esp_timer_get_time() - now;
            TRACE_TX(ifx, p->frame, p->len, err);
            portENTER_CRITICAL(&s_lock);
            s_stats.worker_active = false; q->send_us += us;
            if (us > q->send_max_us) q->send_max_us = us;
            portEXIT_CRITICAL(&s_lock);
        }
        portENTER_CRITICAL(&s_lock);
        if (err == ESP_OK) { q->sent++; q->bytes_sent += p->len; q->last_send_us = esp_timer_get_time(); }
        else if (retryable(err)) {
            q->retries++; q->last_error = err;
            portEXIT_CRITICAL(&s_lock); return false;
        } else { q->failed++; q->last_error = err; }
        portEXIT_CRITICAL(&s_lock);
    }
    uint64_t residence = esp_timer_get_time() - p->queued_us;
    portENTER_CRITICAL(&s_lock);
    q->residence_us += residence;
    if (residence > q->residence_max_us) q->residence_max_us = residence;
    q->in_use--;
    portEXIT_CRITICAL(&s_lock);
    s_head[ifx] = -1;
    BaseType_t returned = xQueueSend(s_free[ifx], &slot, 0); assert(returned == pdTRUE);
    return true;
}
static esp_err_t drain(void *arg)
{
    bool *progress = arg;
    /* Config/kill-switch changes are applied by this same TCP/IP thread.
     * Serialize the final epoch check and zero-wait handoff with them. There
     * is no capacity wait here; only the worker sleeps/retries outside lwIP. */
    for (unsigned n = 0; n < 16; n++) {
        bool a = service(0), b = service(1);
        if (!a && !b) break;
        *progress = true;
    }
    return ESP_OK;
}
static void worker(void *arg)
{
    (void)arg;
    for (;;) {
        bool progress = false;
        esp_netif_tcpip_exec(drain, &progress);
        if (progress) continue;
        uint32_t stack_free = uxTaskGetStackHighWaterMark(NULL);
        portENTER_CRITICAL(&s_lock);
        s_stats.worker_stack_free = stack_free;
        bool pending = s_stats.queue[0].in_use || s_stats.queue[1].in_use;
        portEXIT_CRITICAL(&s_lock);
        /* Completion/throttle/link events normally wake us. The bounded tick
         * also handles a missed hint and ensures expiry if C6 never resumes. */
        ulTaskNotifyTake(pdTRUE, pending ? pdMS_TO_TICKS(1) : portMAX_DELAY);
    }
}
esp_err_t meshvpn_hosted_tx_init(void)
{
    if (s_pool) return ESP_ERR_INVALID_STATE;
    s_pool = heap_caps_calloc(2 * MESHVPN_HOSTED_TX_SLOTS, sizeof(*s_pool), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_pool) return ESP_ERR_NO_MEM;
    for (unsigned i = 0; i < 2; i++) {
        s_free[i] = xQueueCreate(MESHVPN_HOSTED_TX_SLOTS, sizeof(uint8_t));
        s_pending[i] = xQueueCreate(MESHVPN_HOSTED_TX_SLOTS, sizeof(uint8_t));
        if (!s_free[i] || !s_pending[i]) goto failed;
        for (uint8_t n = 0; n < MESHVPN_HOSTED_TX_SLOTS; n++) xQueueSend(s_free[i], &n, 0);
    }
    TaskHandle_t task;
    if (xTaskCreate(worker, "wifi_tx", 3072, NULL, 18, &task) != pdPASS) goto failed;
    portENTER_CRITICAL(&s_lock); s_task = task; s_stats.enabled = true; portEXIT_CRITICAL(&s_lock);
    return ESP_OK;
failed:
    for (unsigned i = 0; i < 2; i++) {
        if (s_free[i]) vQueueDelete(s_free[i]);
        if (s_pending[i]) vQueueDelete(s_pending[i]);
        s_free[i] = s_pending[i] = NULL;
    }
    free(s_pool); s_pool = NULL;
    return ESP_ERR_NO_MEM;
}
