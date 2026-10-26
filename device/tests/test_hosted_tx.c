#include <stdio.h>
#include <stdatomic.h>
#include "../components/meshvpn_wifi/meshvpn_hosted_tx.c"

struct test_queue {
    unsigned head, count, cap;
    uint8_t slots[MESHVPN_HOSTED_TX_SLOTS];
};
static int64_t clock_us;
static unsigned policy_epoch, notifications, attempts[2], successes[2];
static unsigned create_calls, live_queues, fail_queue;
static bool fail_alloc, fail_task, allow_policy = true, fail_publish;
static esp_err_t result[2];
static unsigned expected_sequence[2];
static bool concurrent_submit;
static esp_err_t submit(unsigned ifx, unsigned sequence);

int64_t esp_timer_get_time(void) { return clock_us; }
uint32_t meshvpn_vpn_dns_epoch(void) { return policy_epoch; }
bool meshvpn_vpn_sta_egress_allowed(const void *p, size_t n)
{ assert(p && n); return allow_policy; }
void *heap_caps_calloc(size_t n, size_t size, uint32_t caps)
{
    assert(n == 2 * MESHVPN_HOSTED_TX_SLOTS && size == sizeof(tx_slot_t));
    assert(caps == (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    return fail_alloc ? NULL : calloc(n, size);
}
QueueHandle_t xQueueCreate(unsigned cap, unsigned size)
{
    assert(cap == MESHVPN_HOSTED_TX_SLOTS && size == 1);
    if (++create_calls == fail_queue) return NULL;
    QueueHandle_t q = calloc(1, sizeof(*q)); assert(q); q->cap = cap; live_queues++; return q;
}
void vQueueDelete(QueueHandle_t q) { live_queues--; free(q); }
BaseType_t xQueueSend(QueueHandle_t q, const void *p, TickType_t wait)
{
    assert(!wait);
    if (q->count == q->cap || (fail_publish && (q == s_pending[0] || q == s_pending[1]))) return 0;
    q->slots[(q->head + q->count++) % q->cap] = *(uint8_t *)p; return pdTRUE;
}
BaseType_t xQueueReceive(QueueHandle_t q, void *p, TickType_t wait)
{
    assert(!wait); if (!q->count) return 0;
    *(uint8_t *)p = q->slots[q->head]; q->head = (q->head + 1) % q->cap; q->count--; return pdTRUE;
}
BaseType_t xQueueSendToFront(QueueHandle_t q, const void *p, TickType_t wait)
{
    assert(!wait);
    if (q->count == q->cap || fail_publish) return 0;
    q->head = (q->head + q->cap - 1) % q->cap;
    q->slots[q->head] = *(const uint8_t *)p; q->count++; return pdTRUE;
}
BaseType_t xTaskCreate(void (*fn)(void *), const char *name, unsigned stack, void *arg, unsigned prio, TaskHandle_t *task)
{
    assert(fn == worker && name && stack == 3072 && !arg && prio == 18);
    if (fail_task) return 0;
    *task = (void *)123; return pdPASS;
}
BaseType_t xTaskNotifyGive(TaskHandle_t task) { assert(task == s_task); notifications++; return pdPASS; }
uint32_t ulTaskNotifyTake(BaseType_t clear, TickType_t wait)
{ assert(clear == pdTRUE); clock_us += wait * 1000; return 0; }
unsigned uxTaskGetStackHighWaterMark(TaskHandle_t task) { assert(!task); return 2048; }
static esp_err_t send(void *channel, void *frame, size_t len)
{
    unsigned ifx = (uintptr_t)channel - 1; assert(ifx < 2 && len == 32);
    uint8_t *p = frame; attempts[ifx]++; clock_us += 20;
    /* No pointer to caller storage may survive acceptance. */
    for (unsigned i = 1; i < len; i++) assert(p[i] == 0x5a);
    if (concurrent_submit && !ifx) {
        concurrent_submit = false;
        assert(s_direct[0] && submit(0, p[0] + 1) == ESP_OK);
        assert(!service(0)); /* Cannot overtake the still-active fast call. */
    }
    if (!result[ifx]) { assert(p[0] == expected_sequence[ifx]++); successes[ifx]++; }
    return result[ifx];
}
static esp_err_t submit(unsigned ifx, unsigned sequence)
{
    uint8_t input[32]; memset(input, 0x5a, sizeof(input)); input[0] = sequence;
    esp_err_t r = meshvpn_hosted_tx_submit(ifx, (void *)(uintptr_t)(ifx + 1), input, sizeof(input), send);
    memset(input, 0xcc, sizeof(input)); return r;
}
static esp_err_t stage(unsigned ifx, unsigned sequence)
{
    s_direct[ifx] = true; /* Simulate another producer inside its fast call. */
    esp_err_t r = submit(ifx, sequence); s_direct[ifx] = false; return r;
}
static void assert_empty(void)
{
    for (unsigned i = 0; i < 2; i++) {
        assert(!s_stats.queue[i].in_use && !s_pending[i]->count && s_head[i] == -1);
        assert(s_free[i]->count == MESHVPN_HOSTED_TX_SLOTS);
    }
}
int main(void)
{
    fail_alloc = true; assert(meshvpn_hosted_tx_init() == ESP_ERR_NO_MEM); fail_alloc = false;
    for (unsigned i = 1; i <= 4; i++) {
        create_calls = 0; fail_queue = i;
        assert(meshvpn_hosted_tx_init() == ESP_ERR_NO_MEM && !live_queues && !s_pool);
    }
    fail_queue = 0; fail_task = true;
    assert(meshvpn_hosted_tx_init() == ESP_ERR_NO_MEM && !live_queues && !s_pool);
    fail_task = false; assert(meshvpn_hosted_tx_init() == ESP_OK);
    assert(submit(0, 0) == ESP_ERR_INVALID_STATE);
    meshvpn_hosted_tx_link(0, true); meshvpn_hosted_tx_link(1, true);
    assert(meshvpn_hosted_tx_submit(0, (void *)1, "x", 1519, send) == ESP_ERR_INVALID_ARG);
    meshvpn_hosted_tx_throttle(true); clock_us = 1000;
    for (unsigned i = 0; i < MESHVPN_HOSTED_TX_SLOTS; i++) assert(submit(0, i) == ESP_OK);
    assert(submit(0, 64) == ESP_ERR_ESP_NETIF_NO_MEM);
    assert(!service(0) && !attempts[0]);
    /* Congested STA must not starve AP, even with a full STA staging queue. */
    assert(submit(1, 0) == ESP_OK && !service(1) && successes[1] == 1);
    meshvpn_hosted_tx_stats_t snapshot; meshvpn_hosted_tx_snapshot(&snapshot);
    assert(snapshot.throttle_us == 1020 && snapshot.throttle_age_us == 1020);
    meshvpn_hosted_tx_throttle(false);
    result[0] = ESP_ERR_ESP_NETIF_TX_FAILED;
    assert(!service(0) && s_stats.queue[0].in_use == 64);
    assert(submit(1, 1) == ESP_OK && !service(1));
    result[0] = ESP_OK;
    for (unsigned i = 0; i < 64; i++) assert(service(0));
    assert_empty(); assert(successes[0] == 64 && s_stats.queue[0].retries == 1);
    /* Same FIFO head is retained across transient OOM; no duplication/reorder. */
    result[0] = ESP_ERR_ESP_NETIF_NO_MEM; assert(submit(0, 64) == ESP_OK);
    assert(!service(0)); result[0] = ESP_OK; assert(service(0)); assert_empty();
    /* A disconnect/reconnect cannot send frames from the previous link. */
    assert(stage(0, 65) == ESP_OK); meshvpn_hosted_tx_link(0, false); meshvpn_hosted_tx_link(0, true);
    unsigned before = attempts[0]; assert(service(0) && attempts[0] == before);
    assert(s_stats.queue[0].stale == 1); assert_empty();
    /* Endpoint / kill-switch policy changes invalidate even ordinary TCP. */
    assert(stage(0, 65) == ESP_OK); policy_epoch++;
    assert(service(0) && attempts[0] == before && s_stats.queue[0].policy_changed == 1);
    /* A permanently asserted C6 flag cannot retain copies indefinitely. */
    meshvpn_hosted_tx_throttle(true); assert(submit(0, 65) == ESP_OK);
    clock_us += MESHVPN_HOSTED_TX_MAX_AGE_US - 1; assert(!service(0));
    clock_us++; assert(service(0) && s_stats.queue[0].expired == 1); assert_empty();
    meshvpn_hosted_tx_throttle(false);
    allow_policy = false; assert(stage(0, 65) == ESP_OK && service(0));
    assert(attempts[0] == before && s_stats.queue[0].failed == 1); allow_policy = true;
    fail_publish = true; assert(stage(0, 65) == ESP_ERR_ESP_NETIF_NO_MEM);
    fail_publish = false; assert_empty();
    assert(submit(0, 65) == ESP_OK && !service(0)); assert_empty();
    concurrent_submit = true; result[0] = ESP_ERR_ESP_NETIF_TX_FAILED;
    assert(submit(0, 66) == ESP_OK && s_stats.queue[0].in_use == 2);
    result[0] = ESP_OK;
    assert(service(0) && service(0)); assert_empty(); /* 66 must precede 67. */
    meshvpn_hosted_tx_snapshot(&snapshot);
    assert(snapshot.queue[0].high_water == 64 && snapshot.throttle_starts == 2 && snapshot.throttle_stops == 2);
    for (unsigned i = 0; i < 2; i++) {
        meshvpn_hosted_queue_stats_t *q = &snapshot.queue[i];
        assert(q->submitted == q->enqueued + q->direct_sent + q->full + q->invalid + q->not_ready + (i ? 0 : 1));
        assert(q->enqueued + q->direct_sent == q->sent + q->expired + q->stale + q->policy_changed + q->failed - (i ? 0 : 1));
    }
    for (unsigned i = 0; i < 2; i++) { vQueueDelete(s_free[i]); vQueueDelete(s_pending[i]); }
    free(s_pool);
    puts("Hosted TX: owned copies, AP/STA fairness, bounded retries, expiry, policy/link cancellation and init failure cleanup passed");
}
