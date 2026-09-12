#include <assert.h>
#include <stdatomic.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include "../components/meshvpn_usb/meshvpn_usb.c"

static bool ready = true;
static unsigned busy_left, sends, yields, delays, polls;
static esp_err_t final_result;
static int64_t now_us, per_attempt_us;
static esp_netif_driver_ifconfig_t driver;
static atomic_bool stop_reader;
static atomic_bool reader_started;
#if CONFIG_MESHVPN_USB_TX_QUEUE
static esp_err_t queue_init_result = ESP_ERR_NO_MEM;
static meshvpn_usb_tx_send_fn queue_sender;
static unsigned enqueues;
static uint32_t queue_epoch;
static bool change_epoch_on_send;
#if CONFIG_MESHVPN_USB_TX_EVENT_WAIT
static unsigned prepares, capacity_waits;
static esp_err_t capacity_result = ESP_OK;
void meshvpn_usb_tx_prepare_wait(void) { prepares++; }
esp_err_t meshvpn_usb_tx_wait_capacity(uint32_t epoch, int64_t deadline)
{
    assert(prepares > capacity_waits && deadline > now_us);
    capacity_waits++;
    now_us += 1000;
    return epoch != queue_epoch ? ESP_ERR_INVALID_STATE : capacity_result;
}
#endif
esp_err_t meshvpn_usb_tx_queue_init(meshvpn_usb_tx_send_fn fn)
{ queue_sender=fn; return queue_init_result; }
esp_err_t meshvpn_usb_tx_queue_submit(const void *buffer, size_t len)
{ assert(buffer && len==1514); enqueues++; return ESP_OK; }
uint32_t meshvpn_usb_tx_queue_epoch(void) { return queue_epoch; }
#endif

bool tud_ready(void) { return ready; }
bool tud_network_can_xmit(unsigned size)
{
    (void)size;
    /* A read must never enter this state-mutating driver API. */
    assert(!"statistics called tud_network_can_xmit");
    return false;
}
int64_t esp_timer_get_time(void) { return now_us; }
void test_usb_yield(void) { yields++; }
void vTaskDelay(unsigned ticks)
{
    assert(ticks == 1 && sends > 0 && sends < 64);
    delays++;
    /* Deterministic 1kHz clock model, not a real scheduler timing guarantee. */
    now_us += 1000;
    meshvpn_usb_stats_t snapshot;
    meshvpn_usb_get_stats(&snapshot); /* delay must not hold the stats lock */
}
esp_err_t esp_netif_set_driver_config(esp_netif_t *n, const esp_netif_driver_ifconfig_t *d)
{
    assert(n); driver = *d; return ESP_OK;
}
esp_err_t tinyusb_net_send_sync(void *buf, uint16_t len, void *arg, unsigned wait)
{
    assert(buf && len == 1514 && !arg && wait == 25);
    sends++;
#if CONFIG_MESHVPN_USB_TX_QUEUE
    if (change_epoch_on_send) { queue_epoch++; change_epoch_on_send=false; }
#endif
    now_us += per_attempt_us;
    /* Reentrant reader while TX waits must not deadlock or publish half a frame. */
    meshvpn_usb_stats_t snapshot;
    meshvpn_usb_get_stats(&snapshot);
    assert(snapshot.tx_calls == snapshot.tx_ok + snapshot.tx_dropped +
           snapshot.tx_timeout + snapshot.tx_no_host);
    if (busy_left) { busy_left--; return ESP_FAIL; }
    return final_result;
}
static void reset(void)
{
    memset(&s_stats, 0, sizeof(s_stats));
    ready = true; busy_left = sends = yields = delays = 0;
    final_result = ESP_OK; now_us = 0; per_attempt_us = 100;
}
static meshvpn_usb_stats_t send_frame(esp_err_t expected)
{
    char packet[1514] = {0};
    esp_err_t r = driver.transmit_wrap(NULL, packet, sizeof(packet), NULL);
    assert(r == expected);
    meshvpn_usb_stats_t s;
    meshvpn_usb_get_stats(&s);
    assert(s.tx_calls == s.tx_ok + s.tx_dropped + s.tx_timeout + s.tx_no_host);
    assert(s.tx_dropped == s.tx_busy_exhausted + s.tx_no_mem + s.tx_invalid_state + s.tx_other_error);
    assert(s.tx_calls == s.tx_wait_le_1ms + s.tx_wait_1_5ms + s.tx_wait_5_25ms + s.tx_wait_gt_25ms);
    return s;
}
static void *reader(void *unused)
{
    (void)unused;
    while (!atomic_load(&stop_reader)) {
        meshvpn_usb_stats_t s;
        meshvpn_usb_get_stats(&s);
        assert(s.tx_calls == s.tx_ok + s.tx_dropped + s.tx_timeout + s.tx_no_host);
        assert(s.tx_calls == s.tx_wait_le_1ms + s.tx_wait_1_5ms + s.tx_wait_5_25ms + s.tx_wait_gt_25ms);
        polls++;
        atomic_store(&reader_started, true);
    }
    return NULL;
}
int main(void)
{
    esp_netif_t netif = {0};
    assert(meshvpn_usb_attach_netif(NULL) == ESP_ERR_INVALID_ARG);
    assert(meshvpn_usb_attach_netif(&netif) == ESP_OK);
    meshvpn_usb_get_stats(NULL);
    reset();
    meshvpn_usb_stats_t a, b;
    meshvpn_usb_get_stats(&a);
    for (unsigned i = 0; i < 10000; i++) meshvpn_usb_get_stats(&b);
    assert(!memcmp(&a, &b, sizeof(a)) && !sends && !yields && !delays);
    meshvpn_usb_stats_t s = send_frame(ESP_OK);
    assert(s.tx_ok == 1 && !s.tx_retried && s.tx_bytes == 1514 && s.tx_max_len == 1514);
    assert(!delays && !yields);
    reset(); busy_left = 2; per_attempt_us = 2000;
    s = send_frame(ESP_OK);
    assert(s.tx_ok == 1 && s.tx_retried == 1 && s.tx_busy == 2 && sends == 3 && !delays && yields == 2);
    assert(s.tx_attempts == 3 && s.tx_attempts_max == 3 && s.tx_wait_us == 6000 && s.tx_wait_max_us == 6000 && s.tx_wait_5_25ms == 1);
    reset(); busy_left = 100;
    s = send_frame(ESP_FAIL);
    assert(s.tx_busy_exhausted == 1 && s.tx_dropped == 1 && s.tx_busy == 64 && sends == 64 && !s.tx_retried);
    assert(!delays && yields == 64 && s.tx_wait_us == 6400 && s.tx_wait_5_25ms == 1);
    reset(); busy_left = 63;
    s = send_frame(ESP_OK);
    assert(s.tx_retried == 1 && s.tx_ok == 1 && !s.tx_dropped && s.tx_busy == 63 && sends == 64);
    assert(!delays && yields == 63);
    const esp_err_t errors[] = {ESP_ERR_TIMEOUT, ESP_ERR_NO_MEM, ESP_ERR_INVALID_STATE, 999};
    for (unsigned i = 0; i < sizeof(errors)/sizeof(errors[0]); i++) {
        reset(); final_result = errors[i]; per_attempt_us = 30000;
        s = send_frame(ESP_FAIL);
        assert(sends == 1 && !s.tx_busy && !s.tx_retried && s.tx_wait_gt_25ms == 1);
        assert(!delays && !yields);
        assert(s.tx_timeout == (i == 0) && s.tx_no_mem == (i == 1) && s.tx_invalid_state == (i == 2) && s.tx_other_error == (i == 3));
        reset(); busy_left = 1; final_result = errors[i];
        s = send_frame(ESP_FAIL);
        assert(sends == 2 && !delays && yields == 1 && s.tx_busy == 1 && !s.tx_retried);
        assert(s.tx_timeout == (i == 0) && s.tx_no_mem == (i == 1) && s.tx_invalid_state == (i == 2) && s.tx_other_error == (i == 3));
    }
    reset(); ready = false;
    s = send_frame(ESP_ERR_INVALID_STATE);
    assert(s.tx_no_host == 1 && !s.tx_dropped && !s.tx_timeout && !sends && !delays && !yields);
    const int64_t bounds[] = {1000, 1001, 5000, 5001, 25000, 25001};
    for (unsigned i = 0; i < sizeof(bounds)/sizeof(bounds[0]); i++) {
        reset(); per_attempt_us = bounds[i];
        s = send_frame(ESP_OK);
        assert(s.tx_wait_le_1ms == (i == 0));
        assert(s.tx_wait_1_5ms == (i == 1 || i == 2));
        assert(s.tx_wait_5_25ms == (i == 3 || i == 4));
        assert(s.tx_wait_gt_25ms == (i == 5));
    }
    reset();
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, reader, NULL));
    while (!atomic_load(&reader_started)) sched_yield();
    char packet[1514] = {0};
    for (unsigned i = 0; i < 50000; i++) assert(driver.transmit(NULL, packet, sizeof(packet)) == ESP_OK);
    atomic_store(&stop_reader, true);
    assert(!pthread_join(thread, NULL));
    meshvpn_usb_get_stats(&s);
    assert(polls && s.tx_ok == 50000 && s.tx_wait_us == 5000000);
#if CONFIG_MESHVPN_USB_TX_QUEUE
    /* First part covered allocation-failure fallback. Now verify successful
     * attachment uses enqueue only, and only the worker calls the sync sender. */
    queue_init_result=ESP_OK;
    assert(meshvpn_usb_attach_netif(&netif)==ESP_OK && s_use_queue);
    unsigned old_sends=sends;
    assert(driver.transmit(NULL,packet,sizeof(packet))==ESP_OK);
    assert(enqueues==1 && sends==old_sends);
    assert(queue_sender(packet,sizeof(packet),queue_epoch)==ESP_OK);
    assert(sends==old_sends+1);
    assert(queue_sender(packet,sizeof(packet),queue_epoch+1)==ESP_FAIL);
    assert(sends==old_sends+1); /* stale frame never reaches TinyUSB */
    busy_left=10; change_epoch_on_send=true;
    assert(queue_sender(packet,sizeof(packet),queue_epoch)==ESP_FAIL);
    assert(sends==old_sends+2); /* disconnect between retries stops the loop */
#if CONFIG_MESHVPN_USB_TX_EVENT_WAIT
    reset(); busy_left=3;
    assert(queue_sender(packet,sizeof(packet),queue_epoch)==ESP_OK);
    assert(sends==4 && !yields && s_stats.tx_retried==1);
    reset(); busy_left=20; capacity_result=ESP_ERR_TIMEOUT;
    assert(queue_sender(packet,sizeof(packet),queue_epoch)==ESP_FAIL);
    assert(sends==1 && !yields && s_stats.tx_timeout==1 && !s_stats.tx_dropped);
    reset(); final_result=ESP_ERR_NO_MEM;
    unsigned waits=capacity_waits;
    assert(queue_sender(packet,sizeof(packet),queue_epoch)==ESP_FAIL);
    assert(sends==1 && capacity_waits==waits && s_stats.tx_no_mem==1);
#endif
#endif
    puts("USB TX accounting, passive snapshots and concurrent reader: OK");
}
