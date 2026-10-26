/* Compile the actual generated SDIO submit function against its ownership ABI. */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_ESP_NETIF_TX_FAILED 0x500e
#define ESP_STA_IF 0
#define ESP_AP_IF 1
#define ESP_SERIAL_IF 2
#define ESP_HCI_IF 3
#define PRIO_Q_SERIAL 0
#define PRIO_Q_BT 1
#define PRIO_Q_OTHERS 2
#define MAX_PAYLOAD_SIZE 1524
#define HOSTED_BLOCK_MAX -1
#define ESP_LOGE(...) ((void)0)
#define H_FREE_PTR_WITH_FUNC(fn,p) do { if (fn) fn(p); } while (0)
typedef struct {
    uint8_t payload_zcopy, if_type, if_num, *payload;
    uint16_t payload_len;
    void *priv_buffer_handle;
    void (*free_buf_handle)(void *);
} interface_buffer_handle_t;
static interface_buffer_handle_t owned;
static unsigned freed, posted, calls, recorded;
static int full;
static bool ready = true;
static int to_slave_queue[] = {0, 1, 2}, sem_to_slave_queue;
static int64_t now;
static int64_t esp_timer_get_time(void) { now += 5; return now; }
static uint8_t is_transport_tx_ready(void) { return ready; }
static void release(void *p) { assert(p); freed++; free(p); }
static int enqueue(int queue, interface_buffer_handle_t *item, int timeout)
{
    assert(queue == (item->if_type == ESP_SERIAL_IF ? 0 : item->if_type == ESP_HCI_IF ? 1 : 2));
    assert(timeout == (item->if_type < 2 ? 0 : HOSTED_BLOCK_MAX));
    calls++; if (!full) owned = *item; return full;
}
static int post(int semaphore) { assert(semaphore == sem_to_slave_queue); posted++; return 0; }
static struct { struct { int (*_h_queue_item)(int, interface_buffer_handle_t *, int); int (*_h_post_semaphore)(int); } *funcs; } g_h;
static void meshvpn_hosted_tx_sdio(unsigned ifx, uint64_t us, bool rejected)
{ assert(ifx < 2 && us == 5 && rejected == (full != 0)); recorded++; }
#include "sdio-tx.inc"
#define MAX_WRITE_BUF_RETRIES 50
#define ESP_HOSTED_SDIO_UNRESPONSIVE_CODE 99
#define BUFFER_AVAILABLE 1
#define BUFFER_UNAVAILABLE 0
#define ESP_LOGV(...) ((void)0)
#define ACQUIRE_LOCK false
static bool locked = true, grant_on_rx;
static unsigned credit_reads, credit_sleeps, credits;
static int sdio_get_tx_buffer_num(uint32_t *out, bool take_lock)
{ assert(locked && !take_lock); credit_reads++; *out = credits; return 0; }
static void unlock_bus(void) { assert(locked); locked = false; }
static void lock_bus(void) { assert(!locked); locked = true; }
#define SDIO_DRV_UNLOCK() unlock_bus()
#define SDIO_DRV_LOCK() lock_bus()
static void sleep_for_rx(unsigned ms)
{
    assert(!locked && ms == 1); credit_sleeps++;
    if (grant_on_rx) credits = 1; /* An RX transfer can run during this wait. */
}
static void unexpected_restart(void) { abort(); }
/* The credit helper uses two other members of the actual g_h ABI. */
#define g_h credit_host
static struct { struct { void (*_h_restart_host)(void); void (*_h_msleep)(unsigned); } *funcs; } credit_host;
#include "sdio-credit.inc"
#undef g_h
int main(void)
{
    typeof(*g_h.funcs) ops = {enqueue, post}; g_h.funcs = &ops;
    for (unsigned ifx = 0; ifx < 4; ifx++) {
        unsigned before_freed = freed, before_posted = posted;
        full = 1;
        assert(esp_hosted_tx(ifx, 0, malloc(64), 32, 1, release) == ESP_ERR_ESP_NETIF_TX_FAILED);
        assert(freed == before_freed + 1 && posted == before_posted);
        full = 0;
        assert(esp_hosted_tx(ifx, 0, malloc(64), 32, 1, release) == ESP_OK);
        assert(freed == before_freed + 1 && posted == before_posted + 1);
        assert(owned.payload == owned.priv_buffer_handle && owned.free_buf_handle == release);
        owned.free_buf_handle(owned.priv_buffer_handle);
    }
    assert(freed == 8 && posted == 4 && calls == 8 && recorded == 4);
    ready = false;
    assert(esp_hosted_tx(0, 0, malloc(64), 32, 1, release) == ESP_FAIL);
    assert(freed == 9 && posted == 4 && calls == 8);
    typeof(*credit_host.funcs) credit_ops = {unexpected_restart, sleep_for_rx}; credit_host.funcs = &credit_ops;
    assert(sdio_is_write_buffer_available(1) == BUFFER_UNAVAILABLE && locked);
    assert(credit_reads == 50 && credit_sleeps == 25);
    grant_on_rx = true; credit_reads = credit_sleeps = 0;
    assert(sdio_is_write_buffer_available(1) == BUFFER_AVAILABLE && locked);
    assert(credit_sleeps == 1); /* Progress required releasing the shared bus. */
    credits = 4; unsigned reads = credit_reads;
    assert(sdio_is_write_buffer_available(2) == BUFFER_AVAILABLE && credit_reads == reads + 1);
    reads = credit_reads;
    assert(sdio_is_write_buffer_available(2) == BUFFER_AVAILABLE && credit_reads == reads);
    puts("SDIO TX: zero Wi-Fi queue wait, free-on-reject exactly once, accepted ownership and semaphore accounting passed");
    puts("SDIO credits: lock released only during sleep, bounded retries, RX progress and cached credit reservation passed");
}
