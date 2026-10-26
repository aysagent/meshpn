/* Actual generated RX loop: timeout/IRQ/pending-length and CMD53 error cases. */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_TIMEOUT 0x107
#define ESP_LOGE(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGV(...) ((void)0)
#define BIT(n) (1u << (n))
#define SDIO_INT_NEW_PACKET 0
#define SDIO_INT_START_THROTTLE 7
#define SDIO_INT_STOP_THROTTLE 6
#define DO_COMBINED_REG_READ 1
#define INT_RAW_INDEX 0
#define PACKET_LEN_INDEX 4
#define H_SDIO_ALWAYS_HOST_RX_MAX_TRANSPORT_SIZE 0
#define H_SDIO_HOST_STREAMING_MODE 1
#define H_SDIO_HOST_RX_MODE 1
#define H_SDIO_RX_BLOCK_ONLY_XFER 0
#define ACQUIRE_LOCK false
#define ESP_SLAVE_CMD53_END_ADDR 0x1f800
#define ESP_RX_BYTE_MAX 0x100000
#define ESP_BLOCK_SIZE 512
#define pdMS_TO_TICKS(n) (n)
#define unlikely(n) (n)
static uint8_t buffer[32768];
static uint32_t registers[2];
static uint8_t *reg_buf = (uint8_t *)registers;
static void *sdio_handle = (void *)123;
static uint8_t wifi_tx_throttling;
static uint32_t sdio_rx_byte_count;
static struct { unsigned write_index; struct { uint8_t *buf; unsigned buf_size; } buffer[1]; } double_buf;
static jmp_buf end;
static bool locked, fail_read;
static int wait_result;
static unsigned wait_calls, read_calls, deliveries, wait_kind, pending_calls, completions, completion_errors;
static bool saw_without_irq, saw_poll_data;
static void lock(void) { assert(!locked); locked = true; }
static void unlock(void) { assert(locked); locked = false; }
#define SDIO_DRV_LOCK() lock()
#define SDIO_DRV_UNLOCK() unlock()
static int wait_irq(void *ctx, unsigned ticks)
{
    assert(ctx == sdio_handle && ticks == 10 && !locked);
    if (wait_calls++) longjmp(end, 1);
    return wait_result;
}
static int read_block(void *ctx, unsigned addr, uint8_t *out, unsigned len, bool take_lock)
{
    assert(ctx == sdio_handle && addr == ESP_SLAVE_CMD53_END_ADDR - 128);
    assert(out == buffer && len == 128 && !take_lock && locked);
    read_calls++; return fail_read ? ESP_FAIL : ESP_OK;
}
static void unexpected_restart(void) { assert(!"unexpected restart"); }
static struct { struct {
    int (*_h_sdio_wait_slave_intr)(void *, unsigned);
    int (*_h_sdio_read_block)(void *, unsigned, uint8_t *, unsigned, bool);
    void (*_h_restart_host)(void);
} *funcs; } g_h;
static int sdio_read_regs(void *p) { assert(p == reg_buf && locked); return ESP_OK; }
static int sdio_clear_intr(unsigned bits) { assert(bits == registers[0] && locked); return ESP_OK; }
static int sdio_get_len_from_slave(unsigned *n, unsigned value, bool take_lock)
{ assert(locked && !take_lock); *n = value; return 0; }
static uint8_t *sdio_rx_get_buffer(unsigned n) { assert(n == 128 && locked); return buffer; }
static void sdio_rx_free_buffer(uint8_t *p) { assert(p == buffer); }
static int sdio_push_data_to_queue(uint8_t *p, unsigned len)
{ assert(p == buffer && len == 128 && !locked); deliveries++; return 0; }
static void meshvpn_hosted_rx_wait(unsigned k) { wait_kind = k; }
static void meshvpn_hosted_tx_throttle(bool active) { assert(active == (wifi_tx_throttling != 0)); }
static void meshvpn_hosted_rx_pending(unsigned n, bool irq, bool timeout)
{ assert(n == 128); pending_calls++; saw_without_irq = !irq; saw_poll_data = timeout; }
static void meshvpn_hosted_rx_complete(unsigned bytes, bool failed)
{ assert(bytes == (failed ? 0 : 128)); completions++; completion_errors += failed; }
static void meshvpn_hosted_rx_drop(unsigned reason, unsigned bytes) { (void)reason; (void)bytes; assert(false); }
static void run_rx(void)
{
    esp_err_t res;
    uint8_t *rxbuff = NULL, *pos;
    int ret;
    uint32_t len_from_slave, data_left, len_to_read, interrupts;
    uint32_t *intr_index = NULL, *read_len_index = NULL;
#include "sdio-rx-loop.inc"
}
static void run_case(int result, unsigned irq, unsigned pending, bool failed)
{
    wait_result = result; registers[0] = irq; registers[1] = pending;
    locked = false; fail_read = failed; sdio_rx_byte_count = 1000;
    wait_calls = read_calls = deliveries = pending_calls = completions = completion_errors = 0;
    saw_without_irq = saw_poll_data = false;
    if (!setjmp(end)) run_rx();
    assert(!locked && wait_calls == 2);
}
int main(void)
{
    typeof(*g_h.funcs) ops = {wait_irq, read_block, unexpected_restart}; g_h.funcs = &ops;
    double_buf.buffer[0].buf = buffer; double_buf.buffer[0].buf_size = sizeof(buffer);
    run_case(ESP_ERR_TIMEOUT, 0, 128, false);
    assert(wait_kind == 1 && read_calls == 1 && deliveries == 1 && completions == 1);
    assert(saw_without_irq && saw_poll_data && sdio_rx_byte_count == 1128);
    run_case(ESP_ERR_TIMEOUT, 0, 0, false);
    assert(wait_kind == 1 && !read_calls && !deliveries && !pending_calls && sdio_rx_byte_count == 1000);
    run_case(ESP_OK, BIT(SDIO_INT_START_THROTTLE), 128, false);
    assert(wait_kind == 0 && read_calls == 1 && saw_without_irq && !saw_poll_data && wifi_tx_throttling);
    run_case(ESP_OK, BIT(SDIO_INT_NEW_PACKET) | BIT(SDIO_INT_STOP_THROTTLE), 128, false);
    assert(read_calls == 1 && deliveries == 1 && !saw_without_irq && !wifi_tx_throttling);
    run_case(ESP_OK, BIT(SDIO_INT_NEW_PACKET), 128, true);
    assert(read_calls == 1 && !deliveries && completion_errors == 1 && sdio_rx_byte_count == 1000);
    run_case(ESP_FAIL, 0, 128, false);
    assert(wait_kind == 2 && !read_calls && !deliveries);
    puts("SDIO RX: missing notification recovery, idle timeout, throttle-only IRQ, normal IRQ and failed-read counter bounds passed");
}
