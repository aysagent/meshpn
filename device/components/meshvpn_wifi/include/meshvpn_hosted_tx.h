#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define MESHVPN_HOSTED_TX_SLOTS 64
#define MESHVPN_HOSTED_TX_FRAME_MAX 1518
#define MESHVPN_HOSTED_TX_MAX_AGE_US 100000
typedef esp_err_t (*meshvpn_hosted_send_fn)(void *, void *, size_t);

typedef struct {
    uint64_t submitted, enqueued, sent, full, invalid, not_ready, expired, stale;
    uint64_t policy_changed, failed, retries, bytes_sent, residence_us, residence_max_us;
    uint64_t send_us, send_max_us, last_send_us;
    uint64_t direct_sent;
    uint32_t in_use, high_water;
    int32_t last_error;
} meshvpn_hosted_queue_stats_t;
typedef struct {
    bool enabled, throttled, link_up[2], worker_active;
    uint32_t worker_interface, worker_stack_free;
    uint64_t worker_age_us, throttle_starts, throttle_stops, throttle_us;
    uint64_t throttle_max_us, throttle_age_us;
    uint64_t sdio_full[2], sdio_calls[2], sdio_enqueue_us[2], sdio_enqueue_max_us[2];
    uint64_t slave_buffer_calls, slave_buffer_unavailable, slave_buffer_us, slave_buffer_max_us;
    uint64_t rx_interrupts, rx_wait_timeouts, rx_wait_errors, rx_poll_data, rx_without_new_packet;
    uint64_t rx_reads, rx_bytes, rx_read_errors, rx_last_read_us;
    uint32_t rx_pending_max;
    uint64_t rx_netif[2][5], rx_netif_bytes[2];
    meshvpn_hosted_queue_stats_t queue[2]; /* STA, AP; acceptance != RF delivery */
} meshvpn_hosted_tx_stats_t;

esp_err_t meshvpn_hosted_tx_init(void);
esp_err_t meshvpn_hosted_tx_submit(unsigned ifx, void *channel, const void *frame,
                                  size_t len, meshvpn_hosted_send_fn send);
void meshvpn_hosted_tx_link(unsigned ifx, bool up);
void meshvpn_hosted_tx_throttle(bool active);
void meshvpn_hosted_tx_capacity(void);
void meshvpn_hosted_tx_sdio(unsigned ifx, uint64_t elapsed_us, bool full);
void meshvpn_hosted_tx_buffers(uint64_t elapsed_us, bool unavailable);
void meshvpn_hosted_rx_wait(unsigned result); /* 0 IRQ, 1 expected poll timeout, 2 error */
void meshvpn_hosted_rx_pending(unsigned bytes, bool new_packet_irq, bool poll_timeout);
void meshvpn_hosted_rx_complete(unsigned bytes, bool failed);
void meshvpn_hosted_rx_netif(unsigned ifx, unsigned stage, unsigned bytes);
void meshvpn_hosted_tx_snapshot(meshvpn_hosted_tx_stats_t *out);
