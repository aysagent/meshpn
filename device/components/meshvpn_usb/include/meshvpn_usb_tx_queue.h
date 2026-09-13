#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define MESHVPN_USB_TX_SLOTS 8
#define MESHVPN_USB_TX_FRAME_MAX 1536
#define MESHVPN_USB_TX_MAX_AGE_US 50000
#define MESHVPN_USB_BURST_RECORDS 32
#define MESHVPN_USB_BURST_WINDOW_US 1000
typedef struct {
    uint64_t seq, window_us, first_full_us, worker_started_us, last_completed_us;
    uint64_t ncm_captured_us, ncm_sampled_us;
    uint32_t submitted, full, epoch;
    uint16_t in_use, ncm_free, ncm_ready;
    bool worker_active, worker_waiting, ncm_available, ncm_active, ncm_glue;
} meshvpn_usb_burst_record_t;
typedef struct {
    bool available;
    uint32_t session_id;
    uint64_t sampled_us, latest_seq, submitted, full, windows;
    /* Nonempty fixed 1ms windows with 1..4, 5..8, 9..16, >=17 submissions. */
    uint64_t arrival_hist[4];
    meshvpn_usb_burst_record_t records[MESHVPN_USB_BURST_RECORDS];
} meshvpn_usb_burst_stats_t;
void meshvpn_usb_tx_burst_get_stats(meshvpn_usb_burst_stats_t *out);
typedef esp_err_t (*meshvpn_usb_tx_send_fn)(void *, size_t, uint32_t);
#define MESHVPN_USB_QUEUE_COUNTERS(X) \
    X(submitted) X(enqueued) X(completed) X(sent) X(send_failed) \
    X(full) X(no_host) X(invalid_length) X(not_ready) X(enqueue_failed) \
    X(expired) X(stale) X(bytes_copied) X(init_failed) \
    X(capacity_waits) X(capacity_wakeups) X(capacity_timeouts) X(capacity_disconnects)
typedef struct {
    bool enabled, worker_active, event_wait;
    uint16_t in_use, high_water, pending;
    uint64_t queue_wait_us, queue_wait_max_us, residence_us, residence_max_us;
    uint64_t capacity_wait_us;
#define FIELD(name) uint32_t name;
    MESHVPN_USB_QUEUE_COUNTERS(FIELD)
#undef FIELD
} meshvpn_usb_tx_queue_stats_t;

/* Startup only, before installing the producer in esp_netif. On error all
 * partial allocations are released; caller must use the sync fallback. */
esp_err_t meshvpn_usb_tx_queue_init(meshvpn_usb_tx_send_fn send);
esp_err_t meshvpn_usb_tx_queue_submit(const void *buffer, size_t len);
void meshvpn_usb_tx_queue_get_stats(meshvpn_usb_tx_queue_stats_t *out);
uint32_t meshvpn_usb_tx_queue_epoch(void);
/* Worker only: clear OLD signals BEFORE the send attempt, never after BUSY. */
void meshvpn_usb_tx_prepare_wait(void);
esp_err_t meshvpn_usb_tx_wait_capacity(uint32_t epoch, int64_t deadline_us);
/* TinyUSB task only, AFTER completion has freed the NTB and updated state. */
void meshvpn_usb_tx_capacity_available(void);
