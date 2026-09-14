#pragma once
#include <stdint.h>

/* Completed driver handoff calls, NOT radio completions or MAC retries.
 * Lifetime counters; snapshots are atomic across STA/AP. No buffers retained. */
#define MESHVPN_WIFI_TX_COUNTERS(X) \
    X(calls) X(copy_calls) X(ref_calls) X(accepted) X(bytes_accepted) \
    X(no_mem) X(invalid_arg) X(not_ready) X(tx_disallow) X(post_failed) X(other_error) \
    X(call_us) X(call_le_100us) X(call_100_1000us) X(call_1_5ms) X(call_gt_5ms)
typedef struct {
#define FIELD(name) uint64_t name;
    MESHVPN_WIFI_TX_COUNTERS(FIELD)
#undef FIELD
    uint64_t call_max_us;
    int32_t last_error;
} meshvpn_wifi_tx_diag_t;
void meshvpn_wifi_tx_snapshot(meshvpn_wifi_tx_diag_t out[2]); /* STA, AP */
