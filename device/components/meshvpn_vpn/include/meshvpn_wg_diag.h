#pragma once
#include <stdint.h>

/* Boot-lifetime counters. No keys, packet contents or peer identifiers. */
typedef struct {
    uint64_t calls, bytes, time_us, max_us, failed;
    uint64_t core_calls[2];
} meshvpn_wg_crypto_direction_t;
typedef struct {
    uint64_t sampled_us;
    meshvpn_wg_crypto_direction_t encrypt, decrypt;
} meshvpn_wg_crypto_stats_t;
void meshvpn_wg_crypto_snapshot(meshvpn_wg_crypto_stats_t *out);
