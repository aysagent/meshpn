#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
/* Authenticated, bounded direct STA client. No persistent configuration. */
typedef struct {
    uint32_t target, nonce;
    uint16_t port, seconds, rate_kbps;
    bool udp, download;
} meshvpn_net_bench_config_t;
typedef struct {
    bool running;
    uint32_t nonce, source, packets, invalid, stalls;
    bool udp_sequence_available;
    uint32_t duplicates, reordered, sequence_span;
    uint64_t bytes, elapsed_us;
    int error;
} meshvpn_net_bench_result_t;
esp_err_t meshvpn_net_bench_start(const meshvpn_net_bench_config_t *config);
void meshvpn_net_bench_cancel(void);
void meshvpn_net_bench_status(meshvpn_net_bench_result_t *result);
