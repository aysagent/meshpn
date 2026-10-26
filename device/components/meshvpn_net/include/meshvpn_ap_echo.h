#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
struct netif; struct pbuf;
typedef struct {
    uint32_t target; /* network byte order, same STA subnet */
    uint16_t port, packets, payload, rate_kbps, source_port;
} meshvpn_ap_echo_config_t;
typedef struct {
    uint32_t injected, accepted, received, duplicates, bad_checksum;
    uint16_t mapped_source_port;
    uint64_t send_us, total_us, rtt_sum_us, rtt_max_us;
    int error;
} meshvpn_ap_echo_result_t;
esp_err_t meshvpn_ap_echo_run(struct netif *ap, struct netif *sta,
    const meshvpn_ap_echo_config_t *config, meshvpn_ap_echo_result_t *result);
bool meshvpn_ap_echo_output(struct pbuf *p, uint32_t destination);
void meshvpn_ap_echo_tx(unsigned ifx, const void *frame, size_t length);
