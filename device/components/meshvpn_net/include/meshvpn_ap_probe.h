#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"
#include "meshvpn_ap_echo.h"
struct netif;
struct pbuf;
typedef struct {
    uint32_t src, dst, seq;
    uint16_t sport, dport, mapped_port;
    uint8_t stages, reply_flags;
    bool synthetic;
    uint64_t age_ms;
} meshvpn_ap_flow_t;
typedef struct {
    bool received, checksums_ok;
    uint8_t flags, rcode;
    uint32_t elapsed_ms;
    uint8_t interface_flags; /* AP up/link/NAPT:1/2/4; STA up/link/NAPT:8/16/32 */
    int error;
} meshvpn_ap_probe_result_t;
typedef struct { uint64_t seen, checked, skipped, bad_ip, bad_tcp, bad_udp; } meshvpn_rx_checksum_t;
#define MESHPN_STA_TCP_EVENTS 64
typedef struct {
    uint32_t elapsed_ms, seq, ack, sack_left, sack_right;
    uint16_t payload, window;
    uint8_t flags, tx, sack_blocks, checksum_checked, bad_ip, bad_tcp;
} meshvpn_sta_tcp_event_t;
typedef struct {
    uint32_t peer, local, initial_seq, packets[2], data_bytes[2], total_events;
    uint32_t checked[2], bad_ip[2], bad_tcp[2];
    uint16_t peer_port;
    uint64_t age_ms;
    unsigned count;
    meshvpn_sta_tcp_event_t events[MESHPN_STA_TCP_EVENTS];
} meshvpn_sta_tcp_trace_t;
void meshvpn_ap_probe_sta_tcp(meshvpn_sta_tcp_trace_t *out);
void meshvpn_ap_probe_attach(struct netif *ap, struct netif *sta);
void meshvpn_ap_probe_input(const struct pbuf *p, const struct netif *inp);
void meshvpn_ap_probe_tx(unsigned ifx, const void *frame, size_t len);
void meshvpn_ap_probe_flows(meshvpn_ap_flow_t out[8]);
void meshvpn_ap_probe_checksums(meshvpn_rx_checksum_t out[4]); /* RX STA/AP, TX STA/AP */
esp_err_t meshvpn_ap_probe_run(meshvpn_ap_probe_result_t out[2]); /* UDP DNS, TCP SYN */
esp_err_t meshvpn_ap_probe_echo(const meshvpn_ap_echo_config_t *, meshvpn_ap_echo_result_t *);
