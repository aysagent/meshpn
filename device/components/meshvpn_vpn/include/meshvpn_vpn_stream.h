#pragma once
#include "meshvpn_vpn_frame.h"

#define MESHVPN_VPN_BATCH_FRAMES 8
#define MESHVPN_VPN_STREAM_TIMEOUT_US 5000000ULL
typedef struct {
    meshvpn_vpn_decoder_t decoder;
    uint64_t partial_since;
    bool partial_active;
} meshvpn_vpn_rx_stream_t;
bool meshvpn_vpn_rx_feed(meshvpn_vpn_rx_stream_t *, const uint8_t *, size_t,
                        uint64_t now, meshvpn_vpn_packet_fn, void *);
bool meshvpn_vpn_rx_expired(const meshvpn_vpn_rx_stream_t *, uint64_t now);

typedef struct {
    uint8_t data[MESHVPN_VPN_BATCH_FRAMES * (MESHVPN_VPN_MTU + 4)];
    size_t length, used, ends[MESHVPN_VPN_BATCH_FRAMES];
    unsigned count, completed;
} meshvpn_vpn_tx_batch_t;
bool meshvpn_vpn_tx_append(meshvpn_vpn_tx_batch_t *, const uint8_t *, size_t);
/* Returns full frames/IPv4 bytes accepted in this write, NOT host delivery. */
bool meshvpn_vpn_tx_advance(meshvpn_vpn_tx_batch_t *, size_t sent, unsigned *packets, size_t *bytes);
