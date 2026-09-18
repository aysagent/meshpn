#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MESHVPN_VPN_MTU 1400
#define MESHVPN_VPN_SLOTS 16
/* No allocation based on an untrusted frame length. */
typedef struct {
    uint8_t header[4], packet[MESHVPN_VPN_MTU];
    size_t header_used, used, length;
} meshvpn_vpn_decoder_t;
typedef bool (*meshvpn_vpn_packet_fn)(void *, const uint8_t *, size_t);
bool meshvpn_vpn_decode(meshvpn_vpn_decoder_t *, const uint8_t *, size_t,
                        meshvpn_vpn_packet_fn, void *);
bool meshvpn_vpn_ipv4_valid(const uint8_t *, size_t);
void meshvpn_vpn_frame_header(uint8_t out[4], size_t length);
/* Numeric IPv4:port only in the socket MVP; no bootstrap DNS ambiguity. */
bool meshvpn_vpn_endpoint(const char *, uint8_t address[4], uint16_t *port);
/* Clamp an existing SYN MSS option. Does not insert options or change length. */
bool meshvpn_vpn_clamp_mss(uint8_t *, size_t);
