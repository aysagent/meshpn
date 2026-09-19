#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MESHVPN_VPN_MTU 1400
/* A browser/phone TCP stack can enqueue a short burst much faster than the
 * outer TCP stream wakes the VPN worker. XIAO has PSRAM, so retain enough
 * packets to absorb that burst instead of dropping it at 16 frames. */
#define MESHVPN_VPN_SLOTS 64
/* No allocation based on an untrusted frame length. */
typedef struct {
    uint8_t header[4], packet[MESHVPN_VPN_MTU];
    size_t header_used, used, length;
    uint32_t completed; /* Tracks frame boundaries, not recv() boundaries. */
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
/* Raw IP transports do not carry checksum-offload metadata. Recalculate all
 * checksums after NAPT/MSS changes before a packet crosses that boundary. */
bool meshvpn_vpn_repair_checksums(uint8_t *, size_t);
/* Normalize an Ethernet IPv4 frame at the final LAN driver boundary. Returns
 * false for non-IPv4/malformed frames; changed reports checksum bytes repaired. */
bool meshvpn_vpn_repair_ethernet_checksums(uint8_t *, size_t, bool *changed);
