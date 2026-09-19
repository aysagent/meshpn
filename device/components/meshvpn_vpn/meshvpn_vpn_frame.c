#include "meshvpn_vpn_frame.h"
#include <string.h>

static unsigned be16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }
static void put16(uint8_t *p, unsigned v) { p[0] = v >> 8; p[1] = v; }
static uint32_t checksum_add(uint32_t sum, const uint8_t *p, size_t n)
{
    while (n >= 2) { sum += ((unsigned)p[0] << 8) | p[1]; p += 2; n -= 2; }
    if (n) sum += (unsigned)p[0] << 8;
    return sum;
}
static uint16_t checksum_finish(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}
bool meshvpn_vpn_ipv4_valid(const uint8_t *p, size_t n)
{
    if (!p || n < 20 || (p[0] >> 4) != 4) return false;
    size_t h = (p[0] & 15) * 4;
    if (h < 20 || h > n || be16(p + 2) != n) return false;
    if (be16(p + 6) & 0x3fff) return true; /* Reassemble before inspecting L4. */
    if (p[9] == 6) {
        if (n < h + 20) return false;
        size_t th = (p[h + 12] >> 4) * 4;
        return th >= 20 && th <= n - h;
    }
    if (p[9] == 17) return n >= h + 8 && be16(p + h + 4) == n - h;
    if (p[9] == 1) return n >= h + 8;
    return false; /* MVP NAPT supports TCP/UDP/ICMP, not arbitrary IP protocols. */
}
void meshvpn_vpn_frame_header(uint8_t out[4], size_t n)
{
    out[0] = (uint8_t)(n >> 24); out[1] = (uint8_t)(n >> 16);
    out[2] = (uint8_t)(n >> 8); out[3] = (uint8_t)n;
}
bool meshvpn_vpn_decode(meshvpn_vpn_decoder_t *d, const uint8_t *p, size_t n,
                        meshvpn_vpn_packet_fn emit, void *ctx)
{
    while (n) {
        if (d->header_used < 4) {
            d->header[d->header_used++] = *p++; n--;
            if (d->header_used != 4) continue;
            d->length = ((uint32_t)d->header[0] << 24) | ((uint32_t)d->header[1] << 16) |
                        ((uint32_t)d->header[2] << 8) | d->header[3];
            if (d->length < 20 || d->length > MESHVPN_VPN_MTU) return false;
        }
        size_t take = d->length - d->used;
        if (take > n) take = n;
        memcpy(d->packet + d->used, p, take);
        d->used += take; p += take; n -= take;
        if (d->used == d->length) {
            if (!meshvpn_vpn_ipv4_valid(d->packet, d->length) ||
                !emit(ctx, d->packet, d->length)) return false;
            d->completed++;
            d->used = d->length = d->header_used = 0;
        }
    }
    return true;
}
bool meshvpn_vpn_endpoint(const char *s, uint8_t address[4], uint16_t *port)
{
    if (!s) return false;
    for (unsigned i = 0; i < 5; i++) {
        unsigned value = 0, digits = 0;
        const unsigned limit = i < 4 ? 255 : 65535;
        while (*s >= '0' && *s <= '9') {
            value = value * 10 + (unsigned)(*s++ - '0');
            if (++digits > 5 || value > limit) return false;
        }
        if (!digits) return false;
        if (i < 4) {
            address[i] = value;
            if (*s++ != (i == 3 ? ':' : '.')) return false;
        } else {
            if (*s || !value) return false;
            *port = value;
        }
    }
    return address[0] != 0 && address[0] != 127 && address[0] < 224 &&
           !(address[0] == 169 && address[1] == 254);
}
bool meshvpn_vpn_clamp_mss(uint8_t *p, size_t n)
{
    if (!meshvpn_vpn_ipv4_valid(p, n)) return false;
    if (p[9] != 6 || (be16(p + 6) & 0x3fff)) return true;
    size_t h = (p[0] & 15) * 4;
    if (!(p[h + 13] & 2)) return true;
    size_t end = h + (p[h + 12] >> 4) * 4;
    for (size_t i = h + 20; i < end;) {
        unsigned kind = p[i];
        if (!kind) break;
        if (kind == 1) { i++; continue; }
        if (i + 2 > end || p[i + 1] < 2 || i + p[i + 1] > end) return false;
        if (kind == 2 && p[i + 1] == 4) {
            unsigned old = be16(p + i + 2), mss = MESHVPN_VPN_MTU - 40;
            if (old > mss) {
                unsigned old_word = old, new_word = mss;
                /* NOPs can place MSS on an odd checksum byte boundary. */
                if ((i + 2 - h) & 1) {
                    old_word = ((old & 255) << 8) | (old >> 8);
                    new_word = ((mss & 255) << 8) | (mss >> 8);
                }
                unsigned sum = (~be16(p + h + 16) & 0xffff) + (~old_word & 0xffff) + new_word;
                sum = (sum & 0xffff) + (sum >> 16);
                sum = (sum & 0xffff) + (sum >> 16);
                unsigned c = ~sum & 0xffff;
                p[h + 16] = c >> 8; p[h + 17] = c;
                p[i + 2] = mss >> 8; p[i + 3] = mss;
            }
        }
        i += p[i + 1];
    }
    return true;
}
bool meshvpn_vpn_repair_checksums(uint8_t *p, size_t n)
{
    if (!meshvpn_vpn_ipv4_valid(p, n)) return false;
    size_t h = (p[0] & 15) * 4;
    put16(p + 10, 0);
    put16(p + 10, checksum_finish(checksum_add(0, p, h)));
    /* A non-first fragment has no L4 header, while the first fragment lacks
     * the complete segment. Reassembly in the VPN ingress normally prevents
     * this path; preserve its existing transport checksum if it does occur. */
    if (be16(p + 6) & 0x3fff) return true;
    size_t l4_len = n - h, checksum_offset;
    uint32_t sum = 0;
    if (p[9] == 6) checksum_offset = 16;
    else if (p[9] == 17) checksum_offset = 6;
    else if (p[9] == 1) {
        checksum_offset = 2;
        put16(p + h + checksum_offset, 0);
        put16(p + h + checksum_offset, checksum_finish(checksum_add(0, p + h, l4_len)));
        return true;
    } else return false;
    put16(p + h + checksum_offset, 0);
    sum = checksum_add(sum, p + 12, 8);
    sum += p[9];
    sum += l4_len;
    sum = checksum_add(sum, p + h, l4_len);
    uint16_t checksum = checksum_finish(sum);
    if (p[9] == 17 && checksum == 0) checksum = 0xffff;
    put16(p + h + checksum_offset, checksum);
    return true;
}
