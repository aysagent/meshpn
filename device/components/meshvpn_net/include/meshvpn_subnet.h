#pragma once
#include <stdbool.h>
#include <stdint.h>

/* All arguments are host-order IPv4 values with contiguous subnet masks. */
static inline bool meshvpn_subnets_overlap(uint32_t a, uint32_t amask, uint32_t b, uint32_t bmask)
{
    uint32_t common = amask & bmask;
    return (a & common) == (b & common);
}

/* Select a private /24 excluding both uplink and the other downstream LAN. */
static inline bool meshvpn_pick_lan_ip(uint32_t wan, uint32_t wanmask,
                                      uint32_t other, uint32_t othermask, uint32_t *ip)
{
    if (!ip) return false;
    const uint32_t prefixes[] = {0xc0a80000u, 0x0acb0000u, 0xac1f0000u};
    for (unsigned family = 0; family < 3; family++) {
        for (unsigned subnet = 7; subnet <= 254; subnet++) {
            uint32_t candidate = prefixes[family] | (subnet << 8) | 1;
            if (meshvpn_subnets_overlap(candidate, 0xffffff00u, wan, wanmask)) continue;
            if (other && meshvpn_subnets_overlap(candidate, 0xffffff00u, other, othermask)) continue;
            *ip = candidate;
            return true;
        }
    }
    return false;
}
