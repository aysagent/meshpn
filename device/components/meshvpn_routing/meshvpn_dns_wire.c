#include "meshvpn_dns_wire.h"
#include <string.h>

static uint32_t read32(const uint8_t *p)
{ return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | (p[2] << 8) | p[3]; }

uint32_t meshvpn_dns_age_ttls(uint8_t *p, size_t len, uint32_t elapsed)
{
    meshvpn_dns_question_t q;
    if (!meshvpn_dns_question(p, len, &q) || (p[3] & 15) || (p[2] & 2) ||
        (!p[6] && !p[7])) return 0;
    unsigned count = (p[6] << 8) + p[7] + (p[8] << 8) + p[9] + (p[10] << 8) + p[11];
    if (count > 128) return 0;
    uint32_t minimum = UINT32_MAX;
    size_t off = q.end;
    for (unsigned i = 0; i < count; i++) {
        bool ended = false;
        for (unsigned labels = 0; labels < 128 && off < len; labels++) {
            unsigned n = p[off++];
            if (!n) { ended = true; break; }
            if ((n & 0xc0) == 0xc0) {
                if (off >= len || (((n & 63) << 8) | p[off]) >= off - 1) return 0;
                off++; ended = true; break;
            }
            if (n > 63 || n > len - off) return 0;
            off += n;
        }
        if (!ended || off + 10 > len) return 0;
        unsigned type = (p[off] << 8) | p[off + 1];
        size_t rdlen = (p[off + 8] << 8) | p[off + 9];
        if (rdlen > len - off - 10) return 0;
        if (type != 41) {
            uint32_t ttl = read32(p + off + 4);
            ttl = ttl > elapsed ? ttl - elapsed : 0;
            if (ttl < minimum) minimum = ttl;
            p[off + 4] = ttl >> 24; p[off + 5] = ttl >> 16;
            p[off + 6] = ttl >> 8; p[off + 7] = ttl;
        }
        off += 10 + rdlen;
    }
    return off == len && minimum != UINT32_MAX ? minimum : 0;
}

bool meshvpn_dns_question(const uint8_t *p, size_t len, meshvpn_dns_question_t *q)
{
    if (!p || !q || len < 17 || p[4] != 0 || p[5] != 1 || (p[2] & 0x78)) return false;
    size_t off = 12, pos = 0, end = 0;
    for (unsigned hops = 0; hops < 128 && off < len; hops++) {
        unsigned n = p[off++];
        if ((n & 0xc0) == 0xc0) {
            if (off >= len) return false;
            size_t target = ((n & 63) << 8) | p[off++];
            /* RFC compression points to a prior occurrence; no loops. */
            if (target >= off - 2 || target < 12) return false;
            if (!end) end = off;
            off = target;
            continue;
        }
        if (n > 63 || off + n > len) return false;
        if (!n) {
            if (!end) end = off;
            if (end + 4 > len) return false;
            q->name[pos] = 0;
            q->type = (p[end] << 8) | p[end + 1];
            q->klass = (p[end + 2] << 8) | p[end + 3];
            q->end = end + 4;
            return true;
        }
        if (pos && pos + 1 < sizeof(q->name)) q->name[pos++] = '.';
        if (pos + n >= sizeof(q->name)) return false;
        for (unsigned i = 0; i < n; i++) {
            unsigned c = p[off++];
            if (!c || c == '.') return false;
            q->name[pos++] = c >= 'A' && c <= 'Z' ? c + 32 : c;
        }
    }
    return false;
}

size_t meshvpn_dns_reply(const uint8_t *query, size_t len, uint8_t *out,
                        size_t cap, unsigned rcode, bool truncated, uint32_t ipv4)
{
    meshvpn_dns_question_t q;
    if (!meshvpn_dns_question(query, len, &q)) return 0;
    bool answer = ipv4 && q.type == 1 && q.klass == 1 && !rcode && !truncated;
    if (q.end + (answer ? 16 : 0) > cap) return 0;
    memcpy(out, query, q.end);
    out[2] = 0x80 | (query[2] & 1) | (truncated ? 2 : 0);
    out[3] = 0x80 | (rcode & 15);
    memset(out + 6, 0, 6); /* No stale EDNS/answer counts */
    if (!answer) return q.end;
    out[7] = 1;
    const uint8_t rr[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4};
    memcpy(out + q.end, rr, sizeof(rr));
    memcpy(out + q.end + sizeof(rr), &ipv4, 4);
    return q.end + 16;
}
