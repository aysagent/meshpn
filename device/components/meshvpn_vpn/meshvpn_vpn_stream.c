#include "meshvpn_vpn_stream.h"
#include <string.h>

bool meshvpn_vpn_rx_feed(meshvpn_vpn_rx_stream_t *s, const uint8_t *data, size_t len,
                        uint64_t now, meshvpn_vpn_packet_fn emit, void *arg)
{
    uint32_t completed = s->decoder.completed;
    if (!meshvpn_vpn_decode(&s->decoder, data, len, emit, arg)) return false;
    if (!s->decoder.header_used) s->partial_active = false;
    else if (!s->partial_active || s->decoder.completed != completed) {
        /* The previous partial frame completed, even if this recv also began
         * a new frame. A new frame must not inherit the old frame's deadline. */
        s->partial_since = now;
        s->partial_active = true;
    }
    return true;
}
bool meshvpn_vpn_rx_expired(const meshvpn_vpn_rx_stream_t *s, uint64_t now)
{
    return s->partial_active && now - s->partial_since > MESHVPN_VPN_STREAM_TIMEOUT_US;
}
bool meshvpn_vpn_tx_append(meshvpn_vpn_tx_batch_t *b, const uint8_t *p, size_t len)
{
    if (b->used || b->count == MESHVPN_VPN_BATCH_FRAMES || len < 20 || len > MESHVPN_VPN_MTU)
        return false;
    meshvpn_vpn_frame_header(b->data + b->length, len);
    memcpy(b->data + b->length + 4, p, len);
    b->length += len + 4;
    b->ends[b->count++] = b->length;
    return true;
}
bool meshvpn_vpn_tx_advance(meshvpn_vpn_tx_batch_t *b, size_t sent, unsigned *packets, size_t *bytes)
{
    *packets = 0; *bytes = 0;
    if (sent > b->length - b->used) return false;
    b->used += sent;
    while (b->completed < b->count && b->ends[b->completed] <= b->used) {
        unsigned i = b->completed++;
        *bytes += b->ends[i] - (i ? b->ends[i - 1] : 0) - 4;
        (*packets)++;
    }
    return true;
}
