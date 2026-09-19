#include "meshvpn_vpn_stream.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned seen;
static bool emit(void *ctx, const uint8_t *p, size_t n)
{ (void)ctx; assert(n == 100 && p[9] == 17); seen++; return true; }
static bool reject(void *ctx, const uint8_t *p, size_t n)
{ (void)ctx; (void)p; (void)n; return false; }
int main(void)
{
    uint8_t frame[104] = {0}, chunk[104];
    meshvpn_vpn_frame_header(frame, 100);
    frame[4] = 0x45; frame[7] = 100; frame[13] = 17; frame[29] = 80;
    meshvpn_vpn_rx_stream_t rx = {0};
    assert(meshvpn_vpn_rx_feed(&rx, frame, 1, 0, emit, NULL));
    memcpy(chunk, frame + 1, 103); chunk[103] = frame[0];
    /* Every recv completes one valid frame and starts a new header. The old
     * worker falsely timed out after 5s, despite continuous complete packets. */
    for (unsigned i = 1; i <= 1000; i++) {
        uint64_t now = i * 50000ULL;
        assert(meshvpn_vpn_rx_feed(&rx, chunk, sizeof(chunk), now, emit, NULL));
        assert(rx.partial_active && rx.partial_since == now);
        assert(!meshvpn_vpn_rx_expired(&rx, now));
    }
    assert(seen == 1000);
    assert(meshvpn_vpn_rx_expired(&rx, 55000001)); /* Real stall still expires. */
    memset(&rx, 0, sizeof(rx));
    assert(meshvpn_vpn_rx_feed(&rx, frame, 1, 0, emit, NULL));
    assert(meshvpn_vpn_rx_feed(&rx, frame + 1, 1, 4000000, emit, NULL));
    assert(rx.partial_since == 0 && meshvpn_vpn_rx_expired(&rx, 5000001));
    /* Progress within the SAME frame does not keep it alive indefinitely. */
    for (unsigned split = 0; split <= sizeof(frame); split++) {
        memset(&rx, 0, sizeof(rx));
        assert(meshvpn_vpn_rx_feed(&rx, frame, split, 100, emit, NULL));
        assert(meshvpn_vpn_rx_feed(&rx, frame + split, sizeof(frame) - split, 200, emit, NULL));
        assert(!rx.partial_active && !meshvpn_vpn_rx_expired(&rx, 99999999));
    }
    memset(&rx, 0, sizeof(rx)); rx.decoder.completed = UINT32_MAX;
    assert(meshvpn_vpn_rx_feed(&rx, frame, 1, 10, emit, NULL));
    assert(meshvpn_vpn_rx_feed(&rx, chunk, sizeof(chunk), 20, emit, NULL));
    assert(rx.decoder.completed == 0 && rx.partial_since == 20);
    memset(&rx, 0, sizeof(rx));
    assert(!meshvpn_vpn_rx_feed(&rx, frame, sizeof(frame), 0, reject, NULL));
    memset(&rx, 0, sizeof(rx)); uint8_t invalid[4] = {0};
    assert(!meshvpn_vpn_rx_feed(&rx, invalid, 4, 0, emit, NULL));

    meshvpn_vpn_tx_batch_t batch = {0};
    for (unsigned i = 0; i < 8; i++) assert(meshvpn_vpn_tx_append(&batch, frame + 4, 100));
    assert(!meshvpn_vpn_tx_append(&batch, frame + 4, 100));
    assert(batch.length == 8 * sizeof(frame));
    for (unsigned i = 0; i < 8; i++) assert(!memcmp(batch.data + i * sizeof(frame), frame, sizeof(frame)));
    for (size_t split = 0; split <= batch.length; split++) {
        meshvpn_vpn_tx_batch_t b = batch;
        unsigned packets, packets2; size_t bytes, bytes2;
        assert(meshvpn_vpn_tx_advance(&b, split, &packets, &bytes));
        assert(packets == split / sizeof(frame) && bytes == packets * 100);
        assert(meshvpn_vpn_tx_advance(&b, b.length - b.used, &packets2, &bytes2));
        assert(packets + packets2 == 8 && bytes + bytes2 == 800 && b.completed == 8);
        assert(meshvpn_vpn_tx_advance(&b, 0, &packets, &bytes) && !packets && !bytes);
        assert(!meshvpn_vpn_tx_advance(&b, 1, &packets, &bytes));
    }
    unsigned packets; size_t bytes;
    assert(meshvpn_vpn_tx_advance(&batch, 105, &packets, &bytes));
    assert(packets == 1 && bytes == 100 && batch.count - batch.completed == 7);
    assert(!meshvpn_vpn_tx_append(&batch, frame + 4, 100));
    /* A disconnect counts the remaining 7, not all 8 or only 1 batch. */
    puts("Socket streams: 50s continuous partial-boundary regression, real stalls, splits, wrap, bounded batches and partial-send accounting passed");
}
