#include <assert.h>
#include <stdbool.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "meshvpn_hosted_wifi_init.h"

static uint64_t decode(const ProtobufCMessageUnknownField *f)
{
    uint64_t v = 0;
    assert(f->wire_type == PROTOBUF_C_WIRE_TYPE_VARINT && f->len <= 10);
    for (size_t i = 0; i < f->len; i++) {
        assert(!!(f->data[i] & 0x80) == (i + 1 < f->len));
        v |= (uint64_t)(f->data[i] & 0x7f) << (7 * i);
    }
    return v;
}

static void check(const int32_t values[4], bool standard)
{
    WifiInitConfig cfg = WIFI_INIT_CONFIG__INIT;
    meshvpn_hosted_wifi_init_extra_t extra;
    cfg.static_rx_buf_num = 16;
    cfg.ampdu_tx_enable = 1;
    cfg.feature_caps = UINT64_C(0x100000003);
    cfg.magic = 0x1f2f3f4f;
    meshvpn_hosted_wifi_init_extend(&cfg, &extra, values);
    RpcReqWifiInit init = RPC__REQ__WIFI_INIT__INIT;
    init.cfg = &cfg;
    Rpc request = RPC__INIT;
    request.msg_type = RPC_TYPE__Req;
    request.msg_id = RPC_ID__Req_WifiInit;
    request.uid = 123;
    request.payload_case = (Rpc__PayloadCase)request.msg_id;
    request.req_wifi_init = &init;
    size_t size = rpc__get_packed_size(&request);
    uint8_t *wire = malloc(size);
    assert(wire && rpc__pack(&request, wire) == size);
    /* New fields are the standard upstream wire tags, with no custom wrapper. */
    const uint8_t expected[] = {0xa8,1,0, 0xb0,1,5, 0xb8,1,3, 0xc0,1,0};
    if (standard) assert(size >= sizeof(expected) && !memcmp(wire + size - sizeof(expected), expected, sizeof(expected)));
    /* The old peer can still decode known fields and safely free the extras. */
    Rpc *old = rpc__unpack(NULL, size, wire);
    assert(old && old->uid == 123 && old->req_wifi_init && old->req_wifi_init->cfg);
    WifiInitConfig *out = old->req_wifi_init->cfg;
    assert(out->magic == cfg.magic && out->static_rx_buf_num == 16 && out->ampdu_tx_enable == 1);
    assert(out->feature_caps == cfg.feature_caps && out->base.n_unknown_fields == 4);
    for (unsigned i = 0; i < 4; i++) {
        assert(out->base.unknown_fields[i].tag == 21 + i);
        assert(decode(&out->base.unknown_fields[i]) == (uint64_t)(int64_t)values[i]);
    }
    rpc__free_unpacked(old, NULL);
    free(wire);
}

int main(void)
{
    for (unsigned i = 0; i < 100; i++) {
        check((int32_t[]){0,5,3,0}, true);
        check((int32_t[]){1,128,16384,1}, false);
        check((int32_t[]){INT32_MAX,INT32_MIN,-1,0}, false);
    }
    puts("Hosted Wi-Fi init upstream fields 21..24, full RPC packing and legacy decode/free: PASS");
}
