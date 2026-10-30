#pragma once

#include <stdint.h>
#include "esp_hosted_rpc.pb-c.h"

/* ESP-Hosted 1.4.7's schema ends at field 20. C6 2.12.1 consumes 21..24
 * unconditionally, replacing its defaults with zero when they are absent.
 * Use protobuf-c's supported unknown-field encoding to extend only this
 * message, retaining the pinned RPC ABI. Old peers safely ignore these fields.
 * Field numbers: upstream f45f8ab865a03e409bfe3c22198b0c27727b40d5,
 * common/proto/esp_hosted_rpc.proto, wifi_init_config.
 * Storage belongs to process_rpc_tx_msg and must outlive size/pack/send. The
 * pinned RPC_FREE_BUFFS frees its explicit allocation list, not this storage. */
typedef struct {
    ProtobufCMessageUnknownField fields[4];
    uint8_t data[4][10];
} meshvpn_hosted_wifi_init_extra_t;

static inline void meshvpn_hosted_wifi_init_extend(WifiInitConfig *cfg,
        meshvpn_hosted_wifi_init_extra_t *extra, const int32_t values[4])
{
    for (unsigned i = 0; i < 4; i++) {
        /* int32 negative values use a sign-extended ten-byte varint. */
        uint64_t value = (uint64_t)(int64_t)values[i];
        size_t n = 0;
        do {
            uint8_t byte = value & 0x7f;
            value >>= 7;
            extra->data[i][n++] = byte | (value ? 0x80 : 0);
        } while (value);
        extra->fields[i] = (ProtobufCMessageUnknownField){
            .tag = 21 + i, .wire_type = PROTOBUF_C_WIRE_TYPE_VARINT,
            .len = n, .data = extra->data[i],
        };
    }
    cfg->base.n_unknown_fields = 4;
    cfg->base.unknown_fields = extra->fields;
}
