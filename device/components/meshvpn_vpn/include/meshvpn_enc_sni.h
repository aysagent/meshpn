#pragma once

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t meshvpn_enc_sni_build_relay_hostname(const uint8_t *psk, size_t psk_len,
                                               const char *origin_sni, uint16_t port,
                                               const char *public_name,
                                               char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif
