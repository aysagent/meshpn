#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t meshvpn_tls_ch_replace_sni(const uint8_t *tcp_buf, size_t tcp_len,
                                     const char *new_hostname,
                                     uint8_t **out_buf, size_t *out_len,
                                     char *origin_sni, size_t origin_cap);

#ifdef __cplusplus
}
#endif
