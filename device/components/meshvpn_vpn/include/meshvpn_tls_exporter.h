#pragma once

#include <stddef.h>
#include "esp_err.h"
#include "esp_tls.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t meshvpn_tls_exporter_from_esp_tls(esp_tls_t *tls, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif
