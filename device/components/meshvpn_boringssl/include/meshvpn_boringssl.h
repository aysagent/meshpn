#pragma once

#include "meshvpn_config.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Apply boring-tls ClientHello profile fields to esp_tls_cfg (mbedTLS presets). */
esp_err_t meshvpn_boringssl_apply_profile(const meshvpn_vpn_config_t *cfg, void *tls_cfg);

#ifdef __cplusplus
}
#endif
