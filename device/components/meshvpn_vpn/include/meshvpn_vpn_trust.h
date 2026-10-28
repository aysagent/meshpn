#pragma once
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#define MESHVPN_VPN_CA_MAX 8192
/* Caller frees the allocated, NUL-terminated PEM. No trust defaults/fallback. */
esp_err_t meshvpn_vpn_ca_load(char **pem);
esp_err_t meshvpn_vpn_ca_save(const char *pem);
bool meshvpn_vpn_ca_configured(void);
bool meshvpn_vpn_ca_valid(const char *pem);
bool meshvpn_vpn_tls_name_valid(const char *name);
