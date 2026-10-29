#pragma once
#include "esp_err.h"
#include "profile_model.h"
esp_err_t meshvpn_vpn_profile_slot(unsigned slot, meshpn_tls_profile_t *out);
esp_err_t meshvpn_vpn_profile_load(const char *id, meshpn_tls_profile_t *out);
bool meshvpn_vpn_profile_exists(const char *id);
/* Caller serializes mutations on the HTTP task; never call from PSRAM worker. */
esp_err_t meshvpn_vpn_profile_save(const meshpn_tls_profile_t *p);
esp_err_t meshvpn_vpn_profile_delete(const char *id);
