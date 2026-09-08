#pragma once
#include "esp_err.h"
esp_err_t meshvpn_web_tls_init(void);
const char *meshvpn_web_tls_cert(void);
const char *meshvpn_web_tls_key(void);
const char *meshvpn_web_tls_fingerprint(void);
/* Persist validated pair atomically; takes effect after reboot. */
esp_err_t meshvpn_web_tls_import(const char *cert, const char *key);
