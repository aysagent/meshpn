#pragma once

#include "esp_err.h"
#include "esp_tls.h"

/* Test transport: ordinary ESP-TLS 1.2 followed by the raw IPv4 framing used
 * by the tcp transport. Certificate verification is intentionally disabled in
 * this first version; do not expose it to an untrusted exit. */
esp_err_t meshvpn_vpn_tls_connect(const char *server, const char *tls_server_name,
                                  const char *ifname, esp_tls_t **out_tls, int *out_fd);
