#pragma once

#include "esp_err.h"
#include "esp_tls.h"

/* Ordinary TLS 1.2 with required CA, name and validity verification, followed
 * by the raw IPv4 framing used by tcp. No client authentication or mimicry. */
typedef struct {
    int sdk_error, mbedtls_error, verify_flags;
    char reason[48];
} meshvpn_vpn_tls_diag_t;
void meshvpn_vpn_tls_get_diag(meshvpn_vpn_tls_diag_t *out);
esp_err_t meshvpn_vpn_tls_connect(const char *server, const char *tls_server_name,
                                  const char *ifname, esp_tls_t **out_tls, int *out_fd);
