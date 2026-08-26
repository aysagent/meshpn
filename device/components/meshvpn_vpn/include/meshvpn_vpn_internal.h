#pragma once

#include "esp_err.h"
#include "meshvpn_config.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t meshvpn_vpn_bearer_compute(const uint8_t *psk, size_t psk_len,
                                     const uint8_t *exporter, size_t exporter_len,
                                     char *token_hex, size_t token_hex_len);

esp_err_t meshvpn_vpn_tls_connect(const meshvpn_vpn_config_t *cfg, int sock,
                                  char *last_error, size_t last_error_len);

#include "esp_tls.h"

esp_err_t meshvpn_vpn_tls_handshake(const meshvpn_vpn_config_t *cfg, int *out_sock, esp_tls_t **out_tls,
                                    char *last_error, size_t last_error_len);

esp_err_t meshvpn_vpn_h2_open(int tls_sock, const meshvpn_vpn_config_t *cfg,
                              const char *bearer_token,
                              int *out_stream_id,
                              char *last_error, size_t last_error_len);

esp_err_t meshvpn_vpn_framing_write(int fd, const uint8_t *pkt, uint16_t len);
esp_err_t meshvpn_vpn_framing_read(int fd, uint8_t *pkt, uint16_t maxlen, uint16_t *out_len);

esp_err_t meshvpn_vpn_transparent_mux_connect(const meshvpn_vpn_config_t *cfg, int *out_sock,
                                              char *last_error, size_t last_error_len);

esp_err_t meshvpn_vpn_transparent_intercept_start(const meshvpn_vpn_config_t *cfg);
void meshvpn_vpn_transparent_intercept_stop(void);

esp_err_t meshvpn_vpn_boring_connect(const meshvpn_vpn_config_t *cfg, int *out_sock, esp_tls_t **out_tls,
                                     char *last_error, size_t last_error_len);

#ifdef __cplusplus
}
#endif
