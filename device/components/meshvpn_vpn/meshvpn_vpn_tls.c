#include "meshvpn_vpn_internal.h"
#include "meshvpn_tls_exporter.h"
#include "meshvpn_vpn_protocol.h"
#include "meshvpn_storage.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_tls.h"

static const char *TAG = "meshvpn_vpn_tls";

static esp_err_t parse_host_port(const char *server, char *host, size_t host_len, uint16_t *port)
{
    const char *colon = strrchr(server, ':');
    if (!colon) {
        strncpy(host, server, host_len - 1);
        *port = 443;
        return ESP_OK;
    }
    size_t hlen = (size_t)(colon - server);
    if (hlen >= host_len) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(host, server, hlen);
    host[hlen] = '\0';
    *port = (uint16_t)atoi(colon + 1);
    if (*port == 0) {
        *port = 443;
    }
    return ESP_OK;
}

esp_err_t meshvpn_vpn_tls_handshake(const meshvpn_vpn_config_t *cfg, int *out_sock, esp_tls_t **out_tls,
                                    char *last_error, size_t last_error_len)
{
    char host[128];
    uint16_t port = 443;
    if (parse_host_port(cfg->server, host, sizeof(host), &port) != ESP_OK) {
        snprintf(last_error, last_error_len, "bad server");
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t ca_pem[8192];
    size_t ca_len = 0;
    if (!meshvpn_storage_has_ca()) {
        snprintf(last_error, last_error_len, "missing ca.pem");
        return ESP_ERR_NOT_FOUND;
    }
    meshvpn_storage_read_file(MESHVPN_STORAGE_CA_PATH, ca_pem, sizeof(ca_pem) - 1, &ca_len);
    ca_pem[ca_len] = '\0';

    const char *sni = cfg->tls_server_name[0] ? cfg->tls_server_name : host;

    esp_tls_cfg_t tls_cfg = {
        .cacert_buf = (const unsigned char *)ca_pem,
        .cacert_bytes = ca_len + 1,
        .common_name = sni,
        .alpn_protos = cfg->http_vers == 1 ? (const char *[]) { "http/1.1", NULL }
                                          : (const char *[]) { "h2", "http/1.1", NULL },
    };

    esp_tls_t *tls = esp_tls_init();
    if (!tls) {
        snprintf(last_error, last_error_len, "esp_tls_init");
        return ESP_ERR_NO_MEM;
    }

    if (esp_tls_conn_new_sync(sni, strlen(sni), port, &tls_cfg, tls) != 1) {
        esp_tls_conn_destroy(tls);
        snprintf(last_error, last_error_len, "TLS handshake failed");
        return ESP_FAIL;
    }

    int fd = -1;
    if (esp_tls_get_conn_sockfd(tls, &fd) != ESP_OK || fd < 0) {
        esp_tls_conn_destroy(tls);
        snprintf(last_error, last_error_len, "no tls fd");
        return ESP_FAIL;
    }

    *out_sock = fd;
    if (out_tls) {
        *out_tls = tls;
    } else {
        esp_tls_conn_destroy(tls);
    }

    ESP_LOGI(TAG, "TLS OK sni=%s", sni);
    return ESP_OK;
}

esp_err_t meshvpn_vpn_tls_connect(const meshvpn_vpn_config_t *cfg, int sock,
                                  char *last_error, size_t last_error_len)
{
    (void)sock;
    int fd = -1;
    return meshvpn_vpn_tls_handshake(cfg, &fd, NULL, last_error, last_error_len);
}
