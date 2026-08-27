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

static bool host_is_ipv4(const char *host)
{
    uint8_t a, b, c, d;
    return sscanf(host, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) == 4;
}

/** clean-vpn: verify CN + HTTP :authority; TCP still goes to host:port. */
static void resolve_verify_name(const meshvpn_vpn_config_t *cfg, const char *tcp_host, char *verify, size_t verify_len)
{
    if (cfg->tls_server_name[0]) {
        strncpy(verify, cfg->tls_server_name, verify_len - 1);
        verify[verify_len - 1] = '\0';
        return;
    }
    if (host_is_ipv4(tcp_host)) {
        strncpy(verify, "clean-vpn", verify_len - 1);
    } else {
        strncpy(verify, tcp_host, verify_len - 1);
    }
    verify[verify_len - 1] = '\0';
}

void meshvpn_vpn_tls_http_authority(const meshvpn_vpn_config_t *cfg, char *out, size_t out_len)
{
    char host[128];
    uint16_t port = 443;
    if (parse_host_port(cfg->server, host, sizeof(host), &port) != ESP_OK) {
        strncpy(out, "clean-vpn", out_len - 1);
        out[out_len - 1] = '\0';
        return;
    }
    resolve_verify_name(cfg, host, out, out_len);
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

    char verify_name[128];
    resolve_verify_name(cfg, host, verify_name, sizeof(verify_name));

    esp_tls_cfg_t tls_cfg = {
        .cacert_buf = (const unsigned char *)ca_pem,
        .cacert_bytes = ca_len + 1,
        .common_name = verify_name,
        .tls_version = ESP_TLS_VER_TLS_1_3,
        .alpn_protos = cfg->http_vers == 1 ? (const char *[]) { "http/1.1", NULL }
                                          : (const char *[]) { "h2", "http/1.1", NULL },
    };

    esp_tls_t *tls = esp_tls_init();
    if (!tls) {
        snprintf(last_error, last_error_len, "esp_tls_init");
        return ESP_ERR_NO_MEM;
    }

    if (esp_tls_conn_new_sync(host, strlen(host), port, &tls_cfg, tls) != 1) {
        int esp_tls_err = 0;
        esp_tls_error_handle_t err_hdl = NULL;
        esp_tls_get_error_handle(tls, &err_hdl);
        if (err_hdl) {
            esp_tls_err = err_hdl->esp_tls_error_code;
        }
        esp_tls_conn_destroy(tls);
        snprintf(last_error, last_error_len, "TLS to %s:%u failed (0x%x)", host, port, esp_tls_err);
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

    ESP_LOGI(TAG, "TLS OK host=%s verify=%s", host, verify_name);
    return ESP_OK;
}

esp_err_t meshvpn_vpn_tls_connect(const meshvpn_vpn_config_t *cfg, int sock,
                                  char *last_error, size_t last_error_len)
{
    (void)sock;
    int fd = -1;
    return meshvpn_vpn_tls_handshake(cfg, &fd, NULL, last_error, last_error_len);
}
