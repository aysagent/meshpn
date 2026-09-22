#include "meshvpn_vpn_tls.h"

#include "sdkconfig.h"
#include "meshvpn_vpn_frame.h"
#include "esp_log.h"
#include "esp_tls_errors.h"
#include <string.h>
#include <stdio.h>
#include <net/if.h>

static const char *TAG = "meshvpn_vpn_tls";

#if !CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
#error "Raw TLS transport requires CONFIG_MBEDTLS_SSL_PROTO_TLS1_3=y"
#endif

esp_err_t meshvpn_vpn_tls_connect(const char *server, const char *tls_server_name,
                                  const char *ifname, esp_tls_t **out_tls, int *out_fd)
{
    if (!server || !ifname || !out_tls || !out_fd) return ESP_ERR_INVALID_ARG;
    uint8_t address[4]; uint16_t port;
    if (!meshvpn_vpn_endpoint(server, address, &port)) return ESP_ERR_INVALID_ARG;
    char host[16];
    snprintf(host, sizeof(host), "%u.%u.%u.%u", address[0], address[1], address[2], address[3]);
    struct ifreq iface = {0};
    strlcpy(iface.ifr_name, ifname, sizeof(iface.ifr_name));
    esp_tls_t *tls = esp_tls_init();
    if (!tls) return ESP_ERR_NO_MEM;
    esp_tls_cfg_t cfg = {0};
    cfg.if_name = &iface;
    cfg.timeout_ms = 5000;
    cfg.tls_version = ESP_TLS_VER_TLS_1_3;
    cfg.skip_common_name = true;
    cfg.common_name = (tls_server_name && tls_server_name[0]) ? tls_server_name : NULL;
    /* This is a deliberately simple test transport. The raw TLS exit uses a
     * generated/self-signed certificate, so verification will be added as a
     * separate CA configuration before this mode is used outside a lab. */
    int result = esp_tls_conn_new_sync(host, strlen(host), port, &cfg, tls);
    if (result != 1 || esp_tls_get_conn_sockfd(tls, out_fd) != ESP_OK) {
        ESP_LOGW(TAG, "TLS connect to %s failed (%d)", server, result);
        esp_tls_conn_destroy(tls);
        return ESP_FAIL;
    }
    *out_tls = tls;
    ESP_LOGI(TAG, "raw TLS 1.3 connected to %s via %s (certificate verification disabled)", server, ifname);
    return ESP_OK;
}
