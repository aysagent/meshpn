/*
 * TLS + HTTP/2 tunnel implementation placeholder.
 * Enable CONFIG_MESHVPN_VPN_ENABLE and link nghttp2 + esp-tls to activate.
 */

#include "meshvpn_vpn_protocol.h"

#include "esp_err.h"
#include "esp_log.h"
#include "sdkconfig.h"

static const char *TAG = "meshvpn_vpn_tls";

#if defined(CONFIG_MESHVPN_VPN_ENABLE) && CONFIG_MESHVPN_VPN_ENABLE

esp_err_t meshvpn_vpn_tls_connect(const char *server, const char *tls_server_name)
{
    ESP_LOGW(TAG, "TLS connect to %s (sni=%s) — implement nghttp2 + exporter", server, tls_server_name);
    return ESP_ERR_NOT_SUPPORTED;
}

#else

esp_err_t meshvpn_vpn_tls_connect(const char *server, const char *tls_server_name)
{
    (void)TAG;
    (void)server;
    (void)tls_server_name;
    return ESP_ERR_NOT_SUPPORTED;
}

#endif
