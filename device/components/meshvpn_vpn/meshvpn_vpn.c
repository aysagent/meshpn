/*
 * meshvpn_vpn — clean-vpn TLS client (phase 2).
 *
 * Protocol (--type=tls):
 *   TLS 1.3 + exporter + Bearer HMAC + HTTP/2 POST /clean-vpn
 *   Stream framing: [uint32 BE len][IPv4 packet]
 *
 * This module provides the API surface; full TLS/HTTP2 implementation
 * is gated behind CONFIG_MESHVPN_VPN_ENABLE.
 */

#include "meshvpn_vpn.h"

#include <string.h>

#include "esp_log.h"
#include "sdkconfig.h"

static const char *TAG = "meshvpn_vpn";

static bool s_enabled;
static bool s_connected;
static char s_server[128];

esp_err_t meshvpn_vpn_init(void)
{
#ifdef CONFIG_MESHVPN_VPN_ENABLE
    ESP_LOGI(TAG, "VPN module init (enabled)");
#else
    ESP_LOGI(TAG, "VPN module init (stub, enable via CONFIG_MESHVPN_VPN_ENABLE)");
#endif
    return ESP_OK;
}

esp_err_t meshvpn_vpn_start(const meshvpn_vpn_config_t *cfg)
{
    s_enabled = cfg->enabled;
    strncpy(s_server, cfg->server, sizeof(s_server) - 1);

#if defined(CONFIG_MESHVPN_VPN_ENABLE) && CONFIG_MESHVPN_VPN_ENABLE
    ESP_LOGW(TAG, "VPN start to %s — TLS/HTTP2 stack not yet linked", cfg->server);
    s_connected = false;
    return ESP_ERR_NOT_SUPPORTED;
#else
    if (cfg->enabled) {
        ESP_LOGW(TAG, "VPN requested but CONFIG_MESHVPN_VPN_ENABLE is off");
    }
    s_connected = false;
    return ESP_OK;
#endif
}

esp_err_t meshvpn_vpn_stop(void)
{
    s_connected = false;
    s_enabled = false;
    return ESP_OK;
}

bool meshvpn_vpn_is_connected(void)
{
    return s_connected;
}

esp_err_t meshvpn_vpn_send_ipv4(const uint8_t *pkt, uint16_t len)
{
    if (!s_connected) {
        return ESP_ERR_INVALID_STATE;
    }
    (void)pkt;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t meshvpn_vpn_recv_ipv4(uint8_t *pkt, uint16_t maxlen, uint16_t *out_len)
{
    (void)pkt;
    (void)maxlen;
    (void)out_len;
    return ESP_ERR_NOT_SUPPORTED;
}

void meshvpn_vpn_get_status(meshvpn_vpn_status_t *status)
{
    memset(status, 0, sizeof(*status));
    status->enabled = s_enabled;
    status->connected = s_connected;
    strncpy(status->server, s_server, sizeof(status->server) - 1);
}
