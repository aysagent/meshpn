/* One-peer full-tunnel adapter. Never calls the library's set-default helper:
 * STA remains the physical uplink and project hooks own LAN routing. */
#include "meshvpn_wireguard.h"
#include "meshvpn_vpn_frame.h"
#include "wireguardif.h"
#include "wireguard.h"
#include "wireguard-platform.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "sdkconfig.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

static struct netif wg;
static bool active, crypto_ready;
static uint8_t peer_index;

static bool decode_key(const char *text, uint8_t out[32])
{
    size_t n = 0;
    if (strnlen(text, 45) != 44 || text[43] != '=' ||
        mbedtls_base64_decode(out, 32, &n, (const unsigned char *)text, 44) || n != 32) return false;
    unsigned bits = 0; for (unsigned i=0; i<32; i++) bits |= out[i];
    return bits != 0;
}
static bool unicast(const char *text)
{
    if (strnlen(text, 16) == 16) return false;
    char endpoint[24]; snprintf(endpoint, sizeof(endpoint), "%s:1", text);
    uint8_t bytes[4]; uint16_t port;
    ip4_addr_t parsed;
    return meshvpn_vpn_endpoint(endpoint, bytes, &port) && ip4addr_aton(text, &parsed) &&
        !memcmp(&parsed.addr, bytes, 4); /* reject ambiguous octal/short forms */
}
esp_err_t meshvpn_wg_validate(const meshvpn_vpn_config_t *c)
{
    uint8_t key[32];
    bool ok = unicast(c->wg_address) && unicast(c->wg_dns) && strcmp(c->wg_address, c->wg_dns) &&
        decode_key(c->wg_private_key, key) && decode_key(c->wg_public_key, key) &&
        (!c->wg_preshared_key[0] || decode_key(c->wg_preshared_key, key));
    mbedtls_platform_zeroize(key, sizeof(key));
    if (ok) {
        ip4_addr_t address; ip4addr_aton(c->wg_address, &address);
        unsigned ap_octet = CONFIG_MESHVPN_USB_SUBNET_OCTET_2 == 4 ? 3 : 4;
        if (ip4_addr1(&address) == 192 && ip4_addr2(&address) == 168 &&
            (ip4_addr3(&address) == CONFIG_MESHVPN_USB_SUBNET_OCTET_2 || ip4_addr3(&address) == ap_octet)) ok = false;
        uint8_t peer[4]; uint16_t port;
        if (!meshvpn_vpn_endpoint(c->server, peer, &port) || !memcmp(&address.addr, peer, 4)) ok = false;
    }
    return ok ? ESP_OK : ESP_ERR_INVALID_ARG;
}
bool meshvpn_wg_clock_ready(void)
{
    /* Worker context. ESP SNTP wrappers marshal calls to lwIP themselves.
     * WireGuard replay timestamps must not restart at 1970 on each reboot. */
    static bool started;
    if (!started) {
        esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
        esp_sntp_setservername(0, "pool.ntp.org");
        esp_sntp_init(); started = true;
    }
    return time(NULL) >= 1704067200; /* 2024-01-01 */
}
struct netif *meshvpn_wg_netif(void) { return active ? &wg : NULL; }
void meshvpn_wg_stop(void)
{
    if (!active) return;
    wireguardif_disconnect(&wg, peer_index);
    wireguardif_remove_peer(&wg, peer_index);
    wireguardif_shutdown(&wg); netif_remove(&wg);
    /* Upstream frees the context without wiping long-term/session keys. */
    mbedtls_platform_zeroize(wg.state, sizeof(struct wireguard_device));
    wireguardif_fini(&wg); memset(&wg, 0, sizeof(wg)); active = false;
}
esp_err_t meshvpn_wg_start(const meshvpn_vpn_config_t *c)
{
    if (active) return ESP_OK;
    esp_err_t err = meshvpn_wg_validate(c); if (err != ESP_OK) return err;
    if (!crypto_ready) {
        err = wireguard_platform_init(); if (err != ESP_OK) return err;
        crypto_ready = true;
    }
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta || !esp_netif_is_netif_up(sta)) return ESP_ERR_INVALID_STATE;
    esp_netif_ip_info_t sta_ip;
    ip4_addr_t wanted; ip4addr_aton(c->wg_address, &wanted);
    if (esp_netif_get_ip_info(sta, &sta_ip) != ESP_OK || !sta_ip.ip.addr) return ESP_ERR_INVALID_STATE;
    if ((wanted.addr & sta_ip.netmask.addr) == (sta_ip.ip.addr & sta_ip.netmask.addr)) return ESP_ERR_INVALID_ARG;
    struct wireguardif_init_data init = { .private_key = c->wg_private_key, .listen_port = 0 };
    ip4_addr_t address, mask, gateway;
    ip4addr_aton(c->wg_address, &address); IP4_ADDR(&mask,255,255,255,255); ip4_addr_set_zero(&gateway);
    /* Pinned library explicitly binds its UDP PCB to WIFI_STA_DEF. */
    if (!netif_add(&wg, &address, &mask, &gateway, &init, wireguardif_init, ip_input)) return ESP_FAIL;
    active = true; peer_index = WIREGUARDIF_INVALID_INDEX; wg.mtu = MESHVPN_VPN_MTU;
    struct wireguardif_peer peer; wireguardif_peer_init(&peer);
    peer.public_key = c->wg_public_key;
    uint8_t psk[32] = {0};
    if (c->wg_preshared_key[0]) { decode_key(c->wg_preshared_key, psk); peer.preshared_key = psk; }
    ip_addr_set_zero_ip4(&peer.allowed_ip); ip_addr_set_zero_ip4(&peer.allowed_mask); /* 0/0 */
    uint8_t bytes[4]; uint16_t port; meshvpn_vpn_endpoint(c->server, bytes, &port);
    IP_ADDR4(&peer.endpoint_ip, bytes[0],bytes[1],bytes[2],bytes[3]);
    peer.endport_port = port; peer.keep_alive = c->wg_keepalive;
    err_t result = wireguardif_add_peer(&wg, &peer, &peer_index);
    mbedtls_platform_zeroize(psk, sizeof(psk));
    if (result != ERR_OK) { meshvpn_wg_stop(); return ESP_FAIL; }
    netif_set_up(&wg);
    if (wireguardif_connect(&wg, peer_index) != ERR_OK) { meshvpn_wg_stop(); return ESP_FAIL; }
    return ESP_OK;
}
bool meshvpn_wg_up(void)
{ return active && wireguardif_peer_is_up(&wg, peer_index, NULL, NULL) == ERR_OK; }
uint32_t meshvpn_wg_handshake_age(void)
{
    if (!active) return UINT32_MAX;
    time_t t = wireguardif_latest_handshake(&wg, peer_index), now = time(NULL);
    return t && now >= t ? (uint32_t)(now-t) : UINT32_MAX;
}
err_t meshvpn_wg_output(struct pbuf *p, const ip4_addr_t *dest)
{ return active ? wg.output(&wg, p, dest) : ERR_RTE; }
