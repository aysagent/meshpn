#include "meshvpn_net.h"

#include <stdio.h>
#include <string.h>

#include "meshvpn_net_dhcp.h"
#include "esp_bridge.h"
#include "esp_bridge_events.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "lwip/lwip_napt.h"
#include "lwip/netif.h"
#include "meshvpn_usb.h"
#include "meshvpn_wifi.h"
#include "meshvpn_lwip_hooks.h"
#include "meshvpn_subnet.h"
#include "esp_wifi.h"
#include "sdkconfig.h"
#include "mdns.h"
#include "meshvpn_dns_proxy.h"

#define MESHVPN_AP_SUBNET_OCTET_2 (CONFIG_MESHVPN_USB_SUBNET_OCTET_2 == 4 ? 3 : 4)

static const char *TAG = "meshvpn_net";
static bool s_bridge_running;
static esp_netif_t *s_usb_netif;
static esp_netif_t *s_ap_netif;
static esp_netif_t *s_sta_netif;
static bool s_usb_napt;
static bool s_ap_napt;
static bool s_mdns;

esp_netif_t *meshvpn_net_usb(void) { return s_usb_netif; }
esp_netif_t *meshvpn_net_ap(void) { return s_ap_netif; }

esp_err_t meshvpn_net_start_mdns(bool https_enabled)
{
    const char *service = https_enabled ? "_https" : "_http";
    const uint16_t port = https_enabled ? 443 : 80;
    esp_err_t err = mdns_init();
    if (err != ESP_OK) return err;
    if ((err = mdns_hostname_set("meshpn")) != ESP_OK ||
        (err = mdns_register_netif(s_usb_netif)) != ESP_OK ||
        (err = mdns_netif_action(s_usb_netif, MDNS_EVENT_ENABLE_IP4)) != ESP_OK ||
        (err = mdns_service_add(NULL, service, "_tcp", port, NULL, 0)) != ESP_OK) {
        mdns_free();
        return err;
    }
    s_mdns = true;
    if (s_ap_netif && ((err = mdns_register_netif(s_ap_netif)) != ESP_OK ||
        (err = mdns_netif_action(s_ap_netif, MDNS_EVENT_ENABLE_IP4)) != ESP_OK)) {
        mdns_free();
        s_mdns = false;
        return err;
    }
    return ESP_OK;
}

typedef struct {
    esp_netif_t *netif;
    bool napt;
} meshvpn_net_napt_query_t;

static void meshvpn_net_fill_ip(esp_netif_ip_info_t *ip, uint8_t octet3)
{
    ip->ip.addr = ESP_IP4TOADDR(192, 168, octet3, 1);
    ip->gw.addr = ESP_IP4TOADDR(192, 168, octet3, 1);
    ip->netmask.addr = ESP_IP4TOADDR(255, 255, 255, 0);
}

static void meshvpn_net_read_ip(esp_netif_t *netif, char *out, size_t out_len)
{
    esp_netif_ip_info_t ip;
    if (!netif || esp_netif_get_ip_info(netif, &ip) != ESP_OK) {
        snprintf(out, out_len, "-");
        return;
    }
    snprintf(out, out_len, IPSTR, IP2STR(&ip.ip));
}

static esp_err_t meshvpn_net_napt_enable_api(void *ctx)
{
    struct netif *lwip_netif = esp_netif_get_netif_impl((esp_netif_t *)ctx);
    if (!lwip_netif || !netif_is_up(lwip_netif)) {
        return ESP_ERR_INVALID_STATE;
    }
    return ip_napt_enable_netif(lwip_netif, 1) ? ESP_OK : ESP_FAIL;
}

static esp_err_t meshvpn_net_napt_query_api(void *ctx)
{
    meshvpn_net_napt_query_t *q = ctx;
    struct netif *lwip_netif = esp_netif_get_netif_impl(q->netif);
    q->napt = lwip_netif && lwip_netif->napt;
    return ESP_OK;
}

static bool meshvpn_net_query_napt(esp_netif_t *netif)
{
    meshvpn_net_napt_query_t q = { .netif = netif, .napt = false };
    if (!netif) {
        return false;
    }
    if (esp_netif_tcpip_exec(meshvpn_net_napt_query_api, &q) != ESP_OK) {
        return false;
    }
    return q.napt;
}

static void meshvpn_net_refresh_napt_flags(void)
{
    s_usb_napt = meshvpn_net_query_napt(s_usb_netif);
    s_ap_napt = meshvpn_net_query_napt(s_ap_netif);
}

/**
 * DHCP DNS = gateway IP. The proxy answers local management names and forwards
 * ordinary queries, including host connectivity checks, upstream.
 */
static void meshvpn_net_configure_lan_dhcp(esp_netif_t *netif)
{
    if (!netif) return;
    esp_err_t err = meshvpn_net_apply_lan_dhcp(netif);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "LAN DHCP configuration failed on %s: %s",
                 esp_netif_get_ifkey(netif), esp_err_to_name(err));
    }
}

static void meshvpn_net_read_offered_dns(esp_netif_t *netif, char *out, size_t out_len)
{
    esp_netif_dns_info_t dns = {0};
    if (!netif || esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns) != ESP_OK ||
        dns.ip.type != IPADDR_TYPE_V4 || dns.ip.u_addr.ip4.addr == 0) {
        snprintf(out, out_len, "-");
        return;
    }
    snprintf(out, out_len, IPSTR, IP2STR(&dns.ip.u_addr.ip4));
}

void meshvpn_net_refresh_lan_dhcp(void)
{
    char usb_dns[16];
#if defined(CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP)
    char ap_dns[16];
#endif

    meshvpn_net_configure_lan_dhcp(s_usb_netif);
#if defined(CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP)
    meshvpn_net_configure_lan_dhcp(s_ap_netif);
#endif

    meshvpn_net_read_offered_dns(s_usb_netif, usb_dns, sizeof(usb_dns));
#if defined(CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP)
    meshvpn_net_read_offered_dns(s_ap_netif, ap_dns, sizeof(ap_dns));
    ESP_LOGD(TAG, "LAN DHCP DNS: USB=%s AP=%s", usb_dns, ap_dns);
#else
    ESP_LOGD(TAG, "LAN DHCP DNS: USB=%s", usb_dns);
#endif
}

static void meshvpn_net_resolve_lan_conflict(esp_netif_t *lan, esp_netif_t *other,
                                           const esp_netif_ip_info_t *uplink)
{
    esp_netif_ip_info_t current, peer = {0};
    if (!lan || esp_netif_get_ip_info(lan, &current) != ESP_OK) return;
    if (other) esp_netif_get_ip_info(other, &peer);
    if (!meshvpn_subnets_overlap(ntohl(current.ip.addr), ntohl(current.netmask.addr),
                                 ntohl(uplink->ip.addr), ntohl(uplink->netmask.addr)) &&
        (!peer.ip.addr || !meshvpn_subnets_overlap(ntohl(current.ip.addr), ntohl(current.netmask.addr),
                                                  ntohl(peer.ip.addr), ntohl(peer.netmask.addr)))) return;
    uint32_t selected;
    if (!meshvpn_pick_lan_ip(ntohl(uplink->ip.addr), ntohl(uplink->netmask.addr),
                            ntohl(peer.ip.addr), ntohl(peer.netmask.addr), &selected)) {
        ESP_LOGE(TAG, "No non-conflicting subnet for %s", esp_netif_get_ifkey(lan));
        return;
    }
    current.ip.addr = current.gw.addr = htonl(selected);
    current.netmask.addr = htonl(0xffffff00u);
    esp_netif_dhcps_stop(lan);
    if (esp_netif_set_ip_info(lan, &current) != ESP_OK) {
        ESP_LOGE(TAG, "Cannot change subnet on %s", esp_netif_get_ifkey(lan));
        return; /* DHCP is restarted by the event handler below. */
    }
    ESP_LOGW(TAG, "%s subnet conflict: moved gateway to " IPSTR "; renew DHCP/reconnect client",
             esp_netif_get_ifkey(lan), IP2STR(&current.ip));
    if (lan == s_ap_netif) esp_wifi_deauth_sta(0);
    if (s_mdns) mdns_netif_action(lan, MDNS_EVENT_ANNOUNCE_IP4);
}

static void meshvpn_net_on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = data;
        if (s_sta_netif && ev->esp_netif == s_sta_netif) {
            meshvpn_dns_clear_cache();
            meshvpn_net_resolve_lan_conflict(s_usb_netif, s_ap_netif, &ev->ip_info);
            meshvpn_net_resolve_lan_conflict(s_ap_netif, s_usb_netif, &ev->ip_info);
            esp_netif_set_default_netif(s_sta_netif);
            ESP_LOGI(TAG, "STA default route set");
        }
    }

    /* iot_bridge calls esp_netif_napt_enable() on the SoftAP whenever its DNS
     * or address changes. That API disables NAPT on every other interface — USB
     * included — so re-apply right after those events, not only on a timer. */
    if ((base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) ||
        (base == BRIDGE_EVENT && id == BRIDGE_EVENT_ID_DNS_UPDATE)
#if defined(CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP)
        || (base == WIFI_EVENT && id == WIFI_EVENT_AP_START)
#endif
        ) {
        /* Bridge overwrites LAN DHCP DNS with the uplink resolver (8.8.8.8 /
         * router) whenever STA gets an address. Undo that so clients keep using
         * the gateway DNS proxy on :53. */
        meshvpn_net_refresh_lan_dhcp();
        meshvpn_net_ensure_napt();
    }
}

void meshvpn_net_ensure_napt(void)
{
    esp_netif_t *lans[] = { s_usb_netif, s_ap_netif };

    for (size_t i = 0; i < sizeof(lans) / sizeof(lans[0]); i++) {
        if (!lans[i]) {
            continue;
        }
        esp_err_t err = esp_netif_tcpip_exec(meshvpn_net_napt_enable_api, lans[i]);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "NAPT enable on %s failed: %s",
                     esp_netif_get_ifkey(lans[i]), esp_err_to_name(err));
        }
    }

    meshvpn_net_refresh_napt_flags();
}

esp_err_t meshvpn_net_init(void)
{
    ESP_LOGI(TAG, "net init");
    return ESP_OK;
}

esp_err_t meshvpn_net_start_bridge(void)
{
    esp_netif_ip_info_t ip;
    /* The dependency can log STA/AP passwords at INFO. Suppress before either
     * interface is created. Our own logs include SSID, never the password. */
    esp_log_level_set("bridge_wifi", ESP_LOG_WARN);

#if defined(CONFIG_BRIDGE_DATA_FORWARDING_NETIF_USB)
    /* lwIP USB gateway MAC: derived from ETH base, locally administered, and
     * distinct from NCM (ESP_MAC_ETH), WiFi STA, and SoftAP. */
    uint8_t usb_lwip_mac[6];
    esp_read_mac(usb_lwip_mac, ESP_MAC_ETH);
    usb_lwip_mac[0] |= 0x02;
    usb_lwip_mac[5] = (uint8_t)(usb_lwip_mac[5] + 1);

    meshvpn_net_fill_ip(&ip, CONFIG_MESHVPN_USB_SUBNET_OCTET_2);
    s_usb_netif = esp_bridge_create_usb_netif(&ip, usb_lwip_mac, true, true);
    if (!s_usb_netif) {
        ESP_LOGE(TAG, "USB netif creation failed");
        return ESP_FAIL;
    } else {
        ESP_LOGI(TAG, "USB lwIP MAC " MACSTR, MAC2STR(usb_lwip_mac));
        meshvpn_net_set_usb_interface(esp_netif_get_netif_impl(s_usb_netif));
        meshvpn_usb_attach_netif(s_usb_netif);
        meshvpn_net_configure_lan_dhcp(s_usb_netif);
    }
#endif

#if defined(CONFIG_BRIDGE_EXTERNAL_NETIF_STATION)
    s_sta_netif = esp_bridge_create_station_netif(NULL, NULL, false, false);
    if (!s_sta_netif) return ESP_FAIL;
#endif

#if defined(CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP)
    /* Configure before starting AP beacons: never expose a transient open AP.
     * STA profile manager has not started connecting yet, so stopping the radio
     * here does not interrupt an established uplink. */
    esp_err_t err = esp_wifi_stop();
    if (err != ESP_OK) return err;
    meshvpn_net_fill_ip(&ip, MESHVPN_AP_SUBNET_OCTET_2);
    s_ap_netif = esp_bridge_create_softap_netif(&ip, NULL, true, true);
    if (!s_ap_netif) return ESP_FAIL;
    meshvpn_net_set_ap_interface(esp_netif_get_netif_impl(s_ap_netif));
    wifi_config_t cfg = {0};
    char ssid[33];
#if CONFIG_BRIDGE_SOFTAP_SSID_END_WITH_THE_MAC
    uint8_t ap_mac[6];
    err = esp_wifi_get_mac(WIFI_IF_AP, ap_mac);
    if (err != ESP_OK) return err;
    snprintf(ssid, sizeof(ssid), "%s_%02x%02x%02x", CONFIG_BRIDGE_SOFTAP_SSID,
             ap_mac[3], ap_mac[4], ap_mac[5]);
#else
    snprintf(ssid, sizeof(ssid), "%s", CONFIG_BRIDGE_SOFTAP_SSID);
#endif
    cfg.ap.ssid_len = strlen(ssid);
    memcpy(cfg.ap.ssid, ssid, cfg.ap.ssid_len);
    memcpy(cfg.ap.password, CONFIG_BRIDGE_SOFTAP_PASSWORD, strlen(CONFIG_BRIDGE_SOFTAP_PASSWORD));
    cfg.ap.authmode = WIFI_AUTH_WPA2_PSK;
    cfg.ap.pmf_cfg.capable = true;
    cfg.ap.max_connection = CONFIG_BRIDGE_SOFTAP_MAX_CONNECT_NUMBER;
    cfg.ap.channel = 1; /* STA association selects the shared channel later. */
    err = esp_wifi_set_config(WIFI_IF_AP, &cfg);
    memset(cfg.ap.password, 0, sizeof(cfg.ap.password));
    if (err != ESP_OK) return err;
    err = esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT40);
    if (err != ESP_OK) return err;
    ESP_LOGI(TAG, "SoftAP %s: WPA2, max %u clients; management remains USB-only",
             ssid, (unsigned)CONFIG_BRIDGE_SOFTAP_MAX_CONNECT_NUMBER);
#endif

    if (s_usb_netif) {
        esp_bridge_netif_set_conflict_check(s_usb_netif, false);
    }
    if (s_ap_netif) {
        esp_bridge_netif_set_conflict_check(s_ap_netif, false);
        meshvpn_net_configure_lan_dhcp(s_ap_netif);
    }

    s_bridge_running = true;
    meshvpn_net_ensure_napt();
    meshvpn_net_log_state();

    /* Register after iot_bridge so our handlers run after bridge DNS/NAPT hooks. */
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, meshvpn_net_on_event, NULL));
#if defined(CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP)
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_AP_START, meshvpn_net_on_event, NULL));
#endif
    ESP_ERROR_CHECK(esp_event_handler_register(BRIDGE_EVENT, BRIDGE_EVENT_ID_DNS_UPDATE, meshvpn_net_on_event, NULL));

#if defined(CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP)
    err = esp_wifi_start();
    if (err != ESP_OK) return err;
#endif

    return ESP_OK;
}

void meshvpn_net_log_state(void)
{
    char usb_ip[16];
    meshvpn_net_read_ip(s_usb_netif, usb_ip, sizeof(usb_ip));
    meshvpn_net_refresh_napt_flags();
#if defined(CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP)
    char ap_ip[16];
    meshvpn_net_read_ip(s_ap_netif, ap_ip, sizeof(ap_ip));
    ESP_LOGI(TAG, "bridge up: USB %s napt=%d (%s), SoftAP %s napt=%d",
             usb_ip, s_usb_napt, meshvpn_usb_profile_name(), ap_ip, s_ap_napt);
#else
    ESP_LOGI(TAG, "bridge up: USB %s napt=%d (%s)",
             usb_ip, s_usb_napt, meshvpn_usb_profile_name());
#endif
}

void meshvpn_net_get_status(meshvpn_net_status_t *status)
{
    memset(status, 0, sizeof(*status));
    status->bridge_running = s_bridge_running;
    esp_netif_ip_info_t ip = {0};
    esp_netif_get_ip_info(s_usb_netif, &ip);
    status->usb_subnet_octet2 = esp_ip4_addr3(&ip.ip);
    meshvpn_net_read_ip(s_usb_netif, status->usb_ip, sizeof(status->usb_ip));
    meshvpn_net_read_ip(s_ap_netif, status->ap_ip, sizeof(status->ap_ip));
    status->usb_napt = s_usb_napt;
    status->ap_napt = s_ap_napt;

    esp_netif_t *def = esp_netif_get_default_netif();
    if (def) {
        strncpy(status->default_ifkey, esp_netif_get_ifkey(def), sizeof(status->default_ifkey) - 1);
    } else {
        strncpy(status->default_ifkey, "-", sizeof(status->default_ifkey));
    }

    meshvpn_net_read_offered_dns(s_usb_netif, status->usb_dhcps_dns, sizeof(status->usb_dhcps_dns));
    status->lan_ip4_rx = meshvpn_net_lan_ip4_rx_count();
    status->ap_ip4_rx = meshvpn_net_ap_ip4_rx_count();
    meshvpn_net_read_offered_dns(s_ap_netif, status->ap_dhcps_dns, sizeof(status->ap_dhcps_dns));

    meshvpn_wifi_status_t ws;
    meshvpn_wifi_get_status(&ws);
    status->wifi_uplink = ws.sta_connected;
    status->ap_active = ws.ap_active;
#if CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP
    wifi_config_t cfg;
    if (s_ap_netif && esp_wifi_get_config(WIFI_IF_AP, &cfg) == ESP_OK) {
        memcpy(status->ap_ssid, cfg.ap.ssid, sizeof(cfg.ap.ssid));
        memset(cfg.ap.password, 0, sizeof(cfg.ap.password));
    }
    wifi_sta_list_t clients;
    if (status->ap_active && esp_wifi_ap_get_sta_list(&clients) == ESP_OK) status->ap_clients = clients.num;
    wifi_second_chan_t secondary;
    if (status->ap_active) esp_wifi_get_channel(&status->ap_channel, &secondary);
#endif
}
