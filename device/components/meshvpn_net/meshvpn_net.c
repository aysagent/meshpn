#include "meshvpn_net.h"

#include <stdio.h>
#include <string.h>

#include "dhcpserver/dhcpserver.h"
#include "esp_bridge.h"
#include "esp_bridge_events.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "lwip/ip4.h"
#include "lwip/lwip_napt.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "meshvpn_usb.h"
#include "meshvpn_wifi.h"
#include "meshvpn_lwip_hooks.h"
#include "sdkconfig.h"

#define MESHVPN_AP_SUBNET_OCTET_2 4

static const char *TAG = "meshvpn_net";
static bool s_bridge_running;
static esp_netif_t *s_usb_netif;
static esp_netif_t *s_ap_netif;
static esp_netif_t *s_sta_netif;
static bool s_usb_napt;
static bool s_ap_napt;

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
 * DHCP DNS = gateway IP. meshvpn_dns_proxy listens on :53 and hijacks captive
 * portal hostnames to the local web UI while forwarding everything else upstream.
 */
static void meshvpn_net_configure_lan_dhcp(esp_netif_t *netif)
{
    esp_netif_ip_info_t ip;
    if (!netif || esp_netif_get_ip_info(netif, &ip) != ESP_OK) {
        return;
    }

    esp_netif_dns_info_t dns = {
        .ip = {
            .type = IPADDR_TYPE_V4,
            .u_addr = { .ip4 = ip.ip },
        },
    };

    dhcps_offer_t offer_dns = OFFER_DNS;
    uint8_t offer_router = 1;
    uint32_t lease_sec = 120;
    char captive[48];

    esp_netif_dhcps_stop(netif);
    esp_netif_dhcps_option(netif, ESP_NETIF_OP_SET, ESP_NETIF_ROUTER_SOLICITATION_ADDRESS,
                           &offer_router, sizeof(offer_router));
    esp_netif_dhcps_option(netif, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER,
                           &offer_dns, sizeof(offer_dns));
    esp_netif_dhcps_option(netif, ESP_NETIF_OP_SET, ESP_NETIF_IP_ADDRESS_LEASE_TIME,
                           &lease_sec, sizeof(lease_sec));
    esp_netif_set_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns);
    snprintf(captive, sizeof(captive), "http://" IPSTR "/login", IP2STR(&ip.ip));
    esp_netif_dhcps_option(netif, ESP_NETIF_OP_SET, ESP_NETIF_CAPTIVEPORTAL_URI,
                           captive, strlen(captive) + 1);
    esp_netif_dhcps_start(netif);
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

static void meshvpn_net_on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = data;
        if (s_sta_netif && ev->esp_netif == s_sta_netif) {
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

#if defined(CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP)
    meshvpn_net_fill_ip(&ip, MESHVPN_AP_SUBNET_OCTET_2);
    s_ap_netif = esp_bridge_create_softap_netif(&ip, NULL, true, true);
    if (!s_ap_netif) {
        ESP_LOGE(TAG, "SoftAP netif creation failed");
    }
#endif

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
    } else {
        ESP_LOGI(TAG, "USB lwIP MAC " MACSTR, MAC2STR(usb_lwip_mac));
        esp_err_t attach_err = meshvpn_usb_attach_netif(s_usb_netif);
        if (attach_err != ESP_OK) {
            ESP_LOGE(TAG, "USB transmit path failed: %s", esp_err_to_name(attach_err));
        }
        meshvpn_net_configure_lan_dhcp(s_usb_netif);
    }
#endif

#if defined(CONFIG_BRIDGE_EXTERNAL_NETIF_STATION)
    s_sta_netif = esp_bridge_create_station_netif(NULL, NULL, false, false);
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
    status->usb_subnet_octet2 = CONFIG_MESHVPN_USB_SUBNET_OCTET_2;
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

    meshvpn_wifi_status_t ws;
    meshvpn_wifi_get_status(&ws);
    status->wifi_uplink = ws.sta_connected;
}

typedef struct {
    const uint8_t *pkt;
    uint16_t len;
} meshvpn_net_inject_ctx_t;

static esp_err_t meshvpn_net_inject_api(void *ctx)
{
    meshvpn_net_inject_ctx_t *inj = ctx;
    if (!s_usb_netif || !inj->pkt || inj->len < 20) {
        return ESP_ERR_INVALID_ARG;
    }

    struct netif *netif = esp_netif_get_netif_impl(s_usb_netif);
    if (!netif || !netif_is_up(netif)) {
        return ESP_ERR_INVALID_STATE;
    }

    struct pbuf *p = pbuf_alloc(PBUF_RAW, inj->len, PBUF_RAM);
    if (!p) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(p->payload, inj->pkt, inj->len);

    if (netif->input(p, netif) != ERR_OK) {
        pbuf_free(p);
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t meshvpn_net_inject_ipv4_to_lan(const uint8_t *pkt, uint16_t len)
{
    meshvpn_net_inject_ctx_t ctx = { .pkt = pkt, .len = len };
    return esp_netif_tcpip_exec(meshvpn_net_inject_api, &ctx);
}
