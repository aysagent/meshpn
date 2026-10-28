#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char name[8];
    uint32_t ip, netmask, gateway;
    bool up, link, napt, is_default;
    bool gateway_arp_known;
    uint8_t mac[6];
    uint8_t gateway_mac[6];
} meshvpn_net_interface_t;
typedef struct {
    meshvpn_net_interface_t interfaces[8];
    unsigned interface_count;
    bool bridge_running;
    bool wifi_uplink;
    uint32_t usb_subnet_octet2;
    char usb_ip[16];
    char ap_ip[16];
    bool usb_napt;
    bool ap_napt;
    char default_ifkey[16];
    char usb_dhcps_dns[16];
    uint32_t lan_ip4_rx;
    uint32_t ap_ip4_rx;
    bool ap_active;
    char ap_ssid[33];
    uint8_t ap_clients;
    uint8_t ap_channel;
    char ap_dhcps_dns[16];
} meshvpn_net_status_t;

esp_err_t meshvpn_net_init(void);

/** Re-apply USB/AP LAN DHCP (gateway DNS, no captive portal). */
void meshvpn_net_refresh_lan_dhcp(void);

/**
 * Create USB (192.168.10.1/24), optional AP (192.168.11.1/24) and DHCP WiFi STA uplink. Initialises
 * the WiFi driver, so this must run before any esp_wifi_* configuration.
 */
esp_err_t meshvpn_net_start_bridge(void);

/** Re-apply NAT independently on both USB and AP LANs. */
void meshvpn_net_ensure_napt(void);

void meshvpn_net_log_state(void);
void meshvpn_net_get_status(meshvpn_net_status_t *status);
esp_netif_t *meshvpn_net_usb(void);
esp_netif_t *meshvpn_net_ap(void);
esp_netif_t *meshvpn_net_sta(void);
esp_err_t meshvpn_net_start_mdns(bool https_enabled);
esp_err_t meshvpn_net_set_hostname(const char *name);

#ifdef __cplusplus
}
#endif
