#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
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
 * Create USB (192.168.7.1/24), optional AP (192.168.4.1/24) and WiFi STA uplink. Initialises
 * the WiFi driver, so this must run before any esp_wifi_* configuration.
 */
esp_err_t meshvpn_net_start_bridge(void);

/** Re-apply NAT independently on both USB and AP LANs. */
void meshvpn_net_ensure_napt(void);

void meshvpn_net_log_state(void);
void meshvpn_net_get_status(meshvpn_net_status_t *status);
esp_netif_t *meshvpn_net_usb(void);
esp_netif_t *meshvpn_net_ap(void);
esp_err_t meshvpn_net_start_mdns(bool https_enabled);

#ifdef __cplusplus
}
#endif
