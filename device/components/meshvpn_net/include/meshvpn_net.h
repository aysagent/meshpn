#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

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
} meshvpn_net_status_t;

esp_err_t meshvpn_net_init(void);

/** Re-apply USB LAN DHCP (gateway DNS + captive portal URI). */
void meshvpn_net_refresh_lan_dhcp(void);

/**
 * Create bridge netifs: USB (192.168.7.1/24) and WiFi STA uplink. Also initialises
 * the WiFi driver, so this must run before any esp_wifi_* configuration.
 */
esp_err_t meshvpn_net_start_bridge(void);

/** Re-apply NAT on the USB LAN interface. */
void meshvpn_net_ensure_napt(void);

void meshvpn_net_log_state(void);
void meshvpn_net_get_status(meshvpn_net_status_t *status);

#ifdef __cplusplus
}
#endif
