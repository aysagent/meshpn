#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_wifi.h"
#include "meshvpn_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool sta_connected;
    bool setup_mode;
    bool configured;
    bool ap_active;
    int8_t rssi;
    uint8_t disconnect_reason;
    char ssid[33];
    char ip[16];
} meshvpn_wifi_status_t;

/** Register event handlers. Call after the WiFi driver is up (bridge netifs). */
esp_err_t meshvpn_wifi_init(void);

/** Load saved SSID from NVS for status/UI (does not connect). */
void meshvpn_wifi_restore_saved(void);

/** Lower TX power for USB bus-powered use (call before STA connect). */
void meshvpn_wifi_apply_bus_power_limits(void);

esp_err_t meshvpn_wifi_start_sta(const meshvpn_wifi_creds_t *creds);
esp_err_t meshvpn_wifi_connect(void);
esp_err_t meshvpn_wifi_disconnect(void);

esp_err_t meshvpn_wifi_scan_start(void);
int meshvpn_wifi_scan_get_count(void);
esp_err_t meshvpn_wifi_scan_get_entry(int index, wifi_ap_record_t *rec);

void meshvpn_wifi_get_status(meshvpn_wifi_status_t *status);

/** True when wall clock is usable for VPN Bearer HMAC windows. */
bool meshvpn_wifi_time_ready(void);

#ifdef __cplusplus
}
#endif
