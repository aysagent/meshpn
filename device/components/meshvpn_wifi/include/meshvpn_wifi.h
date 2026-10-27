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
    bool sta_connected; /* IPv4 obtained, not merely 802.11 association. */
    bool sta_associated;
    uint32_t association_events;
    uint32_t disconnect_events;
    int8_t last_disconnect_rssi;
    int64_t last_disconnect_us;
    bool setup_mode;
    bool ap_active;
    int8_t rssi;
    uint8_t disconnect_reason;
    char ssid[33];
    char ip[16];
    uint32_t profile_id;
    bool scanning;
    bool paused;
    char state[24];
} meshvpn_wifi_status_t;

/** Register event handlers. Call after the WiFi driver is up (bridge netifs). */
esp_err_t meshvpn_wifi_init(void);
esp_err_t meshvpn_wifi_start_manager(void);
esp_err_t meshvpn_wifi_select(uint32_t profile_id);
esp_err_t meshvpn_wifi_reload(void);
bool meshvpn_wifi_scan_busy(void);

esp_err_t meshvpn_wifi_connect(void);
esp_err_t meshvpn_wifi_disconnect(void);

esp_err_t meshvpn_wifi_scan_start(void);
int meshvpn_wifi_scan_get_count(void);
esp_err_t meshvpn_wifi_scan_get_entry(int index, wifi_ap_record_t *rec);

void meshvpn_wifi_get_status(meshvpn_wifi_status_t *status);
bool meshvpn_wifi_needs_setup(void);
const char *meshvpn_wifi_disconnect_reason_name(uint8_t reason);

#ifdef __cplusplus
}
#endif
