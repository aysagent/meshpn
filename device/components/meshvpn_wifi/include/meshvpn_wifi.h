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
    bool ap_active;
    int8_t rssi;
    uint8_t channel;
    uint8_t bandwidth_mhz;
    uint8_t disconnect_reason;
    char ssid[33];
    char ip[16];
} meshvpn_wifi_status_t;

/** Register event handlers. Call after the WiFi driver is up (bridge netifs). */
esp_err_t meshvpn_wifi_init(void);

esp_err_t meshvpn_wifi_start_sta(const meshvpn_wifi_creds_t *creds);
esp_err_t meshvpn_wifi_connect(void);
esp_err_t meshvpn_wifi_disconnect(void);

esp_err_t meshvpn_wifi_scan_start(void);
int meshvpn_wifi_scan_get_count(void);
esp_err_t meshvpn_wifi_scan_get_entry(int index, wifi_ap_record_t *rec);

void meshvpn_wifi_get_status(meshvpn_wifi_status_t *status);

#ifdef __cplusplus
}
#endif
