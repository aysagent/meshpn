#pragma once
#include <stdint.h>
#include "esp_err.h"
#define ESP_ERR_NOT_SUPPORTED 5
typedef int wifi_second_chan_t;
typedef int wifi_ps_type_t;
typedef int wifi_bandwidth_t;
typedef int wifi_phy_mode_t;
typedef struct { int8_t rssi; } wifi_ap_record_t;
typedef struct { unsigned num; } wifi_sta_list_t;
enum { WIFI_IF_STA, WIFI_IF_AP };
esp_err_t esp_wifi_get_channel(uint8_t *, wifi_second_chan_t *);
esp_err_t esp_wifi_get_ps(wifi_ps_type_t *);
esp_err_t esp_wifi_get_bandwidth(int, wifi_bandwidth_t *);
esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *);
esp_err_t esp_wifi_ap_get_sta_list(wifi_sta_list_t *);
esp_err_t esp_wifi_sta_get_negotiated_phymode(wifi_phy_mode_t *);
