#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_wifi.h"

typedef struct {
    int64_t sampled_us;
    uint32_t collection_us;
    esp_err_t channel_error, ps_error, bandwidth_error[2], uplink_error, peers_error;
    esp_err_t phymode_error;
    wifi_phy_mode_t phymode;
    uint8_t primary;
    wifi_second_chan_t secondary;
    wifi_ps_type_t ps;
    wifi_bandwidth_t bandwidth[2];
    wifi_ap_record_t uplink;
    wifi_sta_list_t peers;
} meshvpn_wifi_radio_t;

/* Manager task collects at most every 5 seconds, outside association/scanning.
 * HTTP handlers only copy this cache; no synchronous C6 RPC on that path. */
void meshvpn_wifi_radio_sample(void);
void meshvpn_wifi_radio_snapshot(meshvpn_wifi_radio_t *out);
void meshvpn_wifi_radio_summary(int8_t *rssi, uint8_t *channel, uint8_t *clients);
