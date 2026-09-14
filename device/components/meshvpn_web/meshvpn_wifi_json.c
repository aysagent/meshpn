#include "cJSON.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "meshvpn_wifi_diag.h"

static void number_or_null(cJSON *obj, const char *name, esp_err_t err, int value)
{
    if (err == ESP_OK) cJSON_AddNumberToObject(obj, name, value);
    else cJSON_AddNullToObject(obj, name);
}

void meshvpn_wifi_diagnostics_json(cJSON *wifi)
{
    meshvpn_wifi_tx_diag_t stats[2];
    meshvpn_wifi_tx_snapshot(stats);
    cJSON *tx = cJSON_AddObjectToObject(wifi, "tx");
    cJSON_AddBoolToObject(tx, "available", true);
    for (int i = 0; i < 2; i++) {
        cJSON *s = cJSON_AddObjectToObject(tx, i ? "ap" : "sta");
#define ADD(name) cJSON_AddNumberToObject(s, #name, (double)stats[i].name);
        MESHVPN_WIFI_TX_COUNTERS(ADD)
        ADD(call_max_us)
        ADD(last_error)
#undef ADD
    }
    cJSON *radio = cJSON_AddObjectToObject(wifi, "radio");
    uint8_t primary = 0;
    wifi_second_chan_t secondary = WIFI_SECOND_CHAN_NONE;
    esp_err_t err = esp_wifi_get_channel(&primary, &secondary);
    number_or_null(radio, "primary_channel", err, primary);
    number_or_null(radio, "secondary_channel", err, secondary);
    wifi_ps_type_t ps = WIFI_PS_NONE;
    err = esp_wifi_get_ps(&ps);
    number_or_null(radio, "power_save", err, ps);
    for (int i = 0; i < 2; i++) {
        wifi_bandwidth_t bw = WIFI_BW_HT20;
        err = esp_wifi_get_bandwidth(i ? WIFI_IF_AP : WIFI_IF_STA, &bw);
        number_or_null(radio, i ? "ap_bandwidth_mhz" : "sta_bandwidth_mhz",
                       err == ESP_OK && (bw == WIFI_BW_HT20 || bw == WIFI_BW_HT40) ? ESP_OK : ESP_FAIL,
                       bw == WIFI_BW_HT40 ? 40 : 20);
    }
    wifi_ap_record_t uplink = {0};
    err = esp_wifi_sta_get_ap_info(&uplink);
    cJSON *sta = cJSON_AddObjectToObject(radio, "uplink");
    cJSON_AddBoolToObject(sta, "available", err == ESP_OK);
    if (err == ESP_OK) {
        cJSON_AddNumberToObject(sta, "rssi", uplink.rssi);
        cJSON_AddNumberToObject(sta, "primary_channel", uplink.primary);
        cJSON_AddNumberToObject(sta, "secondary_channel", uplink.second);
        cJSON_AddBoolToObject(sta, "phy_11n", uplink.phy_11n);
    }
    wifi_sta_list_t peers = {0};
    err = esp_wifi_ap_get_sta_list(&peers);
    cJSON_AddBoolToObject(radio, "clients_available", err == ESP_OK);
    cJSON *clients = cJSON_AddArrayToObject(radio, "clients");
    if (err == ESP_OK) for (int i = 0; i < peers.num && i < ESP_WIFI_MAX_CONN_NUM; i++) {
        const wifi_sta_info_t *p = &peers.sta[i];
        cJSON *client = cJSON_CreateObject();
        cJSON_AddItemToArray(clients, client);
        /* No MAC/SSID in diagnostics exports. Index is snapshot-local, not identity. */
        cJSON_AddNumberToObject(client, "index", i);
        cJSON_AddNumberToObject(client, "rssi", p->rssi);
        cJSON_AddBoolToObject(client, "phy_11b", p->phy_11b);
        cJSON_AddBoolToObject(client, "phy_11g", p->phy_11g);
        cJSON_AddBoolToObject(client, "phy_11n", p->phy_11n);
        cJSON_AddBoolToObject(client, "phy_lr", p->phy_lr);
    }
    cJSON_AddNumberToObject(radio, "sampled_us", (double)esp_timer_get_time());
}
