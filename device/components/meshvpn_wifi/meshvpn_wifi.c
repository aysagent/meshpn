#include "meshvpn_wifi.h"

#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "sdkconfig.h"

static const char *TAG = "meshvpn_wifi";

static bool s_sta_connected;
static bool s_sta_configured;
static int8_t s_rssi;
static uint8_t s_disconnect_reason;
static char s_ssid[33];
static char s_ip[16];
static wifi_ap_record_t s_scan_results[20];
static uint16_t s_scan_count;

static void on_wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *ev = data;
        s_disconnect_reason = ev->reason;
        s_sta_connected = false;
        s_ip[0] = '\0';
        ESP_LOGW(TAG, "STA disconnected from %.32s, reason %u", s_ssid, ev->reason);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = data;
        esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (sta && ev->esp_netif != sta) {
            return;
        }
        snprintf(s_ip, sizeof(s_ip), IPSTR, IP2STR(&ev->ip_info.ip));
        s_sta_connected = true;
        s_disconnect_reason = 0;
        /* Keep modem awake on the uplink — PS can cut NAT throughput badly. */
        esp_wifi_set_ps(WIFI_PS_NONE);
        ESP_LOGI(TAG, "STA got IP %s", s_ip);
    }
}

esp_err_t meshvpn_wifi_init(void)
{
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_wifi_event, NULL));
    return ESP_OK;
}

esp_err_t meshvpn_wifi_start_sta(const meshvpn_wifi_creds_t *creds)
{
    wifi_config_t wifi_cfg = {0};
    strncpy((char *)wifi_cfg.sta.ssid, creds->ssid, sizeof(wifi_cfg.sta.ssid));
    strncpy((char *)wifi_cfg.sta.password, creds->password, sizeof(wifi_cfg.sta.password));
    wifi_cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;
    wifi_cfg.sta.pmf_cfg.required = false;

    esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "STA config failed: %s", esp_err_to_name(err));
        return err;
    }

    esp_wifi_disable_pmf_config(WIFI_IF_STA);
    esp_wifi_set_ps(WIFI_PS_NONE);
    /* Prefer HT40 on 2.4 GHz when the AP allows it; falls back silently. */
    esp_err_t bw_err = esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT40);
    if (bw_err != ESP_OK) {
        ESP_LOGW(TAG, "STA HT40 unavailable (%s), staying on default BW", esp_err_to_name(bw_err));
    }

    strncpy(s_ssid, creds->ssid, sizeof(s_ssid) - 1);
    s_sta_configured = true;
    ESP_LOGI(TAG, "STA configured for SSID %s (PS off)", creds->ssid);
    return meshvpn_wifi_connect();
}

esp_err_t meshvpn_wifi_connect(void)
{
    esp_err_t err = esp_wifi_connect();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "connect failed: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t meshvpn_wifi_disconnect(void)
{
    return esp_wifi_disconnect();
}

esp_err_t meshvpn_wifi_scan_start(void)
{
    wifi_scan_config_t scan = {
        .show_hidden = false,
    };
    esp_err_t err = esp_wifi_scan_start(&scan, true);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "scan failed: %s", esp_err_to_name(err));
        return err;
    }

    s_scan_count = sizeof(s_scan_results) / sizeof(s_scan_results[0]);
    return esp_wifi_scan_get_ap_records(&s_scan_count, s_scan_results);
}

int meshvpn_wifi_scan_get_count(void)
{
    return (int)s_scan_count;
}

esp_err_t meshvpn_wifi_scan_get_entry(int index, wifi_ap_record_t *rec)
{
    if (index < 0 || index >= (int)s_scan_count) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(rec, &s_scan_results[index], sizeof(*rec));
    return ESP_OK;
}

void meshvpn_wifi_get_status(meshvpn_wifi_status_t *status)
{
    memset(status, 0, sizeof(*status));
    status->sta_connected = s_sta_connected;
    status->setup_mode = !s_sta_configured;
    status->ap_active = false;
    status->rssi = s_rssi;
    status->disconnect_reason = s_disconnect_reason;
    strncpy(status->ssid, s_ssid, sizeof(status->ssid) - 1);
    strncpy(status->ip, s_ip, sizeof(status->ip) - 1);

    if (s_sta_connected) {
        wifi_ap_record_t ap;
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
            status->rssi = ap.rssi;
            s_rssi = ap.rssi;
        }
    }
}
