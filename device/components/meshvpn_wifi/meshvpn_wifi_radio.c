#include "meshvpn_wifi_radio.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "sdkconfig.h"
#if CONFIG_IDF_TARGET_ESP32P4
#include "esp_hosted.h"
#endif

static portMUX_TYPE s_radio_lock = portMUX_INITIALIZER_UNLOCKED;
static meshvpn_wifi_radio_t s_radio;

void meshvpn_wifi_radio_sample(void)
{
    static int64_t next;
    int64_t started = esp_timer_get_time();
    if (started < next) return;
    next = started + 5000000;
    meshvpn_wifi_radio_t sample = {0};
    sample.channel_error = esp_wifi_get_channel(&sample.primary, &sample.secondary);
    sample.ps_error = esp_wifi_get_ps(&sample.ps);
    for (unsigned i = 0; i < 2; i++)
        sample.bandwidth_error[i] = esp_wifi_get_bandwidth(i ? WIFI_IF_AP : WIFI_IF_STA, &sample.bandwidth[i]);
    for (unsigned i = 0; i < 2; i++)
        sample.protocol_error[i] = esp_wifi_get_protocol(i ? WIFI_IF_AP : WIFI_IF_STA, &sample.protocol[i]);
    sample.uplink_error = esp_wifi_sta_get_ap_info(&sample.uplink);
    sample.peers_error = esp_wifi_ap_get_sta_list(&sample.peers);
#if CONFIG_IDF_TARGET_ESP32P4
    /* Newer RPCs may be absent from a factory C6 image. Probe version once
     * after association, outside HTTP. Attempt PHY only if version worked;
     * latch failures so a missing handler never adds periodic 5s timeouts. */
    static bool attempted, phy_failed;
    static esp_err_t firmware_error = ESP_ERR_INVALID_STATE, phy_error = ESP_ERR_NOT_SUPPORTED;
    static esp_hosted_coprocessor_fwver_t firmware;
    if (!attempted && sample.uplink_error == ESP_OK) {
        attempted = true;
        firmware_error = esp_hosted_get_coprocessor_fwversion(&firmware);
    }
    sample.firmware_attempted = attempted;
    sample.firmware_error = firmware_error;
    sample.firmware[0] = firmware.major1;
    sample.firmware[1] = firmware.minor1;
    sample.firmware[2] = firmware.patch1;
    if (firmware_error == ESP_OK && !phy_failed && sample.uplink_error == ESP_OK) {
        phy_error = esp_wifi_sta_get_negotiated_phymode(&sample.phymode);
        if (phy_error != ESP_OK) phy_failed = true;
    }
    sample.phymode_error = sample.uplink_error != ESP_OK ? sample.uplink_error : phy_error;
#else
    sample.firmware_error = ESP_ERR_NOT_SUPPORTED;
    static bool phymode_unsupported;
    sample.phymode_error = phymode_unsupported ? ESP_ERR_NOT_SUPPORTED :
        esp_wifi_sta_get_negotiated_phymode(&sample.phymode);
    if (sample.phymode_error == ESP_ERR_NOT_SUPPORTED) phymode_unsupported = true;
#endif
    sample.sampled_us = esp_timer_get_time();
    sample.collection_us = sample.sampled_us - started;
    next = sample.sampled_us + 5000000;
    portENTER_CRITICAL(&s_radio_lock); s_radio = sample; portEXIT_CRITICAL(&s_radio_lock);
}

void meshvpn_wifi_radio_snapshot(meshvpn_wifi_radio_t *out)
{
    portENTER_CRITICAL(&s_radio_lock); *out = s_radio; portEXIT_CRITICAL(&s_radio_lock);
    if (!out->sampled_us) {
        out->channel_error = out->ps_error = out->uplink_error = out->peers_error = ESP_ERR_INVALID_STATE;
        out->bandwidth_error[0] = out->bandwidth_error[1] = ESP_ERR_INVALID_STATE;
        out->phymode_error = ESP_ERR_INVALID_STATE;
        out->protocol_error[0] = out->protocol_error[1] = ESP_ERR_INVALID_STATE;
        out->firmware_error = ESP_ERR_INVALID_STATE;
    }
}

void meshvpn_wifi_radio_summary(int8_t *rssi, uint8_t *channel, uint8_t *clients)
{
    portENTER_CRITICAL(&s_radio_lock);
    if (rssi) *rssi = s_radio.sampled_us && s_radio.uplink_error == ESP_OK ? s_radio.uplink.rssi : 0;
    if (channel) *channel = s_radio.sampled_us && s_radio.channel_error == ESP_OK ? s_radio.primary : 0;
    if (clients) *clients = s_radio.sampled_us && s_radio.peers_error == ESP_OK ? s_radio.peers.num : 0;
    portEXIT_CRITICAL(&s_radio_lock);
}
