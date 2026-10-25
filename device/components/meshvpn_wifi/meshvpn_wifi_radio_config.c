#include "meshvpn_wifi_radio.h"
#include "esp_log.h"
#include "sdkconfig.h"

esp_err_t meshvpn_wifi_radio_configure(wifi_interface_t ifx)
{
#if CONFIG_IDF_TARGET_ESP32P4
    /* C6 802.11ax uses HE20; HT40 can demote the shared APSTA radio to 11n. */
    esp_err_t err = esp_wifi_set_bandwidth(ifx, WIFI_BW_HT20);
    if (err != ESP_OK) return err;
    const uint8_t legacy = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N;
    err = esp_wifi_set_protocol(ifx, legacy | WIFI_PROTOCOL_11AX);
    if (err == ESP_ERR_NOT_SUPPORTED || err == ESP_ERR_INVALID_ARG) {
        ESP_LOGW("meshvpn_wifi", "if=%d C6 rejected b/g/n/ax (%s); using b/g/n HT20",
                 (int)ifx, esp_err_to_name(err));
        return esp_wifi_set_protocol(ifx, legacy);
    }
    return err;
#else
    return esp_wifi_set_bandwidth(ifx, WIFI_BW_HT40);
#endif
}
