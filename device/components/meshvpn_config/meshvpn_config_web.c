#include "meshvpn_config.h"
#include "nvs.h"
#include "sdkconfig.h"

esp_err_t meshvpn_config_load_https(bool *enabled)
{
    if (!enabled) return ESP_ERR_INVALID_ARG;
#if CONFIG_MESHVPN_WEB_HTTPS
    *enabled = true;
#else
    *enabled = false;
#endif
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("meshvpn", NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    uint8_t value = 0;
    err = nvs_get_u8(nvs, "web_https", &value);
    nvs_close(nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    if (value > 1) return ESP_ERR_INVALID_ARG;
    *enabled = value != 0;
    return ESP_OK;
}

esp_err_t meshvpn_config_save_https(bool enabled)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("meshvpn", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_u8(nvs, "web_https", enabled ? 1 : 0);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}
