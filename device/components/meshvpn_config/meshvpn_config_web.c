#include "meshvpn_config.h"
#include "nvs.h"
#include "sdkconfig.h"

static esp_err_t load_bool(const char *key, bool default_value, bool *enabled)
{
    if (!enabled) return ESP_ERR_INVALID_ARG;
    *enabled = default_value;
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("meshvpn", NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    uint8_t value = 0;
    err = nvs_get_u8(nvs, key, &value);
    nvs_close(nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    if (value > 1) return ESP_ERR_INVALID_ARG;
    *enabled = value != 0;
    return ESP_OK;
}

static esp_err_t save_bool(const char *key, bool enabled)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("meshvpn", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_u8(nvs, key, enabled ? 1 : 0);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

esp_err_t meshvpn_config_load_https(bool *enabled)
{
#if CONFIG_MESHVPN_WEB_HTTPS
    return load_bool("web_https", true, enabled);
#else
    return load_bool("web_https", false, enabled);
#endif
}
esp_err_t meshvpn_config_save_https(bool enabled)
{
    return save_bool("web_https", enabled);
}
esp_err_t meshvpn_config_load_user_led(bool *enabled)
{
    return load_bool("user_led", true, enabled);
}
esp_err_t meshvpn_config_save_user_led(bool enabled)
{
    return save_bool("user_led", enabled);
}
