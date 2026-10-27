#include "meshvpn_config.h"
#include "nvs.h"

esp_err_t meshvpn_config_load_hostname(char out[MESHVPN_HOSTNAME_MAX + 1])
{
    if (!out) return ESP_ERR_INVALID_ARG;
    strcpy(out, MESHVPN_HOSTNAME_DEFAULT);
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("meshvpn", NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    char value[MESHVPN_HOSTNAME_MAX + 1]; size_t len = sizeof(value);
    err = nvs_get_str(nvs, "hostname", value, &len);
    nvs_close(nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    return meshvpn_hostname_normalize(value, out) ? ESP_OK : ESP_ERR_INVALID_ARG;
}

esp_err_t meshvpn_config_save_hostname(const char *input)
{
    char name[MESHVPN_HOSTNAME_MAX + 1];
    if (!meshvpn_hostname_normalize(input, name)) return ESP_ERR_INVALID_ARG;
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("meshvpn", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_str(nvs, "hostname", name);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}
