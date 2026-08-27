#include "meshvpn_config.h"

#include <string.h>

#include "nvs.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "sdkconfig.h"

static const char *TAG = "meshvpn_config";
static const char *NS = "meshvpn";

static nvs_handle_t s_nvs;

esp_err_t meshvpn_config_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS erase required (%s) — WiFi/VPN settings reset once",
                 esp_err_to_name(err));
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    err = nvs_open(NS, NVS_READWRITE, &s_nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "config ready");
    return ESP_OK;
}

uint32_t meshvpn_config_bump_boot_count(void)
{
    uint32_t count = 0;
    nvs_get_u32(s_nvs, "boot_count", &count);
    count++;
    if (nvs_set_u32(s_nvs, "boot_count", count) == ESP_OK) {
        nvs_commit(s_nvs);
    }
    return count;
}

uint32_t meshvpn_config_get_boot_count(void)
{
    uint32_t count = 0;
    nvs_get_u32(s_nvs, "boot_count", &count);
    return count;
}

bool meshvpn_config_wifi_is_configured(void)
{
    uint8_t flag = 0;
    if (nvs_get_u8(s_nvs, "wifi_ok", &flag) != ESP_OK) {
        return false;
    }
    return flag != 0;
}

esp_err_t meshvpn_config_load_wifi(meshvpn_wifi_creds_t *out)
{
    memset(out, 0, sizeof(*out));
    out->configured = meshvpn_config_wifi_is_configured();
    if (!out->configured) {
        return ESP_OK;
    }

    size_t len = sizeof(out->ssid);
    esp_err_t err = nvs_get_str(s_nvs, "wifi_ssid", out->ssid, &len);
    if (err != ESP_OK) {
        out->configured = false;
        return err;
    }
    len = sizeof(out->password);
    err = nvs_get_str(s_nvs, "wifi_pass", out->password, &len);
    if (err != ESP_OK) {
        out->configured = false;
        return err;
    }
    return ESP_OK;
}

esp_err_t meshvpn_config_save_wifi(const meshvpn_wifi_creds_t *creds)
{
    esp_err_t err = nvs_set_str(s_nvs, "wifi_ssid", creds->ssid);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_str(s_nvs, "wifi_pass", creds->password);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_u8(s_nvs, "wifi_ok", 1);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_commit(s_nvs);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "WiFi saved: %.32s", creds->ssid);
    }
    return err;
}

esp_err_t meshvpn_config_clear_wifi(void)
{
    nvs_erase_key(s_nvs, "wifi_ssid");
    nvs_erase_key(s_nvs, "wifi_pass");
    nvs_erase_key(s_nvs, "wifi_ok");
    return nvs_commit(s_nvs);
}

esp_err_t meshvpn_config_load_admin_password(char *buf, size_t buflen)
{
    size_t len = buflen;
    esp_err_t err = nvs_get_str(s_nvs, "admin_pass", buf, &len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        strncpy(buf, CONFIG_MESHVPN_WEB_ADMIN_PASSWORD_DEFAULT, buflen - 1);
        buf[buflen - 1] = '\0';
        return ESP_OK;
    }
    return err;
}

esp_err_t meshvpn_config_save_admin_password(const char *password)
{
    ESP_ERROR_CHECK(nvs_set_str(s_nvs, "admin_pass", password));
    return nvs_commit(s_nvs);
}

esp_err_t meshvpn_config_load_vpn(meshvpn_vpn_config_t *out)
{
    memset(out, 0, sizeof(*out));
    strncpy(out->transport, "tls", sizeof(out->transport) - 1);
    out->http_vers = 2;

    size_t len = sizeof(out->server);
    if (nvs_get_str(s_nvs, "vpn_server", out->server, &len) != ESP_OK) {
        out->server[0] = '\0';
    }
    len = sizeof(out->tls_server_name);
    if (nvs_get_str(s_nvs, "vpn_sni", out->tls_server_name, &len) != ESP_OK) {
        out->tls_server_name[0] = '\0';
    }
    len = sizeof(out->tls_public_name);
    if (nvs_get_str(s_nvs, "vpn_pubname", out->tls_public_name, &len) != ESP_OK) {
        out->tls_public_name[0] = '\0';
    }
    len = sizeof(out->transport);
    if (nvs_get_str(s_nvs, "vpn_transport", out->transport, &len) != ESP_OK) {
        strncpy(out->transport, "tls", sizeof(out->transport) - 1);
    }
    len = sizeof(out->profile_name);
    if (nvs_get_str(s_nvs, "vpn_profile", out->profile_name, &len) != ESP_OK) {
        strncpy(out->profile_name, "browser", sizeof(out->profile_name) - 1);
    }
    uint8_t en = 0;
    nvs_get_u8(s_nvs, "vpn_en", &en);
    out->enabled = en != 0;
    uint8_t hv = 2;
    nvs_get_u8(s_nvs, "vpn_http", &hv);
    out->http_vers = hv == 1 ? 1 : 2;
    uint8_t strict = 0;
    nvs_get_u8(s_nvs, "vpn_ja3s", &strict);
    out->ja3_strict = strict != 0;
    return ESP_OK;
}

esp_err_t meshvpn_config_save_vpn(const meshvpn_vpn_config_t *cfg)
{
    ESP_ERROR_CHECK(nvs_set_str(s_nvs, "vpn_server", cfg->server));
    ESP_ERROR_CHECK(nvs_set_str(s_nvs, "vpn_sni", cfg->tls_server_name));
    ESP_ERROR_CHECK(nvs_set_str(s_nvs, "vpn_pubname", cfg->tls_public_name));
    ESP_ERROR_CHECK(nvs_set_str(s_nvs, "vpn_transport", cfg->transport));
    ESP_ERROR_CHECK(nvs_set_str(s_nvs, "vpn_profile", cfg->profile_name));
    ESP_ERROR_CHECK(nvs_set_u8(s_nvs, "vpn_en", cfg->enabled ? 1 : 0));
    ESP_ERROR_CHECK(nvs_set_u8(s_nvs, "vpn_http", cfg->http_vers));
    ESP_ERROR_CHECK(nvs_set_u8(s_nvs, "vpn_ja3s", cfg->ja3_strict ? 1 : 0));
    return nvs_commit(s_nvs);
}

esp_err_t meshvpn_config_factory_reset(void)
{
    ESP_LOGW(TAG, "factory reset — erasing NVS");
    nvs_erase_all(s_nvs);
    nvs_commit(s_nvs);
    nvs_close(s_nvs);
    s_nvs = 0;
    return nvs_flash_erase();
}
