#include "meshvpn_config.h"

#include <string.h>
#include <ctype.h>

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
    if (err != ESP_OK) { out->configured = false; return err; }
    len = sizeof(out->password);
    err = nvs_get_str(s_nvs, "wifi_pass", out->password, &len);
    if (err != ESP_OK) out->configured = false;
    return err;
}

esp_err_t meshvpn_config_save_wifi(const meshvpn_wifi_creds_t *creds)
{
    ESP_ERROR_CHECK(nvs_set_str(s_nvs, "wifi_ssid", creds->ssid));
    ESP_ERROR_CHECK(nvs_set_str(s_nvs, "wifi_pass", creds->password));
    ESP_ERROR_CHECK(nvs_set_u8(s_nvs, "wifi_ok", 1));
    return nvs_commit(s_nvs);
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
    if (!buf || buflen == 0) return ESP_ERR_INVALID_ARG;
    memset(buf, 0, buflen);
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
    if (!password || strlen(password) < 8 || strlen(password) > MESHVPN_ADMIN_PASS_MAX)
        return ESP_ERR_INVALID_ARG;
    esp_err_t err = nvs_set_str(s_nvs, "admin_pass", password);
    if (err != ESP_OK) return err;
    return nvs_commit(s_nvs);
}

static esp_err_t validate_profiles(const meshvpn_wifi_profiles_t *p)
{
    if (!p || p->version != 1 || p->count > MESHVPN_WIFI_PROFILES_MAX || !p->next_id)
        return ESP_ERR_INVALID_ARG;
    for (unsigned i = 0; i < p->count; i++) {
        const meshvpn_wifi_profile_t *r = &p->items[i];
        if (!r->id || r->id >= p->next_id || !r->ssid[0] ||
            !memchr(r->ssid, 0, sizeof(r->ssid)) || !memchr(r->password, 0, sizeof(r->password)) ||
            r->security > 2 || r->enabled > 1 || r->hidden > 1 ||
            (r->security && (strlen(r->password) < 8 || strlen(r->password) > 64)) ||
            (!r->security && r->password[0])) return ESP_ERR_INVALID_ARG;
        if (strlen(r->password) == 64) {
            if (r->security != 1) return ESP_ERR_INVALID_ARG;
            for (unsigned j = 0; j < 64; j++)
                if (!isxdigit((unsigned char)r->password[j])) return ESP_ERR_INVALID_ARG;
        }
        for (unsigned j = 0; j < i; j++)
            if (p->items[j].id == r->id) return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}

esp_err_t meshvpn_config_save_profiles(const meshvpn_wifi_profiles_t *p)
{
    esp_err_t err = validate_profiles(p);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(s_nvs, "wifi_profiles", p, sizeof(*p));
    return err == ESP_OK ? nvs_commit(s_nvs) : err;
}

esp_err_t meshvpn_config_load_profiles(meshvpn_wifi_profiles_t *out)
{
    memset(out, 0, sizeof(*out));
    size_t len = sizeof(*out);
    esp_err_t err = nvs_get_blob(s_nvs, "wifi_profiles", out, &len);
    if (err == ESP_OK && len == sizeof(*out) && validate_profiles(out) == ESP_OK) {
        return ESP_OK;
    }
    memset(out, 0, sizeof(*out));
    out->version = 1;
    out->next_id = 1;
    if (err != ESP_ERR_NVS_NOT_FOUND) return ESP_ERR_INVALID_STATE;
    meshvpn_wifi_creds_t legacy;
    if (meshvpn_config_load_wifi(&legacy) == ESP_OK && legacy.configured && legacy.ssid[0]) {
        meshvpn_wifi_profile_t *r = &out->items[0];
        r->id = out->next_id++;
        r->enabled = 1;
        r->security = legacy.password[0] ? 1 : 0;
        memcpy(r->ssid, legacy.ssid, sizeof(r->ssid));
        memcpy(r->password, legacy.password, sizeof(r->password));
        out->count = 1;
        esp_err_t migrated = meshvpn_config_save_profiles(out);
        /* Keep the legacy copy until the new blob has committed successfully. */
        if (migrated == ESP_OK) meshvpn_config_clear_wifi();
        return migrated;
    }
    return ESP_OK;
}

esp_err_t meshvpn_config_load_vpn(meshvpn_vpn_config_t *out)
{
    memset(out, 0, sizeof(*out));
    strncpy(out->transport, "tls", sizeof(out->transport) - 1);

    size_t len = sizeof(out->server);
    if (nvs_get_str(s_nvs, "vpn_server", out->server, &len) != ESP_OK) {
        out->server[0] = '\0';
    }
    len = sizeof(out->tls_server_name);
    if (nvs_get_str(s_nvs, "vpn_sni", out->tls_server_name, &len) != ESP_OK) {
        out->tls_server_name[0] = '\0';
    }
    uint8_t en = 0;
    nvs_get_u8(s_nvs, "vpn_en", &en);
    out->enabled = en != 0;
    return ESP_OK;
}

esp_err_t meshvpn_config_save_vpn(const meshvpn_vpn_config_t *cfg)
{
    ESP_ERROR_CHECK(nvs_set_str(s_nvs, "vpn_server", cfg->server));
    ESP_ERROR_CHECK(nvs_set_str(s_nvs, "vpn_sni", cfg->tls_server_name));
    ESP_ERROR_CHECK(nvs_set_u8(s_nvs, "vpn_en", cfg->enabled ? 1 : 0));
    return nvs_commit(s_nvs);
}

esp_err_t meshvpn_config_factory_reset(void)
{
    nvs_erase_all(s_nvs);
    nvs_commit(s_nvs);
    return nvs_flash_erase();
}
