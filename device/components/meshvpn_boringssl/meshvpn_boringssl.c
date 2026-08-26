#include "meshvpn_boringssl.h"
#include "meshvpn_storage.h"

#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "esp_err.h"
#include "esp_log.h"

static const char *TAG = "meshvpn_boringssl";

esp_err_t meshvpn_boringssl_apply_profile(const meshvpn_vpn_config_t *cfg, void *tls_cfg)
{
    (void)tls_cfg;
    if (!cfg->profile_name[0]) {
        return ESP_ERR_INVALID_ARG;
    }

    char path[160];
    snprintf(path, sizeof(path), "%s/%s.json", MESHVPN_STORAGE_PROFILES_DIR, cfg->profile_name);
    uint8_t buf[8192];
    size_t len = 0;
    if (meshvpn_storage_read_file(path, buf, sizeof(buf) - 1, &len) != ESP_OK) {
        return ESP_ERR_NOT_FOUND;
    }
    buf[len] = '\0';

    cJSON *root = cJSON_Parse((const char *)buf);
    if (!root) {
        return ESP_ERR_INVALID_ARG;
    }

    const cJSON *ciphers = cJSON_GetObjectItem(root, "cipher_suites");
    const cJSON *groups = cJSON_GetObjectItem(root, "supported_groups");
    int nc = cJSON_IsArray(ciphers) ? cJSON_GetArraySize(ciphers) : 0;
    int ng = cJSON_IsArray(groups) ? cJSON_GetArraySize(groups) : 0;
    ESP_LOGI(TAG, "profile %s: %d ciphers, %d groups (mbedTLS preset)", cfg->profile_name, nc, ng);
    cJSON_Delete(root);
    return ESP_OK;
}
