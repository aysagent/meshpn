#include "meshvpn_boringssl.h"
#include "meshvpn_storage.h"
#include "meshvpn_vpn_internal.h"

#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_tls.h"

static const char *TAG = "meshvpn_boring";

esp_err_t meshvpn_vpn_boring_connect(const meshvpn_vpn_config_t *cfg, int *out_sock, esp_tls_t **out_tls,
                                     char *last_error, size_t last_error_len)
{
    if (!cfg->profile_name[0]) {
        snprintf(last_error, last_error_len, "boring-tls: select profile");
        return ESP_ERR_INVALID_ARG;
    }

    char path[160];
    snprintf(path, sizeof(path), "%s/%s.json", MESHVPN_STORAGE_PROFILES_DIR, cfg->profile_name);

    uint8_t buf[16384];
    size_t len = 0;
    if (meshvpn_storage_read_file(path, buf, sizeof(buf) - 1, &len) != ESP_OK) {
        snprintf(last_error, last_error_len, "profile not found");
        return ESP_ERR_NOT_FOUND;
    }
    buf[len] = '\0';

    cJSON *root = cJSON_Parse((const char *)buf);
    if (!root) {
        snprintf(last_error, last_error_len, "invalid profile JSON");
        return ESP_ERR_INVALID_ARG;
    }

    const cJSON *ja3 = cJSON_GetObjectItem(root, "ja3_md5");
    const cJSON *ja4 = cJSON_GetObjectItem(cJSON_GetObjectItem(root, "ja4"), "fingerprint");
    if (cJSON_IsString(ja3)) {
        ESP_LOGI(TAG, "profile %s ja3_md5=%s", cfg->profile_name, ja3->valuestring);
    }
    if (cJSON_IsString(ja4)) {
        ESP_LOGI(TAG, "profile %s ja4=%s", cfg->profile_name, ja4->valuestring);
    }

    cJSON_Delete(root);

    meshvpn_boringssl_apply_profile(cfg, NULL);

    ESP_LOGI(TAG, "boring-tls profile %s (strict=%d)", cfg->profile_name, cfg->ja3_strict);
    return meshvpn_vpn_tls_handshake(cfg, out_sock, out_tls, last_error, last_error_len);
}
