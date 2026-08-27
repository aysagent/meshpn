#include "meshvpn_storage.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "esp_log.h"
#include "esp_spiffs.h"
#include "sdkconfig.h"

static const char *TAG = "meshvpn_storage";
static bool s_mounted;

static bool file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

#if CONFIG_MESHVPN_STORAGE_EMBED_TEST_CERTS
extern const uint8_t _binary_ca_pem_start[] asm("_binary_ca_pem_start");
extern const uint8_t _binary_ca_pem_end[] asm("_binary_ca_pem_end");
extern const uint8_t _binary_clean_vpn_hmac_key_start[] asm("_binary_clean_vpn_hmac_key_start");
extern const uint8_t _binary_clean_vpn_hmac_key_end[] asm("_binary_clean_vpn_hmac_key_end");
extern const uint8_t _binary_browser_json_start[] asm("_binary_browser_json_start");
extern const uint8_t _binary_browser_json_end[] asm("_binary_browser_json_end");

static esp_err_t install_embedded_if_missing(const char *path, const uint8_t *start, const uint8_t *end,
                                             const char *label)
{
    if (file_exists(path)) {
        return ESP_OK;
    }

    size_t len = (size_t)(end - start);
    if (len == 0) {
        ESP_LOGW(TAG, "embedded %s is empty", label);
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t err = meshvpn_storage_write_file(path, start, len);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "installed default %s (%u bytes)", label, (unsigned)len);
    } else {
        ESP_LOGE(TAG, "failed to install default %s", label);
    }
    return err;
}

static void install_embedded_defaults(void)
{
    install_embedded_if_missing(MESHVPN_STORAGE_CA_PATH, _binary_ca_pem_start, _binary_ca_pem_end, "CA");
    install_embedded_if_missing(MESHVPN_STORAGE_PSK_PATH, _binary_clean_vpn_hmac_key_start,
                                _binary_clean_vpn_hmac_key_end, "HMAC key");

    char profile_path[128];
    snprintf(profile_path, sizeof(profile_path), "%s/browser.json", MESHVPN_STORAGE_PROFILES_DIR);
    install_embedded_if_missing(profile_path, _binary_browser_json_start, _binary_browser_json_end,
                                "browser profile");
}
#endif

esp_err_t meshvpn_storage_init(void)
{
    if (s_mounted) {
        return ESP_OK;
    }

    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/storage",
        .partition_label = "storage",
        .max_files = 16,
        .format_if_mount_failed = true,
    };

    esp_err_t err = esp_vfs_spiffs_register(&conf);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "SPIFFS mount failed: %s (check partition table was flashed)", esp_err_to_name(err));
        return err;
    }

    struct stat st;
    if (stat(MESHVPN_STORAGE_PROFILES_DIR, &st) != 0) {
        mkdir(MESHVPN_STORAGE_PROFILES_DIR, 0755);
    }

#if CONFIG_MESHVPN_STORAGE_EMBED_TEST_CERTS
    install_embedded_defaults();
#endif

    s_mounted = true;
    size_t total = 0;
    size_t used = 0;
    esp_spiffs_info(NULL, &total, &used);
    ESP_LOGI(TAG, "SPIFFS mounted: %u / %u bytes used", (unsigned)used, (unsigned)total);
    return ESP_OK;
}

bool meshvpn_storage_has_ca(void)
{
    return s_mounted && file_exists(MESHVPN_STORAGE_CA_PATH);
}

bool meshvpn_storage_has_psk(void)
{
    return s_mounted && file_exists(MESHVPN_STORAGE_PSK_PATH);
}

esp_err_t meshvpn_storage_write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        return ESP_FAIL;
    }
    size_t n = fwrite(data, 1, len, f);
    fclose(f);
    return n == len ? ESP_OK : ESP_FAIL;
}

esp_err_t meshvpn_storage_read_file(const char *path, uint8_t *buf, size_t buflen, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        return ESP_ERR_NOT_FOUND;
    }
    size_t n = fread(buf, 1, buflen, f);
    fclose(f);
    if (out_len) {
        *out_len = n;
    }
    return ESP_OK;
}

esp_err_t meshvpn_storage_write_ca(const uint8_t *data, size_t len)
{
    return meshvpn_storage_write_file(MESHVPN_STORAGE_CA_PATH, data, len);
}

esp_err_t meshvpn_storage_write_psk(const uint8_t *data, size_t len)
{
    return meshvpn_storage_write_file(MESHVPN_STORAGE_PSK_PATH, data, len);
}

esp_err_t meshvpn_storage_load_psk(uint8_t *buf, size_t buflen, size_t *out_len)
{
    return meshvpn_storage_read_file(MESHVPN_STORAGE_PSK_PATH, buf, buflen, out_len);
}

esp_err_t meshvpn_storage_write_profile(const char *name, const uint8_t *data, size_t len)
{
    char path[128];
    snprintf(path, sizeof(path), "%s/%s.json", MESHVPN_STORAGE_PROFILES_DIR, name);
    return meshvpn_storage_write_file(path, data, len);
}

esp_err_t meshvpn_storage_delete_profile(const char *name)
{
    char path[128];
    snprintf(path, sizeof(path), "%s/%s.json", MESHVPN_STORAGE_PROFILES_DIR, name);
    return remove(path) == 0 ? ESP_OK : ESP_FAIL;
}

int meshvpn_storage_list_profiles(char names[][32], int max_names, size_t name_len)
{
    DIR *d = opendir(MESHVPN_STORAGE_PROFILES_DIR);
    if (!d) {
        return 0;
    }

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && count < max_names) {
        size_t nlen = strlen(ent->d_name);
        if (nlen < 6 || strcmp(ent->d_name + nlen - 5, ".json") != 0) {
            continue;
        }
        strncpy(names[count], ent->d_name, name_len - 1);
        names[count][name_len - 1] = '\0';
        char *dot = strrchr(names[count], '.');
        if (dot) {
            *dot = '\0';
        }
        count++;
    }
    closedir(d);
    return count;
}
