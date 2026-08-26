#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESHVPN_STORAGE_CA_PATH "/storage/ca.pem"
#define MESHVPN_STORAGE_PSK_PATH "/storage/clean-vpn-hmac.key"
#define MESHVPN_STORAGE_PROFILES_DIR "/storage/profiles"

esp_err_t meshvpn_storage_init(void);
bool meshvpn_storage_has_ca(void);
bool meshvpn_storage_has_psk(void);

esp_err_t meshvpn_storage_write_file(const char *path, const uint8_t *data, size_t len);
esp_err_t meshvpn_storage_read_file(const char *path, uint8_t *buf, size_t buflen, size_t *out_len);

esp_err_t meshvpn_storage_write_ca(const uint8_t *data, size_t len);
esp_err_t meshvpn_storage_write_psk(const uint8_t *data, size_t len);

/** Load PSK into buf (max 64 bytes). Returns length written. */
esp_err_t meshvpn_storage_load_psk(uint8_t *buf, size_t buflen, size_t *out_len);

/** List profile basenames (without path) into names[][name_len]. Returns count. */
int meshvpn_storage_list_profiles(char names[][32], int max_names, size_t name_len);

esp_err_t meshvpn_storage_write_profile(const char *name, const uint8_t *data, size_t len);
esp_err_t meshvpn_storage_delete_profile(const char *name);

#ifdef __cplusplus
}
#endif
