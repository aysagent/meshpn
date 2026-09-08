#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESHVPN_WIFI_SSID_MAX 32
#define MESHVPN_WIFI_PASS_MAX 64
#define MESHVPN_ADMIN_PASS_MAX 64
#define MESHVPN_VPN_SERVER_MAX 128
#define MESHVPN_VPN_SNI_MAX 128
#define MESHVPN_WIFI_PROFILES_MAX 16

/* Versioned single NVS blob; IDs survive reordering/deletion. */
typedef struct {
    uint32_t id;
    int16_t priority;
    uint8_t enabled;
    uint8_t hidden;
    uint8_t security; /* 0=open, 1=WPA2 personal (or WPA3 transition), 2=WPA3 */
    char ssid[33];
    char password[65];
} meshvpn_wifi_profile_t;

typedef struct {
    uint32_t version;
    uint32_t count;
    uint32_t next_id;
    meshvpn_wifi_profile_t items[MESHVPN_WIFI_PROFILES_MAX];
} meshvpn_wifi_profiles_t;

esp_err_t meshvpn_config_load_profiles(meshvpn_wifi_profiles_t *out);
esp_err_t meshvpn_config_save_profiles(const meshvpn_wifi_profiles_t *profiles);

typedef struct {
    char ssid[MESHVPN_WIFI_SSID_MAX + 1];
    char password[MESHVPN_WIFI_PASS_MAX + 1];
    bool configured;
} meshvpn_wifi_creds_t;

typedef struct {
    char server[MESHVPN_VPN_SERVER_MAX + 1];
    char tls_server_name[MESHVPN_VPN_SNI_MAX + 1];
    char transport[32];
    bool enabled;
} meshvpn_vpn_config_t;

esp_err_t meshvpn_config_init(void);

/** Increment and return the persistent boot counter (reveals reboot loops). */
uint32_t meshvpn_config_bump_boot_count(void);
uint32_t meshvpn_config_get_boot_count(void);

esp_err_t meshvpn_config_load_wifi(meshvpn_wifi_creds_t *out);
esp_err_t meshvpn_config_save_wifi(const meshvpn_wifi_creds_t *creds);
esp_err_t meshvpn_config_clear_wifi(void);
bool meshvpn_config_wifi_is_configured(void);

esp_err_t meshvpn_config_load_admin_password(char *buf, size_t buflen);
esp_err_t meshvpn_config_save_admin_password(const char *password);

esp_err_t meshvpn_config_load_vpn(meshvpn_vpn_config_t *out);
esp_err_t meshvpn_config_save_vpn(const meshvpn_vpn_config_t *cfg);

esp_err_t meshvpn_config_factory_reset(void);

#ifdef __cplusplus
}
#endif
