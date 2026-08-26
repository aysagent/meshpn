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
#define MESHVPN_VPN_PUBLIC_NAME_MAX 128
#define MESHVPN_VPN_PROFILE_MAX 64
#define MESHVPN_VPN_TRANSPORT_MAX 32

typedef struct {
    char ssid[MESHVPN_WIFI_SSID_MAX + 1];
    char password[MESHVPN_WIFI_PASS_MAX + 1];
    bool configured;
} meshvpn_wifi_creds_t;

typedef struct {
    char server[MESHVPN_VPN_SERVER_MAX + 1];
    char tls_server_name[MESHVPN_VPN_SNI_MAX + 1];
    char tls_public_name[MESHVPN_VPN_PUBLIC_NAME_MAX + 1];
    char transport[MESHVPN_VPN_TRANSPORT_MAX + 1];
    char profile_name[MESHVPN_VPN_PROFILE_MAX + 1];
    uint8_t http_vers; /* 2 = HTTP/2 (default), 1 = HTTP/1.1 */
    bool ja3_strict;
    bool enabled;
} meshvpn_vpn_config_t;

esp_err_t meshvpn_config_init(void);

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
