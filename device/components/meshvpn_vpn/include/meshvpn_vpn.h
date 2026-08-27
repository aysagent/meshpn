#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "meshvpn_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef esp_err_t (*meshvpn_vpn_inject_fn)(const uint8_t *pkt, uint16_t len);

typedef struct {
    bool connected;
    bool enabled;
    char server[128];
    char transport[32];
    char profile_name[64];
    char last_error[96];
    uint64_t bytes_in;
    uint64_t bytes_out;
} meshvpn_vpn_status_t;

void meshvpn_vpn_set_inject(meshvpn_vpn_inject_fn fn);

esp_err_t meshvpn_vpn_init(void);
/** Idempotent — safe before first meshvpn_vpn_start (e.g. admin save before bg init). */
esp_err_t meshvpn_vpn_ensure_init(void);
esp_err_t meshvpn_vpn_start(const meshvpn_vpn_config_t *cfg);
/** Persist is caller's job; applies cfg to the running worker. */
esp_err_t meshvpn_vpn_apply_config(const meshvpn_vpn_config_t *cfg);
esp_err_t meshvpn_vpn_stop(void);
bool meshvpn_vpn_is_connected(void);
/** True when LAN traffic should be tunneled (enabled + tunnel up). */
bool meshvpn_vpn_routes_via_tunnel(void);
bool meshvpn_vpn_is_transparent(void);
void meshvpn_vpn_transparent_note_redirect(void);

esp_err_t meshvpn_vpn_send_ipv4(const uint8_t *pkt, uint16_t len);
esp_err_t meshvpn_vpn_recv_ipv4(uint8_t *pkt, uint16_t maxlen, uint16_t *out_len);

void meshvpn_vpn_get_status(meshvpn_vpn_status_t *status);

#ifdef __cplusplus
}
#endif
