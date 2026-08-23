#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "meshvpn_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool connected;
    bool enabled;
    char server[128];
    uint64_t bytes_in;
    uint64_t bytes_out;
} meshvpn_vpn_status_t;

esp_err_t meshvpn_vpn_init(void);
esp_err_t meshvpn_vpn_start(const meshvpn_vpn_config_t *cfg);
esp_err_t meshvpn_vpn_stop(void);
bool meshvpn_vpn_is_connected(void);

esp_err_t meshvpn_vpn_send_ipv4(const uint8_t *pkt, uint16_t len);
esp_err_t meshvpn_vpn_recv_ipv4(uint8_t *pkt, uint16_t maxlen, uint16_t *out_len);

void meshvpn_vpn_get_status(meshvpn_vpn_status_t *status);

#ifdef __cplusplus
}
#endif
