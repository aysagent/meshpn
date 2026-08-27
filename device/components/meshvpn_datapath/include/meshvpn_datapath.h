#pragma once

#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t meshvpn_datapath_init(void);
esp_err_t meshvpn_datapath_ensure_init(void);

/** Queue IPv4 packet from LAN hook (copies data). */
esp_err_t meshvpn_datapath_submit_ipv4(const uint8_t *pkt, uint16_t len);

#ifdef __cplusplus
}
#endif
