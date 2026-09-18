#pragma once
#include "meshvpn_config.h"
#include "lwip/netif.h"
/* All lifecycle/packet calls are restricted to the lwIP core thread. */
esp_err_t meshvpn_wg_validate(const meshvpn_vpn_config_t *cfg);
esp_err_t meshvpn_wg_start(const meshvpn_vpn_config_t *cfg);
void meshvpn_wg_stop(void);
struct netif *meshvpn_wg_netif(void);
bool meshvpn_wg_up(void);
uint32_t meshvpn_wg_handshake_age(void);
err_t meshvpn_wg_output(struct pbuf *p, const ip4_addr_t *dest);
bool meshvpn_wg_clock_ready(void);
