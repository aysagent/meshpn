#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "meshvpn_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool implemented;
    bool connected;
    bool enabled;
    char server[MESHVPN_VPN_SERVER_MAX + 1];
    char transport[32];
    char state[24];
    int last_error;
    uint32_t generation, reconnects, packets_in, packets_out;
    uint32_t queue_full, queue_expired, rx_invalid, rx_dropped, tx_dropped;
    uint32_t queue_depth, queue_high_water;
    uint64_t bytes_in;
    uint64_t bytes_out;
} meshvpn_vpn_status_t;

esp_err_t meshvpn_vpn_init(void);
esp_err_t meshvpn_vpn_validate_config(const meshvpn_vpn_config_t *cfg);
esp_err_t meshvpn_vpn_start(const meshvpn_vpn_config_t *cfg);
esp_err_t meshvpn_vpn_stop(void);
bool meshvpn_vpn_is_connected(void);

esp_err_t meshvpn_vpn_send_ipv4(const uint8_t *pkt, uint16_t len);
esp_err_t meshvpn_vpn_recv_ipv4(uint8_t *pkt, uint16_t maxlen, uint16_t *out_len);

void meshvpn_vpn_get_status(meshvpn_vpn_status_t *status);
/* lwIP core only, called by project hooks. */
struct netif;
struct pbuf;
struct ip4_addr;
void meshvpn_vpn_set_lan(struct netif *usb, struct netif *ap);
struct netif *meshvpn_vpn_route(const struct ip4_addr *src, const struct ip4_addr *dst);
int meshvpn_vpn_input(struct pbuf *, struct netif *);
/* DNS proxy: select and bind its egress, never silently use STA in VPN mode. */
int meshvpn_vpn_dns_socket(int fd, uint32_t *resolver_address);

#ifdef __cplusplus
}
#endif
