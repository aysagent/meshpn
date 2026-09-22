#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "meshvpn_config.h"

#ifndef CONFIG_MESHVPN_VPN_UDP_RX_BATCH_FRAMES
#define CONFIG_MESHVPN_VPN_UDP_RX_BATCH_FRAMES 32
#endif
#ifndef CONFIG_MESHVPN_VPN_UDP_RX_BATCH_US
#define CONFIG_MESHVPN_VPN_UDP_RX_BATCH_US 4000
#endif
#define MESHVPN_VPN_UDP_RX_BATCH_FRAMES CONFIG_MESHVPN_VPN_UDP_RX_BATCH_FRAMES
#define MESHVPN_VPN_UDP_RX_BATCH_US CONFIG_MESHVPN_VPN_UDP_RX_BATCH_US

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool implemented;
    bool connected;
    bool enabled;
    bool kill_switch;
    bool probe_ok;
    int probe_error;
    int64_t probe_at_us; /* zero = untested; invalidated on config/disconnect */
    char server[MESHVPN_VPN_SERVER_MAX + 1];
    char tls_server_name[MESHVPN_VPN_SNI_MAX + 1];
    char transport[32];
    char state[24];
    char address[16];
    uint32_t wg_handshake_age;
    char wg_address[16], wg_dns[16], wg_public_key[45];
    char wg_address_input[160];
    uint16_t wg_keepalive;
    bool wg_private_key_set, wg_preshared_key_set;
    int last_error;
    uint32_t generation, reconnects, packets_in, packets_out;
    uint32_t queue_full, queue_expired, rx_invalid, rx_dropped, tx_dropped;
    uint32_t queue_depth, queue_high_water;
    int socket_last_failure_error;
    char socket_last_failure_reason[24];
    int64_t socket_last_failure_us;
    uint32_t socket_last_failure_generation;
    int socket_last_tls_result, socket_last_tls_error;
    int socket_last_tls_code, socket_last_tls_flags;
    uint32_t socket_rx_timeouts, socket_tx_timeouts;
    uint32_t socket_rx_batches, socket_rx_batch_max;
    uint64_t socket_rx_inject_exec_us;
    uint32_t socket_rx_inject_exec_max_us;
    uint32_t socket_tx_batches, socket_tx_batch_max;
    uint32_t socket_send_calls, socket_send_would_block;
    uint64_t socket_send_bytes;
    uint32_t socket_tx_to_exit, socket_tx_source_tunnel, socket_tx_source_other;
    uint32_t socket_rx_from_exit, socket_rx_to_usb, socket_rx_to_ap;
    uint32_t lan_egress_usb, lan_egress_ap, lan_egress_repaired, lan_egress_invalid;
    uint32_t socket_last_tx_src, socket_last_tx_dst;
    uint32_t socket_last_rx_src, socket_last_rx_dst;
    uint32_t socket_last_return_src, socket_last_return_dst;
    uint16_t socket_last_tx_sport, socket_last_tx_dport;
    uint16_t socket_last_rx_sport, socket_last_rx_dport;
    uint8_t socket_last_tx_proto, socket_last_rx_proto;
    int64_t socket_last_tx_us, socket_last_rx_us, socket_last_return_us;
    uint64_t bytes_in;
    uint64_t bytes_out;
} meshvpn_vpn_status_t;

esp_err_t meshvpn_vpn_init(void);
esp_err_t meshvpn_vpn_validate_config(const meshvpn_vpn_config_t *cfg);
const char *meshvpn_vpn_config_error(const meshvpn_vpn_config_t *cfg);
esp_err_t meshvpn_vpn_start(const meshvpn_vpn_config_t *cfg);
esp_err_t meshvpn_vpn_stop(void);
bool meshvpn_vpn_is_connected(void);
/* Worker/HTTP task only. Bounded TCP reachability test bound to the VPN netif. */
esp_err_t meshvpn_vpn_check_internet(void);

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
/* Final mutable Ethernet-frame boundary, immediately before a LAN driver. */
void meshvpn_vpn_lan_egress(void *frame, size_t length, bool usb);
/* DNS proxy: select and bind its egress, never silently use STA in VPN mode. */
int meshvpn_vpn_dns_socket(int fd, uint32_t *resolver_address);

#ifdef __cplusplus
}
#endif
