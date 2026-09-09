#pragma once

#include <stdint.h>

struct pbuf;
struct netif;

int meshvpn_hook_ip4_input(struct pbuf *p, struct netif *inp);
uint32_t meshvpn_net_lan_ip4_rx_count(void);
uint32_t meshvpn_net_denied_count(void);
void meshvpn_net_set_usb_interface(struct netif *netif);
void meshvpn_net_set_ap_interface(struct netif *netif);
uint32_t meshvpn_net_ap_ip4_rx_count(void);
int meshvpn_hook_ip6_input(struct pbuf *p, struct netif *inp);

#define LWIP_HOOK_IP4_INPUT meshvpn_hook_ip4_input
#define LWIP_HOOK_IP6_INPUT meshvpn_hook_ip6_input
