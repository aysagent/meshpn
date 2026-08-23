#pragma once

#include <stdint.h>

struct pbuf;
struct netif;

int meshvpn_hook_ip4_input(struct pbuf *p, struct netif *inp);
uint32_t meshvpn_net_lan_ip4_rx_count(void);

#define LWIP_HOOK_IP4_INPUT meshvpn_hook_ip4_input
