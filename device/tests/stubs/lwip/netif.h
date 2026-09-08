#pragma once
#include <stdint.h>
typedef struct { uint32_t addr; } ip4_addr_t;
struct netif { struct netif *next; ip4_addr_t ip; };
extern struct netif *netif_list;
#define NETIF_FOREACH(n) for ((n)=netif_list; (n); (n)=(n)->next)
#define netif_ip4_addr(n) (&(n)->ip)
int ip4_addr_isbroadcast(const ip4_addr_t *ip, const struct netif *n);
