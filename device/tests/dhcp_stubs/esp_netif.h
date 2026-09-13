#pragma once
#include <stdint.h>
#include "esp_err.h"
typedef struct esp_netif_obj esp_netif_t;
typedef struct { uint32_t addr; } esp_ip4_addr_t;
typedef struct { esp_ip4_addr_t ip, netmask, gw; } esp_netif_ip_info_t;
typedef struct { struct { int type; union { esp_ip4_addr_t ip4; } u_addr; } ip; } esp_netif_dns_info_t;
typedef enum { ESP_NETIF_DHCP_INIT, ESP_NETIF_DHCP_STARTED, ESP_NETIF_DHCP_STOPPED } esp_netif_dhcp_status_t;
enum { IPADDR_TYPE_V4, ESP_NETIF_DNS_MAIN, ESP_NETIF_OP_GET, ESP_NETIF_OP_SET,
       ESP_NETIF_ROUTER_SOLICITATION_ADDRESS, ESP_NETIF_DOMAIN_NAME_SERVER, ESP_NETIF_IP_ADDRESS_LEASE_TIME };
esp_err_t esp_netif_get_ip_info(esp_netif_t *, esp_netif_ip_info_t *);
esp_err_t esp_netif_dhcps_get_status(esp_netif_t *, esp_netif_dhcp_status_t *);
esp_err_t esp_netif_dhcps_option(esp_netif_t *, int, int, void *, uint32_t);
esp_err_t esp_netif_set_dns_info(esp_netif_t *, int, esp_netif_dns_info_t *);
esp_err_t esp_netif_dhcps_stop(esp_netif_t *);
esp_err_t esp_netif_dhcps_start(esp_netif_t *);
