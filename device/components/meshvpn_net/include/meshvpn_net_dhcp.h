#pragma once

#include "esp_netif.h"

/* Restore LAN gateway DNS without discarding leases on a running server whose
 * options already match. Also configures/starts a stopped LAN after IP changes. */
esp_err_t meshvpn_net_apply_lan_dhcp(esp_netif_t *netif);
