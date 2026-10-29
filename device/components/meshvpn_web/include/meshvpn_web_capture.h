#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
typedef struct {
 uint32_t ticket;
 uint16_t port;
 bool active, saved, reused;
 char state[20], host[80], profile_id[32], detail[128];
} meshvpn_capture_status_t;
/* Called only by the authenticated HTTP task. IPv4 addresses in network order.
 * The temporary listener binds to local_ip and accepts only peer_ip.
 * Poll commits a validated candidate on that same internal HTTP task (NVS). */
esp_err_t meshvpn_web_capture_start(uint32_t local_ip,uint32_t peer_ip,const char *host,
                                   const char *name,meshvpn_capture_status_t *out);
esp_err_t meshvpn_web_capture_poll(uint32_t ticket,meshvpn_capture_status_t *out);
esp_err_t meshvpn_web_capture_cancel(uint32_t ticket);
