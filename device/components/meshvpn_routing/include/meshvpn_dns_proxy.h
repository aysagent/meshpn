#pragma once

#include <stdint.h>

#include "esp_err.h"
#include "meshvpn_routing.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t queries;
    uint32_t captive;
    uint32_t forwarded;
    uint32_t forward_fail;
    uint32_t errors;
    uint32_t hijacked;
    uint32_t cache_hits;
} meshvpn_dns_stats_t;

/** Start bounded UDP/TCP DNS proxy on port 53 with local names and TTL cache. */
esp_err_t meshvpn_dns_proxy_init(void);

void meshvpn_dns_get_stats(meshvpn_dns_stats_t *out);
void meshvpn_dns_clear_cache(void);

void meshvpn_dns_count_hijack(void);

/** Reserved for phase-2 domain routing hook. */
esp_err_t meshvpn_dns_proxy_handle_query(const uint8_t *pkt, uint16_t len);

#ifdef __cplusplus
}
#endif
