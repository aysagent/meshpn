#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MESHVPN_ROUTE_DIRECT = 0,
    MESHVPN_ROUTE_VPN,
    MESHVPN_ROUTE_BLOCK,
} meshvpn_route_action_t;

typedef enum {
    MESHVPN_RULE_IP_CIDR = 0,
    MESHVPN_RULE_DOMAIN,
    MESHVPN_RULE_GEO,
    MESHVPN_RULE_DEFAULT,
} meshvpn_rule_type_t;

typedef struct {
    meshvpn_rule_type_t type;
    meshvpn_route_action_t action;
    char match[96];
    bool enabled;
} meshvpn_route_rule_t;

esp_err_t meshvpn_routing_init(void);
esp_err_t meshvpn_routing_load(void);
esp_err_t meshvpn_routing_save(void);

int meshvpn_routing_get_rule_count(void);
esp_err_t meshvpn_routing_get_rule(int index, meshvpn_route_rule_t *rule);
esp_err_t meshvpn_routing_set_rule(int index, const meshvpn_route_rule_t *rule);
esp_err_t meshvpn_routing_add_rule(const meshvpn_route_rule_t *rule);
esp_err_t meshvpn_routing_delete_rule(int index);

meshvpn_route_action_t meshvpn_routing_classify_ipv4(uint32_t dst_be, uint32_t src_be);
void meshvpn_routing_dns_cache_domain(const char *domain, uint32_t ipv4_be, uint32_t ttl_sec);

meshvpn_route_action_t meshvpn_routing_default_action(void);
esp_err_t meshvpn_routing_set_default_action(meshvpn_route_action_t action);

#ifdef __cplusplus
}
#endif
