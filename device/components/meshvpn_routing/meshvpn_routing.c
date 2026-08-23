#include "meshvpn_routing.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "lwip/def.h"
#include "nvs.h"
#include "sdkconfig.h"

static const char *TAG = "meshvpn_routing";

typedef struct {
    uint32_t ip_be;
    meshvpn_route_action_t action;
    uint32_t expires_ms;
} meshvpn_dns_cache_entry_t;

static meshvpn_route_rule_t s_rules[CONFIG_MESHVPN_ROUTING_MAX_RULES];
static int s_rule_count;
static meshvpn_route_action_t s_default_action = MESHVPN_ROUTE_DIRECT;
static meshvpn_dns_cache_entry_t s_dns_cache[CONFIG_MESHVPN_ROUTING_MAX_DOMAINS];
static int s_dns_cache_count;

static bool meshvpn_parse_cidr(const char *cidr, uint32_t *net_be, uint32_t *mask_be)
{
    char buf[96];
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    if (!slash) {
        return false;
    }
    *slash = '\0';
    int prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) {
        return false;
    }

    uint8_t a, b, c, d;
    if (sscanf(buf, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) {
        return false;
    }

    *net_be = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
    if (prefix == 0) {
        *mask_be = 0;
    } else if (prefix == 32) {
        *mask_be = 0xFFFFFFFFu;
    } else {
        *mask_be = htonl(0xFFFFFFFFu << (32 - prefix));
    }
    return true;
}

esp_err_t meshvpn_routing_init(void)
{
    memset(s_rules, 0, sizeof(s_rules));
    s_rule_count = 0;
    s_dns_cache_count = 0;
    return meshvpn_routing_load();
}

esp_err_t meshvpn_routing_load(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("meshvpn", NVS_READONLY, &nvs);
    if (err != ESP_OK) {
        return ESP_OK;
    }

    uint8_t def = 0;
    if (nvs_get_u8(nvs, "rt_default", &def) == ESP_OK) {
        s_default_action = (meshvpn_route_action_t)def;
    }

    size_t len = sizeof(s_rules);
    if (nvs_get_blob(nvs, "rt_rules", s_rules, &len) == ESP_OK) {
        s_rule_count = (int)(len / sizeof(meshvpn_route_rule_t));
        if (s_rule_count > CONFIG_MESHVPN_ROUTING_MAX_RULES) {
            s_rule_count = CONFIG_MESHVPN_ROUTING_MAX_RULES;
        }
    }

    nvs_close(nvs);
    ESP_LOGI(TAG, "loaded %d rules, default=%d", s_rule_count, (int)s_default_action);
    return ESP_OK;
}

esp_err_t meshvpn_routing_save(void)
{
    nvs_handle_t nvs;
    ESP_ERROR_CHECK(nvs_open("meshvpn", NVS_READWRITE, &nvs));
    ESP_ERROR_CHECK(nvs_set_u8(nvs, "rt_default", (uint8_t)s_default_action));
    ESP_ERROR_CHECK(nvs_set_blob(nvs, "rt_rules", s_rules, s_rule_count * sizeof(meshvpn_route_rule_t)));
    esp_err_t err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

int meshvpn_routing_get_rule_count(void)
{
    return s_rule_count;
}

esp_err_t meshvpn_routing_get_rule(int index, meshvpn_route_rule_t *rule)
{
    if (index < 0 || index >= s_rule_count) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(rule, &s_rules[index], sizeof(*rule));
    return ESP_OK;
}

esp_err_t meshvpn_routing_set_rule(int index, const meshvpn_route_rule_t *rule)
{
    if (index < 0 || index >= s_rule_count) {
        return ESP_ERR_INVALID_ARG;
    }
    s_rules[index] = *rule;
    return meshvpn_routing_save();
}

esp_err_t meshvpn_routing_add_rule(const meshvpn_route_rule_t *rule)
{
    if (s_rule_count >= CONFIG_MESHVPN_ROUTING_MAX_RULES) {
        return ESP_ERR_NO_MEM;
    }
    s_rules[s_rule_count++] = *rule;
    return meshvpn_routing_save();
}

esp_err_t meshvpn_routing_delete_rule(int index)
{
    if (index < 0 || index >= s_rule_count) {
        return ESP_ERR_INVALID_ARG;
    }
    memmove(&s_rules[index], &s_rules[index + 1], (s_rule_count - index - 1) * sizeof(meshvpn_route_rule_t));
    s_rule_count--;
    return meshvpn_routing_save();
}

meshvpn_route_action_t meshvpn_routing_default_action(void)
{
    return s_default_action;
}

esp_err_t meshvpn_routing_set_default_action(meshvpn_route_action_t action)
{
    s_default_action = action;
    return meshvpn_routing_save();
}

void meshvpn_routing_dns_cache_domain(const char *domain, uint32_t ipv4_be, uint32_t ttl_sec)
{
    (void)domain;
    if (s_dns_cache_count >= CONFIG_MESHVPN_ROUTING_MAX_DOMAINS) {
        return;
    }
    s_dns_cache[s_dns_cache_count].ip_be = ipv4_be;
    s_dns_cache[s_dns_cache_count].action = MESHVPN_ROUTE_VPN;
    s_dns_cache[s_dns_cache_count].expires_ms = ttl_sec * 1000;
    s_dns_cache_count++;
}

meshvpn_route_action_t meshvpn_routing_classify_ipv4(uint32_t dst_be, uint32_t src_be)
{
    (void)src_be;

    for (int i = 0; i < s_dns_cache_count; i++) {
        if (s_dns_cache[i].ip_be == dst_be) {
            return s_dns_cache[i].action;
        }
    }

    for (int i = 0; i < s_rule_count; i++) {
        const meshvpn_route_rule_t *r = &s_rules[i];
        if (!r->enabled) {
            continue;
        }
        if (r->type == MESHVPN_RULE_IP_CIDR) {
            uint32_t net, mask;
            if (meshvpn_parse_cidr(r->match, &net, &mask) && ((dst_be & mask) == (net & mask))) {
                return r->action;
            }
        } else if (r->type == MESHVPN_RULE_DOMAIN || r->type == MESHVPN_RULE_GEO) {
            continue;
        } else if (r->type == MESHVPN_RULE_DEFAULT) {
            return r->action;
        }
    }

    return s_default_action;
}
