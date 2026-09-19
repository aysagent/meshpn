#include "meshvpn_wg_json.h"
#include "meshvpn_wg_diag.h"
#include <stdbool.h>

static void direction(cJSON *root, const char *name, const meshvpn_wg_crypto_direction_t *d)
{
    cJSON *o = cJSON_AddObjectToObject(root, name);
#define FIELD(n) cJSON_AddNumberToObject(o, #n, (double)d->n)
    FIELD(calls); FIELD(bytes); FIELD(time_us); FIELD(max_us); FIELD(failed);
#undef FIELD
    if (d->calls) cJSON_AddNumberToObject(o, "mean_us", (double)d->time_us / d->calls);
    else cJSON_AddNullToObject(o, "mean_us");
    cJSON *cores = cJSON_AddArrayToObject(o, "core_calls");
    for (unsigned c = 0; c < 2; c++) cJSON_AddItemToArray(cores, cJSON_CreateNumber(d->core_calls[c]));
}
void meshvpn_wg_crypto_json(cJSON *wireguard)
{
    meshvpn_wg_crypto_stats_t s;
    meshvpn_wg_crypto_snapshot(&s);
    cJSON *o = cJSON_AddObjectToObject(wireguard, "crypto");
    cJSON_AddBoolToObject(o, "available", true);
    cJSON_AddStringToObject(o, "scope", "since boot; transport data + keepalive, not handshake; elapsed includes preemption; bytes exclude tag, include padding and failed attempts");
    cJSON_AddNumberToObject(o, "sampled_us", (double)s.sampled_us);
    direction(o, "encrypt", &s.encrypt);
    direction(o, "decrypt", &s.decrypt);
}
