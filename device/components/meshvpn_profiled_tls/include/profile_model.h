#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "meshvpn_profiled_tls.h"
#define MESHPN_PROFILE_JSON_MAX 4096
#define MESHPN_PROFILE_SLOTS 4
/* Fixed-size, versioned structural profile. Never stores browser random/key material. */
typedef struct { uint16_t values[32]; uint8_t count; } meshpn_profile_ids_t;
typedef struct {
 uint32_t version;
 char id[32], name[65], ja3[33], ja4[37];
 meshpn_profile_ids_t ciphers, groups, shares, signatures, extensions;
 bool grease, http1;
} meshpn_tls_profile_t;
static const meshpn_tls_profile_t meshpn_builtin_profile = {
 1, "chromium156-capture1", "Chromium 156 — capture #1",
 "ed63604b6e93c62437468be3f6b387c3", "t13d1517h2_8daaf6152771_cb7bf5808d99",
 {{4865,4866,4867,49195,49199,49196,49200,52393,52392,49171,49172,156,157,47,53},15},
 {{4588,29,23,24},4}, {{4588,29},2},
 {{2308,2309,2310,1027,2052,1025,1283,2053,1281,2054,1537},11},
 {{5,23,43,35,65281,17613,51764,13,0,11,45,27,16,65037,10,18,51},17}, true,true
};
#ifdef __cplusplus
extern "C" {
#endif
struct cJSON;
bool meshpn_profile_json_text_safe(const char *text, size_t length);
bool meshpn_profile_parse(const struct cJSON *json, meshpn_tls_profile_t *out);
bool meshpn_profile_valid(const meshpn_tls_profile_t *p);
/* Must run on the PSRAM worker in firmware. No network I/O. Input must pass meshpn_profile_valid first. */
bool meshpn_profile_preview(const meshpn_tls_profile_t *p, meshvpn_profile_check_t *actual);
#ifdef __cplusplus
}
#endif
