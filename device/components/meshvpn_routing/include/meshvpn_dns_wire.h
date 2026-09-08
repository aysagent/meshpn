#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char name[256];
    uint16_t type;
    uint16_t klass;
    size_t end;
} meshvpn_dns_question_t;
bool meshvpn_dns_question(const uint8_t *pkt, size_t len, meshvpn_dns_question_t *q);
size_t meshvpn_dns_reply(const uint8_t *query, size_t len, uint8_t *out,
                        size_t cap, unsigned rcode, bool truncated, uint32_t ipv4);
/* Validate RR boundaries and age TTLs in a response copy. Zero means no cache. */
uint32_t meshvpn_dns_age_ttls(uint8_t *pkt, size_t len, uint32_t elapsed);
