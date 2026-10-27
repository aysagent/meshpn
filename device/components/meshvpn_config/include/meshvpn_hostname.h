#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define MESHVPN_HOSTNAME_MAX 63
#define MESHVPN_HOSTNAME_DEFAULT "dongle"

/* One DNS label; accept a pasted .local name and store lowercase ASCII. */
static inline bool meshvpn_hostname_normalize(const char *input, char out[MESHVPN_HOSTNAME_MAX + 1])
{
    if (!input || !out) return false;
    char value[MESHVPN_HOSTNAME_MAX + 7];
    size_t n = 0;
    while (input[n] && n < sizeof(value) - 1) {
        unsigned char c = input[n];
        value[n++] = c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
    }
    if (input[n]) return false;
    value[n] = 0;
    if (n > 6 && !strcmp(value + n - 6, ".local")) n -= 6;
    if (!n || n > MESHVPN_HOSTNAME_MAX || value[0] == '-' || value[n-1] == '-') return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
    }
    memcpy(out, value, n); out[n] = 0;
    return true;
}

static inline bool meshvpn_hostname_local_query(const char *query, const char *label)
{
    size_t n = strlen(label);
    return !strncmp(query, label, n) &&
        (!strcmp(query + n, ".local") || !strcmp(query + n, ".home.arpa"));
}
