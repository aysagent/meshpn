#include "meshvpn_vpn_profile.h"
#include <string.h>

static bool ipv4_valid(const char *s)
{
    for (unsigned part = 0; part < 4; part++) {
        const char *start = s;
        unsigned n = 0;
        while (*s >= '0' && *s <= '9') {
            n = n * 10 + (unsigned)(*s++ - '0');
            if (s - start > 3 || n > 255) return false;
        }
        if (s == start || (s - start > 1 && *start == '0')) return false;
        if (part < 3) { if (*s++ != '.') return false; }
        else if (*s) return false;
    }
    return true;
}
static bool hex(char c)
{ return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
/* Validate IPv6 even in firmware builds where lwIP IPv6 is compiled out. */
static bool ipv6_valid(const char *s)
{
    unsigned groups = 0;
    bool compressed = false;
    if (*s == ':') {
        if (s[1] != ':') return false;
        compressed = true; s += 2;
        if (!*s) return true;
    }
    while (*s) {
        const char *start = s;
        while (hex(*s)) s++;
        if (*s == '.') { /* optional final embedded IPv4 consumes two groups */
            if (!ipv4_valid(start)) return false;
            groups += 2;
            return compressed ? groups < 8 : groups == 8;
        }
        if (s == start || s - start > 4 || ++groups > 8) return false;
        if (!*s) break;
        if (*s++ != ':') return false;
        if (*s == ':') {
            if (compressed) return false;
            compressed = true; s++;
            if (!*s) break;
        } else if (!*s) return false;
    }
    return compressed ? groups < 8 : groups == 8;
}
static bool space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
bool meshvpn_vpn_profile_address(const char *value, char ipv4[16])
{
    if (!value || !ipv4) return false;
    size_t size = 0;
    while (size < 160 && value[size]) size++;
    if (size == 160) return false;
    char selected[16] = {0};
    const char *p = value;
    for (;;) {
        while (space(*p)) p++;
        const char *start = p;
        while (*p && *p != ',') p++;
        const char *end = p;
        while (end > start && space(end[-1])) end--;
        size_t len = (size_t)(end - start);
        char token[64];
        if (!len || len >= sizeof(token)) return false;
        memcpy(token, start, len); token[len] = 0;
        bool v6 = strchr(token, ':') != NULL;
        char *prefix = strchr(token, '/');
        if (prefix) {
            *prefix++ = 0;
            unsigned n = 0, digits = 0;
            while (*prefix >= '0' && *prefix <= '9') {
                n = n * 10 + (unsigned)(*prefix++ - '0');
                if (++digits > 3) return false;
            }
            if (!digits || *prefix || n > (v6 ? 128u : 32u)) return false;
        }
        if (v6) { if (!ipv6_valid(token)) return false; }
        else {
            if (selected[0] || !ipv4_valid(token)) return false;
            memcpy(selected, token, strlen(token) + 1);
        }
        if (!*p) break;
        p++;
    }
    if (!selected[0]) return false; /* IPv6-only is unsupported */
    memcpy(ipv4, selected, sizeof(selected));
    return true;
}
