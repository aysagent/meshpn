#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static inline bool meshvpn_session_valid(const char *token, const char *auth,
                                        int64_t created, int64_t used, int64_t now)
{
    if (!token || !auth || strlen(token) != 32 || strlen(auth) != 39 ||
        memcmp(auth, "Bearer ", 7) || now < created || now < used ||
        now - created >= 8LL * 3600 * 1000000 || now - used >= 30LL * 60 * 1000000)
        return false;
    unsigned diff = 0;
    for (unsigned i = 0; i < 32; i++) diff |= (unsigned char)auth[i + 7] ^ (unsigned char)token[i];
    return diff == 0;
}
