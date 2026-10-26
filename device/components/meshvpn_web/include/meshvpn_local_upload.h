#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MESHVPN_LOCAL_UPLOAD_MAX (8U * 1024U * 1024U)
#define MESHVPN_LOCAL_UPLOAD_BUDGET_US INT64_C(30000000)

/* Discard a bounded body without retaining it. A receive timeout/error aborts;
 * do not restart the deadline for every read or count an incomplete upload. */
static inline bool meshvpn_local_upload(void *ctx, size_t length,
        int (*receive)(void *, char *, size_t), int64_t (*now)(void *), size_t *received)
{
    *received = 0;
    if (!length || length > MESHVPN_LOCAL_UPLOAD_MAX) return false;
    char block[1024];
    const int64_t deadline = now(ctx) + MESHVPN_LOCAL_UPLOAD_BUDGET_US;
    while (*received < length) {
        if (now(ctx) >= deadline) return false;
        size_t remaining = length - *received;
        size_t wanted = remaining < sizeof(block) ? remaining : sizeof(block);
        int n = receive(ctx, block, wanted);
        if (n <= 0 || (size_t)n > wanted) return false;
        *received += n;
    }
    return now(ctx) < deadline;
}
