#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MESHVPN_LOCAL_DOWNLOAD_BYTES (8U * 1024U * 1024U)
#define MESHVPN_LOCAL_DOWNLOAD_BUDGET_US INT64_C(30000000)

/* Bounded generator; no payload allocation. A failed/deadline-limited stream
 * must NOT get an HTTP terminating chunk: the receiver must reject truncation.
 * Budget is checked between writes; a blocking write can add its socket timeout. */
static inline bool meshvpn_local_download(void *ctx,
        bool (*send_block)(void *, const char *, size_t), int64_t (*now)(void *))
{
    static const char block[4096] = {0};
    const int64_t deadline = now(ctx) + MESHVPN_LOCAL_DOWNLOAD_BUDGET_US;
    for (size_t sent = 0; sent < MESHVPN_LOCAL_DOWNLOAD_BYTES; sent += sizeof(block)) {
        if (now(ctx) >= deadline || !send_block(ctx, block, sizeof(block))) return false;
    }
    return now(ctx) < deadline;
}
