#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Percent of one core, not of the combined two-core capacity. Reject a stalled
 * sampler rather than presenting a long average as the current load. */
static inline bool meshvpn_cpu_percent(uint64_t before, uint64_t after,
                                      uint64_t elapsed, double *out)
{
    if (after < before || elapsed < 100000 || elapsed > 10000000) return false;
    uint64_t delta = after - before;
    *out = delta >= elapsed ? 100.0 : 100.0 * (double)delta / (double)elapsed;
    return true;
}
