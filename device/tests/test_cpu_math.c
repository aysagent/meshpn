#include <assert.h>
#include <math.h>
#include <stdio.h>
#include "meshvpn_cpu_math.h"
int main(void)
{
    double p;
    assert(meshvpn_cpu_percent(0, 1000000, 2000000, &p) && p == 50);
    assert(meshvpn_cpu_percent(0, 1980000, 2000000, &p) && p == 99);
    assert(meshvpn_cpu_percent(0, 0, 2000000, &p) && p == 0);
    assert(meshvpn_cpu_percent(0, 2000001, 2000000, &p) && p == 100);
    /* Long uptime and crossing the old 32-bit wrap boundary remain accurate. */
    assert(meshvpn_cpu_percent(UINT32_MAX - 100, (uint64_t)UINT32_MAX + 989900,
        1000000, &p) && fabs(p - 99) < .0001);
    assert(meshvpn_cpu_percent(7200000000ULL, 7201980000ULL, 2000000, &p) && p == 99);
    assert(!meshvpn_cpu_percent(0, 0, 0, &p));
    assert(!meshvpn_cpu_percent(0, 1, 1000, &p));
    assert(!meshvpn_cpu_percent(2, 1, 2000000, &p));
    assert(!meshvpn_cpu_percent(0, 7128000000ULL, 7200000000ULL, &p));
    puts("CPU interval, long uptime, overflow boundary and invalid sample tests passed");
}
