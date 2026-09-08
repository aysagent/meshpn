#include "meshvpn_ip_ranges.h"
bool meshvpn_ip_ranges_contains(const meshvpn_ip_range_t *r, size_t count, uint32_t ip)
{
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ip < r[mid].first) hi = mid;
        else if (ip > r[mid].last) lo = mid + 1;
        else return true;
    }
    return false;
}
