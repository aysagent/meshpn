#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Host-order values in RAM. Disk format uses little endian explicitly. */
typedef struct { uint32_t first, last; } meshvpn_ip_range_t;
bool meshvpn_ip_ranges_contains(const meshvpn_ip_range_t *ranges, size_t count, uint32_t ip);
