#pragma once
#include <stdbool.h>

/* WireGuard Address value: exactly one IPv4, optional CIDR and IPv6 entries.
 * Returns the effective IPv4; never enables IPv6 or installs connected routes. */
bool meshvpn_vpn_profile_address(const char *value, char ipv4[16]);
