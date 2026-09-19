#pragma once

#include <stdbool.h>
#include <stddef.h>

/* Normalize a mutable Ethernet frame immediately before a LAN driver. */
void meshvpn_vpn_lan_egress(void *frame, size_t length, bool usb);
