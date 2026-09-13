#pragma once
#include <stddef.h>
#include <stdint.h>

/* Locate one bulk IN endpoint in the NCM IAD's data interface. Do not assume
 * EP2: the diagnostic CDC interface changes endpoint numbering. Zero means
 * malformed/ambiguous/unsupported descriptors, never a mask for all EPs. */
static inline uint8_t meshvpn_usb_ncm_in_endpoint(const uint8_t *d, size_t size)
{
    if (!d || size < 9 || d[0] != 9 || d[1] != 2 ||
        ((size_t)d[2] | ((size_t)d[3] << 8)) != size) return 0;
    unsigned first = 256, end = 256, ncm_count = 0;
    uint8_t endpoint = 0;
    int data_interface = 0;
    for (size_t pos = 9; pos < size;) {
        const uint8_t *p = d + pos;
        if (size - pos < 2 || p[0] < 2 || p[0] > size - pos) return 0;
        if (p[1] == 11) { /* Interface Association Descriptor */
            if (p[0] < 8) return 0;
            if (p[4] == 2 && p[5] == 13) { /* CDC NCM */
                if (++ncm_count != 1 || p[3] != 2 || p[2] > 254) return 0;
                first = p[2]; end = first + p[3];
            }
            data_interface = 0;
        } else if (p[1] == 4) {
            if (p[0] < 9) return 0;
            data_interface = p[2] >= first && p[2] < end &&
                p[3] == 1 && p[5] == 10 && p[6] == 0 && p[7] == 1;
        } else if (p[1] == 5 && data_interface) {
            if (p[0] < 7) return 0;
            if ((p[2] & 0x80) && (p[3] & 3) == 2) {
                if (endpoint || (p[2] & 0x70) || !(p[2] & 15) ||
                    p[4] != 64 || p[5] != 0) return 0;
                endpoint = p[2];
            }
        }
        pos += p[0];
    }
    return endpoint;
}
