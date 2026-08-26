#include "meshvpn_vpn_internal.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esp_err.h"

esp_err_t meshvpn_vpn_framing_write(int fd, const uint8_t *pkt, uint16_t len)
{
    if (fd < 0 || !pkt || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t hdr[4] = {
        (uint8_t)(len >> 24),
        (uint8_t)(len >> 16),
        (uint8_t)(len >> 8),
        (uint8_t)(len),
    };

    if (write(fd, hdr, 4) != 4) {
        return ESP_FAIL;
    }
    ssize_t n = write(fd, pkt, len);
    return n == len ? ESP_OK : ESP_FAIL;
}

esp_err_t meshvpn_vpn_framing_read(int fd, uint8_t *pkt, uint16_t maxlen, uint16_t *out_len)
{
    uint8_t hdr[4];
    ssize_t n = read(fd, hdr, 4);
    if (n == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    if (n != 4) {
        return ESP_FAIL;
    }

    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
    if (len == 0 || len > maxlen) {
        return ESP_ERR_INVALID_SIZE;
    }

    size_t got = 0;
    while (got < len) {
        n = read(fd, pkt + got, len - got);
        if (n <= 0) {
            return ESP_FAIL;
        }
        got += (size_t)n;
    }

    if (out_len) {
        *out_len = (uint16_t)len;
    }
    return ESP_OK;
}
