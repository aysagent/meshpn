#include "meshvpn_vpn_protocol.h"
#include "meshvpn_vpn_internal.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_err.h"
#include "mbedtls/md.h"

esp_err_t meshvpn_vpn_bearer_compute(const uint8_t *psk, size_t psk_len,
                                     const uint8_t *exporter, size_t exporter_len,
                                     char *token_hex, size_t token_hex_len)
{
    return meshvpn_vpn_bearer_compute_window(psk, psk_len, exporter, exporter_len, 0, token_hex, token_hex_len);
}

esp_err_t meshvpn_vpn_bearer_compute_window(const uint8_t *psk, size_t psk_len,
                                            const uint8_t *exporter, size_t exporter_len,
                                            int64_t window_offset, char *token_hex, size_t token_hex_len)
{
    if (!psk || psk_len == 0 || !token_hex || token_hex_len < 33) {
        return ESP_ERR_INVALID_ARG;
    }

    int64_t window = (int64_t)(time(NULL) / MESHVPN_TLS_BEARER_WINDOW_SEC) + window_offset;

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) {
        return ESP_FAIL;
    }

    uint8_t mac[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md, 1) != 0) {
        mbedtls_md_free(&ctx);
        return ESP_FAIL;
    }

    if (mbedtls_md_hmac_starts(&ctx, psk, psk_len) != 0 ||
        mbedtls_md_hmac_update(&ctx, (const uint8_t *)MESHVPN_TLS_HMAC_PREFIX,
                               strlen(MESHVPN_TLS_HMAC_PREFIX)) != 0) {
        mbedtls_md_free(&ctx);
        return ESP_FAIL;
    }

    if (exporter && exporter_len > 0) {
        if (mbedtls_md_hmac_update(&ctx, exporter, exporter_len) != 0) {
            mbedtls_md_free(&ctx);
            return ESP_FAIL;
        }
    }

    char window_buf[24];
    int wlen = snprintf(window_buf, sizeof(window_buf), ":%lld", (long long)window);
    if (mbedtls_md_hmac_update(&ctx, (const uint8_t *)window_buf, wlen) != 0 ||
        mbedtls_md_hmac_finish(&ctx, mac) != 0) {
        mbedtls_md_free(&ctx);
        return ESP_FAIL;
    }
    mbedtls_md_free(&ctx);

    for (int i = 0; i < 16; i++) {
        snprintf(token_hex + i * 2, 3, "%02x", mac[i]);
    }
    token_hex[32] = '\0';
    return ESP_OK;
}
