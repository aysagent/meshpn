#include "meshvpn_tls_exporter.h"
#include "meshvpn_vpn_protocol.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_tls.h"

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/ssl.h"
#include "ssl_tls13_keys.h"

static const char *TAG = "meshvpn_tls_exp";

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

esp_err_t meshvpn_tls_exporter_from_ssl(mbedtls_ssl_context *ssl, uint8_t *out, size_t out_len)
{
    if (!ssl || !out || out_len < MESHVPN_TLS_EXPORTER_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_ssl_session *session = ssl->session;
    if (!session) {
        return ESP_ERR_INVALID_STATE;
    }

    const unsigned char *ems = session->app_secrets.exporter_master_secret;
    psa_algorithm_t hash_alg = PSA_ALG_SHA_256;
    size_t hash_len = 32;

    unsigned char derived[32];
    int ret = mbedtls_ssl_tls13_derive_secret(
        hash_alg, ems, hash_len,
        (const unsigned char *)"EXPORTER-clean-vpn-bind", 23,
        NULL, 0, derived, hash_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "derive-secret failed: -0x%x", -ret);
        return ESP_FAIL;
    }

    ret = mbedtls_ssl_tls13_hkdf_expand_label(hash_alg, derived, hash_len,
                                              (const unsigned char *)"exporter", 8,
                                              NULL, 0, MESHVPN_TLS_EXPORTER_LEN, out);
    if (ret != 0) {
        ESP_LOGE(TAG, "hkdf expand failed: -0x%x", -ret);
        return ESP_FAIL;
    }
    return ESP_OK;
}

#else

esp_err_t meshvpn_tls_exporter_from_ssl(mbedtls_ssl_context *ssl, uint8_t *out, size_t out_len)
{
    (void)ssl;
    (void)out;
    (void)out_len;
    return ESP_ERR_NOT_SUPPORTED;
}

#endif

esp_err_t meshvpn_tls_exporter_from_esp_tls(esp_tls_t *tls, uint8_t *out, size_t out_len)
{
    mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)esp_tls_get_ssl_context(tls);
    if (!ssl) {
        return ESP_ERR_INVALID_STATE;
    }
    return meshvpn_tls_exporter_from_ssl(ssl, out, out_len);
}
