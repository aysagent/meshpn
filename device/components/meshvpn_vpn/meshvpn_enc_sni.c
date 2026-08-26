#include "meshvpn_enc_sni.h"

#include <string.h>
#include <time.h>

#include "esp_err.h"
#include "esp_random.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"

#define ENC_SNI_VERSION 0x02
#define ENC_SNI_NONCE_LEN 12
#define ENC_SNI_TAG_LEN 16
#define DNS_LABEL_MAX 63

static const char BASE62[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static esp_err_t derive_enc_sni_key(const uint8_t *psk, size_t psk_len, uint8_t out[32])
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_md_hmac(md, psk, psk_len,
                           (const uint8_t *)"transparent-tls-enc-sni-v2", 27, out);
}

static esp_err_t base62_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap, size_t *out_len)
{
    if (in_len == 0) {
        out[0] = BASE62[0];
        out[1] = '\0';
        *out_len = 1;
        return ESP_OK;
    }

    uint32_t digits[512];
    int dlen = 1;
    digits[0] = 0;

    for (size_t i = 0; i < in_len; i++) {
        uint32_t carry = in[i];
        for (int j = 0; j < dlen; j++) {
            carry += digits[j] << 8;
            digits[j] = carry % 62;
            carry /= 62;
        }
        while (carry) {
            digits[dlen++] = carry % 62;
            carry /= 62;
        }
    }

    size_t o = 0;
    for (size_t i = 0; i < in_len && in[i] == 0 && o < out_cap - 1; i++) {
        out[o++] = BASE62[0];
    }
    for (int q = dlen - 1; q >= 0 && o < out_cap - 1; q--) {
        out[o++] = BASE62[digits[q]];
    }
    if (o == 0 && o < out_cap) {
        out[o++] = BASE62[0];
    }
    out[o] = '\0';
    *out_len = o;
    return ESP_OK;
}

static esp_err_t build_plaintext(const char *hostname, uint16_t port, uint8_t *pt, size_t *pt_len)
{
    size_t hlen = strlen(hostname);
    if (hlen == 0 || hlen > 253) {
        return ESP_ERR_INVALID_ARG;
    }
    if (*pt_len < 8 + hlen) {
        return ESP_ERR_NO_MEM;
    }

    pt[0] = ENC_SNI_VERSION;
    uint32_t ts = (uint32_t)time(NULL);
    pt[1] = (uint8_t)(ts >> 24);
    pt[2] = (uint8_t)(ts >> 16);
    pt[3] = (uint8_t)(ts >> 8);
    pt[4] = (uint8_t)(ts);
    pt[5] = (uint8_t)(port >> 8);
    pt[6] = (uint8_t)(port);
    pt[7] = (uint8_t)hlen;
    memcpy(pt + 8, hostname, hlen);
    *pt_len = 8 + hlen;
    return ESP_OK;
}

esp_err_t meshvpn_enc_sni_build_relay_hostname(const uint8_t *psk, size_t psk_len,
                                               const char *origin_sni, uint16_t port,
                                               const char *public_name,
                                               char *out, size_t out_cap)
{
    uint8_t key[32];
    if (derive_enc_sni_key(psk, psk_len, key) != 0) {
        return ESP_FAIL;
    }

    uint8_t pt[300];
    size_t pt_len = sizeof(pt);
    if (build_plaintext(origin_sni, port, pt, &pt_len) != ESP_OK) {
        return ESP_FAIL;
    }

    uint8_t nonce[ENC_SNI_NONCE_LEN];
    esp_fill_random(nonce, sizeof(nonce));

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) {
        mbedtls_gcm_free(&gcm);
        return ESP_FAIL;
    }

    uint8_t ct[300];
    if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, pt_len, nonce, ENC_SNI_NONCE_LEN,
                                  NULL, 0, pt, ct, ENC_SNI_TAG_LEN, ct + pt_len) != 0) {
        mbedtls_gcm_free(&gcm);
        return ESP_FAIL;
    }
    mbedtls_gcm_free(&gcm);

    uint8_t wire[512];
    memcpy(wire, nonce, ENC_SNI_NONCE_LEN);
    memcpy(wire + ENC_SNI_NONCE_LEN, ct, pt_len + ENC_SNI_TAG_LEN);
    size_t wire_len = ENC_SNI_NONCE_LEN + pt_len + ENC_SNI_TAG_LEN;

    char blob[768];
    size_t blob_len = 0;
    if (base62_encode(wire, wire_len, blob, sizeof(blob), &blob_len) != ESP_OK) {
        return ESP_FAIL;
    }

    size_t o = 0;
    for (size_t i = 0; i < blob_len; i += DNS_LABEL_MAX) {
        size_t chunk = blob_len - i;
        if (chunk > DNS_LABEL_MAX) {
            chunk = DNS_LABEL_MAX;
        }
        if (o > 0) {
            if (o + 1 >= out_cap) {
                return ESP_ERR_NO_MEM;
            }
            out[o++] = '.';
        }
        if (o + chunk >= out_cap) {
            return ESP_ERR_NO_MEM;
        }
        memcpy(out + o, blob + i, chunk);
        o += chunk;
    }
    if (o + 1 + strlen(public_name) >= out_cap) {
        return ESP_ERR_NO_MEM;
    }
    out[o++] = '.';
    strcpy(out + o, public_name);
    return ESP_OK;
}
