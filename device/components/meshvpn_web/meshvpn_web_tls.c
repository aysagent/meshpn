#include "meshvpn_web_tls.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

typedef struct { uint32_t version; char cert[4096]; char key[2048]; } identity_t;
static identity_t *s_identity;
static char s_fingerprint[96];

/* WiFi radio is initialized before generating the per-device key. */
static int random_bytes(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}
static esp_err_t validate(const identity_t *id)
{
    if (id->version != 1 || !memchr(id->cert, 0, sizeof(id->cert)) ||
        !memchr(id->key, 0, sizeof(id->key))) return ESP_ERR_INVALID_ARG;
    mbedtls_x509_crt crt; mbedtls_x509_crt_init(&crt);
    mbedtls_pk_context key; mbedtls_pk_init(&key);
    int ret = mbedtls_x509_crt_parse(&crt, (const unsigned char *)id->cert, strlen(id->cert) + 1);
    if (!ret) ret = mbedtls_pk_parse_key(&key, (const unsigned char *)id->key,
                                        strlen(id->key) + 1, NULL, 0, random_bytes, NULL);
    if (!ret) ret = mbedtls_pk_check_pair(&crt.pk, &key, random_bytes, NULL);
    if (!ret) {
        uint32_t flags = 0;
        /* Trust establishment is performed by the host. Here verify the name
         * without relying on the dongle having a wall clock during setup. */
        mbedtls_x509_crt_verify(&crt, &crt, NULL, "meshpn.local", &flags, NULL, NULL);
        if (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) ret = -1;
    }
    mbedtls_pk_free(&key); mbedtls_x509_crt_free(&crt);
    return ret ? ESP_ERR_INVALID_ARG : ESP_OK;
}
static esp_err_t save(const identity_t *id)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("meshvpn", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    /* Do not consume 6 KiB of NVS for a ~1 KiB EC identity. One variable-size
     * blob is an atomic replacement of certificate and key together. */
    uint32_t lengths[3] = {2, strlen(id->cert) + 1, strlen(id->key) + 1};
    size_t size = sizeof(lengths) + lengths[1] + lengths[2];
    uint8_t *blob = malloc(size);
    if (!blob) { nvs_close(nvs); return ESP_ERR_NO_MEM; }
    memcpy(blob, lengths, sizeof(lengths));
    memcpy(blob + sizeof(lengths), id->cert, lengths[1]);
    memcpy(blob + sizeof(lengths) + lengths[1], id->key, lengths[2]);
    err = nvs_set_blob(nvs, "web_identity", blob, size);
    mbedtls_platform_zeroize(blob, size);
    free(blob);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

static esp_err_t load(identity_t *id, nvs_handle_t nvs)
{
    size_t size = 0;
    esp_err_t err = nvs_get_blob(nvs, "web_identity", NULL, &size);
    if (err != ESP_OK) return err;
    if (size < 12 || size > 12 + sizeof(id->cert) + sizeof(id->key)) return ESP_ERR_INVALID_SIZE;
    uint8_t *blob = malloc(size);
    if (!blob) return ESP_ERR_NO_MEM;
    err = nvs_get_blob(nvs, "web_identity", blob, &size);
    uint32_t lengths[3] = {0};
    if (err == ESP_OK) memcpy(lengths, blob, sizeof(lengths));
    if (err == ESP_OK && lengths[0] == 2 && lengths[1] > 0 && lengths[2] > 0 &&
        lengths[1] <= sizeof(id->cert) && lengths[2] <= sizeof(id->key) &&
        size == sizeof(lengths) + lengths[1] + lengths[2]) {
        id->version = 1;
        memcpy(id->cert, blob + sizeof(lengths), lengths[1]);
        memcpy(id->key, blob + sizeof(lengths) + lengths[1], lengths[2]);
        if (id->cert[lengths[1] - 1] || id->key[lengths[2] - 1]) err = ESP_ERR_INVALID_ARG;
    } else if (err == ESP_OK) err = ESP_ERR_INVALID_ARG;
    mbedtls_platform_zeroize(blob, size); free(blob);
    return err;
}
static esp_err_t generate(identity_t *id)
{
    mbedtls_pk_context key; mbedtls_pk_init(&key);
    mbedtls_x509write_cert crt; mbedtls_x509write_crt_init(&crt);
    unsigned char random[16]; random_bytes(NULL, random, sizeof(random)); random[0] &= 0x7f;
    int ret;
#define TRY(call) do { if ((ret = (call)) != 0) goto done; } while (0)
    TRY(mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)));
    TRY(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key), random_bytes, NULL));
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &key);
    TRY(mbedtls_x509write_crt_set_serial_raw(&crt, random, sizeof(random)));
    TRY(mbedtls_x509write_crt_set_subject_name(&crt, "CN=meshpn.local,O=MeshPN device"));
    TRY(mbedtls_x509write_crt_set_issuer_name(&crt, "CN=meshpn.local,O=MeshPN device"));
    TRY(mbedtls_x509write_crt_set_validity(&crt, "20250101000000", "20450101000000"));
    TRY(mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1));
    TRY(mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE));
    /* DNS names survive subnet changes; IP SANs cover factory LAN defaults.
     * Existing/imported identities are deliberately preserved. */
    unsigned char san[96] = {0x30, 0};
    size_t pos = 2;
    const char *names[] = {"meshpn.local", "meshpn.home.arpa"};
    for (unsigned i = 0; i < 2; i++) {
        size_t n = strlen(names[i]);
        san[pos++] = 0x82; san[pos++] = n;
        memcpy(san + pos, names[i], n); pos += n;
    }
    san[pos++] = 0x87; san[pos++] = 4;
    san[pos++] = 192; san[pos++] = 168; san[pos++] = 7; san[pos++] = 1;
    san[pos++] = 0x87; san[pos++] = 4;
    san[pos++] = 192; san[pos++] = 168; san[pos++] = 4; san[pos++] = 1;
    san[1] = pos - 2;
    TRY(mbedtls_x509write_crt_set_extension(&crt, MBEDTLS_OID_SUBJECT_ALT_NAME,
        MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME), 0, san, pos));
    TRY(mbedtls_pk_write_key_pem(&key, (unsigned char *)id->key, sizeof(id->key)));
    TRY(mbedtls_x509write_crt_pem(&crt, (unsigned char *)id->cert, sizeof(id->cert), random_bytes, NULL));
    id->version = 1;
done:
    mbedtls_x509write_crt_free(&crt); mbedtls_pk_free(&key);
    return ret ? ESP_FAIL : ESP_OK;
#undef TRY
}
esp_err_t meshvpn_web_tls_init(void)
{
    if (s_identity) return ESP_OK;
    s_identity = calloc(1, sizeof(*s_identity));
    if (!s_identity) return ESP_ERR_NO_MEM;
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("meshvpn", NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        err = load(s_identity, nvs);
        nvs_close(nvs);
    }
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        err = generate(s_identity);
        if (err == ESP_OK) err = save(s_identity);
    }
    if (err != ESP_OK || validate(s_identity) != ESP_OK) {
        mbedtls_platform_zeroize(s_identity, sizeof(*s_identity));
        free(s_identity); s_identity = NULL;
        return ESP_FAIL;
    }
    mbedtls_x509_crt crt; mbedtls_x509_crt_init(&crt);
    mbedtls_x509_crt_parse(&crt, (const unsigned char *)s_identity->cert, strlen(s_identity->cert) + 1);
    unsigned char hash[32];
    mbedtls_sha256(crt.raw.p, crt.raw.len, hash, 0);
    for (unsigned i = 0; i < 32; i++) snprintf(s_fingerprint + i * 3, 4, i == 31 ? "%02X" : "%02X:", hash[i]);
    mbedtls_x509_crt_free(&crt);
    ESP_LOGI("meshvpn_tls", "Certificate SHA256 %s", s_fingerprint);
    return ESP_OK;
}
const char *meshvpn_web_tls_cert(void) { return s_identity->cert; }
const char *meshvpn_web_tls_key(void) { return s_identity->key; }
const char *meshvpn_web_tls_fingerprint(void) { return s_fingerprint; }
esp_err_t meshvpn_web_tls_import(const char *cert, const char *key)
{
    if (!cert || !key || strlen(cert) >= sizeof(s_identity->cert) ||
        strlen(key) >= sizeof(s_identity->key)) return ESP_ERR_INVALID_SIZE;
    identity_t *next = calloc(1, sizeof(*next));
    if (!next) return ESP_ERR_NO_MEM;
    next->version = 1;
    strcpy(next->cert, cert); strcpy(next->key, key);
    esp_err_t err = validate(next);
    if (err == ESP_OK) err = save(next);
    mbedtls_platform_zeroize(next, sizeof(*next)); free(next);
    return err;
}
