#include "meshvpn_vpn_trust.h"
#include "mbedtls/x509_crt.h"
#include "nvs.h"
#include "esp_heap_caps.h"
#include <stdlib.h>
#include <string.h>

bool meshvpn_vpn_tls_name_valid(const char *name)
{
    if (!name || !*name || strlen(name) > 128) return false;
    size_t label = 0;
    bool last_alnum = false;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        bool alnum = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9');
        if (*p == '.') { if (!last_alnum) return false; label = 0; last_alnum = false; continue; }
        if (!alnum && (*p != '-' || !label)) return false;
        if (++label > 63) return false;
        last_alnum = alnum;
    }
    return last_alnum;
}

bool meshvpn_vpn_ca_valid(const char *pem)
{
    if (!pem || !*pem || strlen(pem) > MESHVPN_VPN_CA_MAX) return false;
    /* Accept certificates only: no private keys, partial bundles or ignored junk. */
    const char *p = pem;
    unsigned count = 0;
    while (*p) {
        p += strspn(p, " \r\n\t");
        if (!*p) break;
        const char *begin = "-----BEGIN CERTIFICATE-----", *end = "-----END CERTIFICATE-----";
        if (strncmp(p, begin, strlen(begin))) return false;
        const char *q = strstr(p + strlen(begin), end);
        if (!q) return false;
        p = q + strlen(end); count++;
    }
    if (!count) return false;
    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    bool valid = mbedtls_x509_crt_parse(&chain, (const unsigned char *)pem, strlen(pem) + 1) == 0;
    for (mbedtls_x509_crt *c = &chain; valid && c; c = c->next) valid = c->MBEDTLS_PRIVATE(ca_istrue) != 0;
    mbedtls_x509_crt_free(&chain);
    return valid;
}

esp_err_t meshvpn_vpn_ca_load(char **pem)
{
    if (!pem) return ESP_ERR_INVALID_ARG;
    *pem = NULL;
    nvs_handle_t h;
    esp_err_t err = nvs_open("meshvpn", NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    size_t n = 0;
    err = nvs_get_blob(h, "vpn_tls_ca", NULL, &n);
    if (err == ESP_OK && n == 1) {
        /* ca_save("") stores a NUL tombstone. Distinguish an intentional
         * removal from corrupt/truncated storage without accepting either
         * as TLS trust or hiding a storage read failure. */
        char empty = 1;
        err = nvs_get_blob(h, "vpn_tls_ca", &empty, &n);
        if (err == ESP_OK) err = n == 1 && empty == 0 ? ESP_ERR_NVS_NOT_FOUND : ESP_ERR_INVALID_SIZE;
    }
    if (err == ESP_OK && (n <= 1 || n > MESHVPN_VPN_CA_MAX + 1)) err = ESP_ERR_INVALID_SIZE;
    char *p = NULL;
    if (err == ESP_OK) {
        p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!p) err = ESP_ERR_NO_MEM;
        else {
            err = nvs_get_blob(h, "vpn_tls_ca", p, &n);
            if (err == ESP_OK && (n < 2 || p[n - 1] != 0 || strlen(p) != n - 1)) err = ESP_ERR_INVALID_SIZE;
        }
    }
    nvs_close(h);
    if (err != ESP_OK) free(p); else *pem = p;
    return err;
}

bool meshvpn_vpn_ca_configured(void)
{
    nvs_handle_t h;
    if (nvs_open("meshvpn", NVS_READONLY, &h) != ESP_OK) return false;
    size_t n = 0;
    esp_err_t err = nvs_get_blob(h, "vpn_tls_ca", NULL, &n);
    nvs_close(h);
    return err == ESP_OK && n > 1 && n <= MESHVPN_VPN_CA_MAX + 1;
}

esp_err_t meshvpn_vpn_ca_save(const char *pem)
{
    if (!pem || (*pem && !meshvpn_vpn_ca_valid(pem))) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open("meshvpn", NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    /* One NVS record; an empty value explicitly removes trust. */
    err = nvs_set_blob(h, "vpn_tls_ca", pem, strlen(pem) + 1);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}
