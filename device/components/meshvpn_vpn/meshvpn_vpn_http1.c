#include "meshvpn_vpn_internal.h"
#include "meshvpn_vpn_protocol.h"

#include <stdio.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "meshvpn_http1";

static esp_tls_t *s_tls;
static uint8_t s_pending[4096];
static size_t s_pending_len;
static size_t s_pending_off;

static ssize_t tls_read(esp_tls_t *tls, uint8_t *buf, size_t len)
{
    ssize_t n = esp_tls_conn_read(tls, buf, len);
    if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
        return 0;
    }
    return n;
}

void meshvpn_vpn_http1_close(void)
{
    s_tls = NULL;
    s_pending_len = 0;
    s_pending_off = 0;
}

esp_err_t meshvpn_vpn_http1_open(esp_tls_t *tls, const meshvpn_vpn_config_t *cfg, const char *bearer_token,
                                 char *last_error, size_t last_error_len)
{
    if (!tls) {
        snprintf(last_error, last_error_len, "http1 no tls");
        return ESP_ERR_INVALID_ARG;
    }

    meshvpn_vpn_http1_close();
    s_tls = tls;

    char host[128];
    meshvpn_vpn_tls_http_authority(cfg, host, sizeof(host));

    char auth_hdr[96];
    snprintf(auth_hdr, sizeof(auth_hdr), "Bearer %s", bearer_token);

    char req[512];
    int req_len = snprintf(req, sizeof(req),
                           "GET %s HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "Accept: */*\r\n"
                           "Authorization: %s\r\n"
                           "Connection: keep-alive\r\n\r\n",
                           MESHVPN_TLS_HTTP_PATH, host, auth_hdr);
    if (req_len <= 0 || req_len >= (int)sizeof(req)) {
        snprintf(last_error, last_error_len, "http1 req too long");
        return ESP_FAIL;
    }

    if (esp_tls_conn_write(tls, req, (size_t)req_len) != req_len) {
        snprintf(last_error, last_error_len, "http1 write req");
        return ESP_FAIL;
    }

    uint8_t buf[2048];
    size_t total = 0;
    for (int attempt = 0; attempt < 128 && total < sizeof(buf); attempt++) {
        ssize_t n = tls_read(tls, buf + total, sizeof(buf) - total);
        if (n <= 0) {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        total += (size_t)n;

        for (size_t i = 3; i < total; i++) {
            if (buf[i - 3] != '\r' || buf[i - 2] != '\n' || buf[i - 1] != '\r' || buf[i] != '\n') {
                continue;
            }
            if (strncmp((char *)buf, "HTTP/1.1 200", 12) != 0 && strncmp((char *)buf, "HTTP/1.0 200", 12) != 0) {
                snprintf(last_error, last_error_len, "http1 status not 200");
                return ESP_FAIL;
            }
            size_t body = i + 1;
            if (body < total) {
                s_pending_len = total - body;
                memcpy(s_pending, buf + body, s_pending_len);
            }
            ESP_LOGI(TAG, "HTTP/1.1 VPN tunnel open host=%s", host);
            return ESP_OK;
        }
    }

    snprintf(last_error, last_error_len, "http1 headers timeout");
    return ESP_FAIL;
}

static ssize_t http1_read_raw(uint8_t *dst, size_t len)
{
    if (s_pending_off < s_pending_len) {
        size_t avail = s_pending_len - s_pending_off;
        size_t n = avail < len ? avail : len;
        memcpy(dst, s_pending + s_pending_off, n);
        s_pending_off += n;
        if (s_pending_off >= s_pending_len) {
            s_pending_len = 0;
            s_pending_off = 0;
        }
        return (ssize_t)n;
    }
    if (!s_tls) {
        return -1;
    }
    return tls_read(s_tls, dst, len);
}

esp_err_t meshvpn_vpn_http1_read(uint8_t *pkt, uint16_t maxlen, uint16_t *out_len)
{
    uint8_t hdr[4];
    size_t got = 0;
    while (got < 4) {
        ssize_t n = http1_read_raw(hdr + got, 4 - got);
        if (n <= 0) {
            return ESP_ERR_NOT_FOUND;
        }
        got += (size_t)n;
    }

    uint32_t plen = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
    if (plen == 0 || plen > maxlen) {
        return ESP_ERR_INVALID_SIZE;
    }

    got = 0;
    while (got < plen) {
        ssize_t n = http1_read_raw(pkt + got, plen - got);
        if (n <= 0) {
            return ESP_FAIL;
        }
        got += (size_t)n;
    }

    if (out_len) {
        *out_len = (uint16_t)plen;
    }
    return ESP_OK;
}

esp_err_t meshvpn_vpn_http1_write(const uint8_t *pkt, uint16_t len)
{
    if (!s_tls) {
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t hdr[4] = {
        (uint8_t)(len >> 24),
        (uint8_t)(len >> 16),
        (uint8_t)(len >> 8),
        (uint8_t)(len),
    };

    if (esp_tls_conn_write(s_tls, hdr, 4) != 4) {
        return ESP_FAIL;
    }
    return esp_tls_conn_write(s_tls, pkt, len) == len ? ESP_OK : ESP_FAIL;
}
