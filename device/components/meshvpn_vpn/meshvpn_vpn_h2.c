#include "meshvpn_vpn_internal.h"
#include "meshvpn_vpn_protocol.h"

#include <nghttp2/nghttp2.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "meshvpn_h2";

#define H2_RX_CAP 16384

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t offset;
} h2_send_buf_t;

typedef struct {
    esp_tls_t *tls;
    int stream_id;
    bool got_status;
    bool status_ok;
} h2_open_ctx_t;

static nghttp2_session *s_session;
static esp_tls_t *s_tls;
static int s_stream_id = -1;

static uint8_t s_rx[H2_RX_CAP];
static size_t s_rx_len;

static ssize_t tls_read(esp_tls_t *tls, uint8_t *buf, size_t len)
{
    ssize_t n = esp_tls_conn_read(tls, buf, len);
    if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
        return 0;
    }
    return n;
}

static ssize_t h2_send_cb(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
    (void)session;
    (void)flags;
    h2_open_ctx_t *ctx = user_data;
    if (!ctx || !ctx->tls) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    ssize_t n = esp_tls_conn_write(ctx->tls, data, length);
    if (n <= 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return n;
}

static int h2_on_header(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
                        const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
    (void)session;
    (void)flags;
    h2_open_ctx_t *ctx = user_data;
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_RESPONSE) {
        return 0;
    }
    if (frame->hd.stream_id != ctx->stream_id) {
        return 0;
    }
    if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
        ctx->got_status = true;
        if (valuelen == 3 && memcmp(value, "200", 3) == 0) {
            ctx->status_ok = true;
        }
    }
    return 0;
}

static int h2_on_data_chunk(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data,
                            size_t len, void *user_data)
{
    (void)session;
    (void)flags;
    (void)user_data;
    if (stream_id != s_stream_id || len == 0) {
        return 0;
    }
    if (s_rx_len + len > H2_RX_CAP) {
        ESP_LOGW(TAG, "h2 rx overflow");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    memcpy(s_rx + s_rx_len, data, len);
    s_rx_len += len;
    return 0;
}

static ssize_t h2_data_read_cb(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
                               uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
    (void)session;
    (void)stream_id;
    (void)user_data;
    h2_send_buf_t *sb = source->ptr;
    size_t remain = sb->len - sb->offset;
    if (remain == 0) {
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }
    size_t n = remain < length ? remain : length;
    memcpy(buf, sb->data + sb->offset, n);
    sb->offset += n;
    if (sb->offset >= sb->len) {
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
    }
    return (ssize_t)n;
}

void meshvpn_vpn_h2_close(void)
{
    if (s_session) {
        nghttp2_session_del(s_session);
        s_session = NULL;
    }
    s_tls = NULL;
    s_stream_id = -1;
    s_rx_len = 0;
}

esp_err_t meshvpn_vpn_h2_poll(void)
{
    if (!s_session || !s_tls) {
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t buf[4096];
    ssize_t n = tls_read(s_tls, buf, sizeof(buf));
    if (n > 0) {
        ssize_t rv = nghttp2_session_mem_recv(s_session, buf, (size_t)n);
        if (rv < 0) {
            return ESP_FAIL;
        }
    }

    while (nghttp2_session_want_write(s_session)) {
        if (nghttp2_session_send(s_session) != 0) {
            return ESP_FAIL;
        }
    }
    return ESP_OK;
}

static esp_err_t h2_open_session(esp_tls_t *tls, const meshvpn_vpn_config_t *cfg, const char *bearer_token,
                                 nghttp2_session **out_session, int *out_stream_id, char *last_error,
                                 size_t last_error_len)
{
    h2_open_ctx_t ctx = { .tls = tls };
    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback(callbacks, h2_send_cb);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, h2_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, h2_on_data_chunk);

    nghttp2_session *session;
    if (nghttp2_session_client_new(&session, callbacks, &ctx) != 0) {
        nghttp2_session_callbacks_del(callbacks);
        snprintf(last_error, last_error_len, "h2 session_new");
        return ESP_FAIL;
    }
    nghttp2_session_callbacks_del(callbacks);

    nghttp2_settings_entry iv[] = {
        { NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 65536 },
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 16 * 1024 * 1024 },
    };
    nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 2);

    char authority[128];
    meshvpn_vpn_tls_http_authority(cfg, authority, sizeof(authority));

    char auth_hdr[96];
    snprintf(auth_hdr, sizeof(auth_hdr), "Bearer %s", bearer_token);

    nghttp2_nv nva[] = {
        { (uint8_t *)":method", (uint8_t *)"POST", 7, 4, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t *)":path", (uint8_t *)MESHVPN_TLS_HTTP_PATH, 5, sizeof(MESHVPN_TLS_HTTP_PATH) - 1,
          NGHTTP2_NV_FLAG_NONE },
        { (uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t *)":authority", (uint8_t *)authority, 10, strlen(authority), NGHTTP2_NV_FLAG_NONE },
        { (uint8_t *)"authorization", (uint8_t *)auth_hdr, 13, strlen(auth_hdr), NGHTTP2_NV_FLAG_NONE },
    };

    ctx.stream_id = nghttp2_submit_request(session, NULL, nva, 5, NULL, NULL);
    if (ctx.stream_id < 0) {
        nghttp2_session_del(session);
        snprintf(last_error, last_error_len, "h2 submit_request");
        return ESP_FAIL;
    }

    while (nghttp2_session_want_write(session)) {
        if (nghttp2_session_send(session) != 0) {
            nghttp2_session_del(session);
            snprintf(last_error, last_error_len, "h2 send");
            return ESP_FAIL;
        }
    }

    uint8_t buf[4096];
    for (int i = 0; i < 128 && !ctx.got_status; i++) {
        ssize_t n = tls_read(tls, buf, sizeof(buf));
        if (n <= 0) {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        ssize_t rv = nghttp2_session_mem_recv(session, buf, (size_t)n);
        if (rv < 0) {
            break;
        }
        while (nghttp2_session_want_write(session)) {
            nghttp2_session_send(session);
        }
    }

    if (!ctx.status_ok) {
        nghttp2_session_del(session);
        snprintf(last_error, last_error_len, "h2 :status not 200");
        return ESP_FAIL;
    }

    *out_session = session;
    *out_stream_id = ctx.stream_id;
    return ESP_OK;
}

esp_err_t meshvpn_vpn_h2_open(esp_tls_t *tls, const meshvpn_vpn_config_t *cfg, const char *bearer_token,
                              int *out_stream_id, char *last_error, size_t last_error_len)
{
    if (!tls) {
        snprintf(last_error, last_error_len, "h2 no tls");
        return ESP_ERR_INVALID_ARG;
    }

    meshvpn_vpn_h2_close();
    s_tls = tls;

    nghttp2_session *session = NULL;
    int stream_id = 0;
    esp_err_t err = h2_open_session(tls, cfg, bearer_token, &session, &stream_id, last_error, last_error_len);
    if (err != ESP_OK) {
        return err;
    }

    s_session = session;
    s_stream_id = stream_id;
    *out_stream_id = stream_id;
    ESP_LOGI(TAG, "HTTP/2 VPN stream %d open", stream_id);
    return ESP_OK;
}

esp_err_t meshvpn_vpn_h2_write(const uint8_t *pkt, uint16_t len)
{
    if (!s_session || s_stream_id < 0 || !s_tls) {
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t frame[4 + 1500];
    if (len > 1500) {
        return ESP_ERR_INVALID_SIZE;
    }
    frame[0] = (uint8_t)(len >> 24);
    frame[1] = (uint8_t)(len >> 16);
    frame[2] = (uint8_t)(len >> 8);
    frame[3] = (uint8_t)(len);
    memcpy(frame + 4, pkt, len);

    h2_send_buf_t sb = { .data = frame, .len = 4 + len, .offset = 0 };
    nghttp2_data_provider dp = { .source.ptr = &sb, .read_callback = h2_data_read_cb };
    if (nghttp2_submit_data(s_session, NGHTTP2_FLAG_NONE, s_stream_id, &dp) != 0) {
        return ESP_FAIL;
    }
    while (nghttp2_session_want_write(s_session)) {
        if (nghttp2_session_send(s_session) != 0) {
            return ESP_FAIL;
        }
    }
    return ESP_OK;
}

esp_err_t meshvpn_vpn_h2_read(uint8_t *pkt, uint16_t maxlen, uint16_t *out_len)
{
    for (int tries = 0; tries < 16; tries++) {
        if (s_rx_len >= 4) {
            uint32_t plen = ((uint32_t)s_rx[0] << 24) | ((uint32_t)s_rx[1] << 16) | ((uint32_t)s_rx[2] << 8) |
                            s_rx[3];
            if (plen == 0 || plen > maxlen) {
                return ESP_ERR_INVALID_SIZE;
            }
            if (s_rx_len >= 4 + plen) {
                memcpy(pkt, s_rx + 4, plen);
                size_t rest = s_rx_len - 4 - plen;
                if (rest > 0) {
                    memmove(s_rx, s_rx + 4 + plen, rest);
                }
                s_rx_len = rest;
                if (out_len) {
                    *out_len = (uint16_t)plen;
                }
                return ESP_OK;
            }
        }
        esp_err_t err = meshvpn_vpn_h2_poll();
        if (err != ESP_OK && s_rx_len < 4) {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }
    return ESP_ERR_NOT_FOUND;
}
