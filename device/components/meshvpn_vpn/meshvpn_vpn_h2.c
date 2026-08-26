#include "meshvpn_vpn_internal.h"
#include "meshvpn_vpn_protocol.h"

#include <nghttp2/nghttp2.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esp_err.h"
#include "esp_log.h"

static const char *TAG = "meshvpn_h2";

typedef struct {
    int fd;
    int stream_id;
    bool got_status;
    bool status_ok;
} h2_ctx_t;

static ssize_t h2_send(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
    (void)session;
    (void)flags;
    h2_ctx_t *ctx = user_data;
    return send(ctx->fd, data, length, 0);
}

static int h2_on_header(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                        size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
    (void)session;
    (void)flags;
    h2_ctx_t *ctx = user_data;
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

esp_err_t meshvpn_vpn_h2_open(int tls_fd, const meshvpn_vpn_config_t *cfg,
                              const char *bearer_token, int *out_stream_id,
                              char *last_error, size_t last_error_len)
{
    if (cfg->http_vers == 1) {
        snprintf(last_error, last_error_len, "use HTTP/1.1 path");
        return ESP_ERR_NOT_SUPPORTED;
    }

    h2_ctx_t ctx = { .fd = tls_fd };
    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback(callbacks, h2_send);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, h2_on_header);

    nghttp2_session *session;
    nghttp2_session_client_new(&session, callbacks, &ctx);
    nghttp2_session_callbacks_del(callbacks);

    nghttp2_settings_entry iv[] = {
        { NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 65536 },
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 16 * 1024 * 1024 },
    };
    nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 2);

    const char *authority = cfg->tls_server_name[0] ? cfg->tls_server_name : cfg->server;
    char auth_buf[128];
    const char *colon = strrchr(authority, ':');
    if (colon) {
        size_t n = (size_t)(colon - authority);
        if (n >= sizeof(auth_buf)) {
            n = sizeof(auth_buf) - 1;
        }
        memcpy(auth_buf, authority, n);
        auth_buf[n] = '\0';
        authority = auth_buf;
    }

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
    for (int i = 0; i < 32 && !ctx.got_status; i++) {
        ssize_t n = recv(tls_fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            break;
        }
        ssize_t rv = nghttp2_session_mem_recv(session, buf, (size_t)n);
        if (rv < 0) {
            break;
        }
        while (nghttp2_session_want_write(session)) {
            nghttp2_session_send(session);
        }
    }

    nghttp2_session_del(session);

    if (!ctx.status_ok) {
        snprintf(last_error, last_error_len, "h2 :status not 200");
        return ESP_FAIL;
    }

    *out_stream_id = ctx.stream_id;
    ESP_LOGI(TAG, "HTTP/2 VPN stream %d open", ctx.stream_id);
    return ESP_OK;
}
