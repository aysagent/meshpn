#pragma once
#include "meshvpn_profiled_tls.h"
#include "profile_model.h"
#ifdef __cplusplus
extern "C" {
#endif
#define MESHPN_TLS_PROFILE_ID "chromium156-capture1"
#define MESHPN_TLS_PROFILE_JA3 "ed63604b6e93c62437468be3f6b387c3"
#define MESHPN_TLS_PROFILE_JA4 "t13d1517h2_8daaf6152771_cb7bf5808d99"
#define MESHPN_PROFILE_READ_BYTES 4096
#define MESHPN_PROFILE_H2_SEND_BYTES 4096
typedef struct {
    char phase[32], alpn[16];
    char expected_ja3[33], expected_ja4[37];
    meshvpn_profile_check_t actual;
    unsigned hellos;
    int error, ssl_error, http2_error;
    int32_t h2_connection_credit, h2_stream_credit;
    uint64_t h2_blocked_calls;
    /* Per connection. ACK counted only after its entire frame is accepted by
     * SSL_write, not when nghttp2 merely queues/serializes it. Not peer receipt. */
    uint64_t h2_ping_received, h2_ping_ack_tls;
    bool alps;
    size_t alps_bytes;
    long verify_error;
    bool authenticated;
    uint64_t tls_bytes_sent;
    char cipher[64];
    /* Per connection; SSL_read/write elapsed includes preemption, not pure
     * crypto time. I/O includes HTTP framing; handshake is excluded. */
    uint64_t read_calls, read_bytes, read_us, read_max_us;
    uint64_t write_calls, write_bytes, write_us, write_max_us;
    uint64_t idle_wait_calls, idle_wait_us;
    int64_t sampled_us;
} meshvpn_profile_tunnel_diag_t;
typedef struct {
    /* fd is connected, nonblocking and caller-owned. All callbacks are executed
     * serially on the calling task. Firmware calls this ONLY on the PSRAM worker.
     * Strings/buffers and arg must outlive the call. No NVS access in callbacks. */
    int fd;
    const char *name, *ca_pem, *psk_hex, *profile;
    void *arg;
    bool (*current)(void *arg);
    void (*diagnostic)(void *arg, const meshvpn_profile_tunnel_diag_t *diag);
    void (*ready)(void *arg);
    /* Return framed IPv4 bytes; pointer remains stable until sent() or return.
     * 0 means no pending TX. Retries never change the pending SSL_write buffer. */
    size_t (*peek)(void *arg, const uint8_t **bytes);
    void (*sent)(void *arg, size_t length);
    bool (*receive)(void *arg, const uint8_t *bytes, size_t length);
    bool (*healthy)(void *arg); /* partial-frame deadlines, uplink health */
    const meshpn_tls_profile_t *model; /* immutable, owned by caller */
} meshvpn_profile_tunnel_options_t;
/* Returns errno-style failure (ECANCELED on orderly config cancellation).
 * No packet callbacks run before verified TLS + exact profile + v2 auth ACK.
 * ALPN chooses HTTP/2 POST duplex or HTTP/1.1 GET + framed tunnel. */
int meshvpn_profile_tunnel_run(const meshvpn_profile_tunnel_options_t *options);
/* Bounded, strict ACK parser; does not accept a public HTTP 200 cover page. */
bool meshvpn_profile_http_ack(const char *headers, size_t length);
#ifdef __cplusplus
}
#endif
