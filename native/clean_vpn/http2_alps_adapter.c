#include "http2_alps_adapter.h"
#include "nghttp2_session.h"

/* ALPS settings are already acknowledged by TLS. Feeding synthetic frames
 * through mem_recv would enqueue an unsolicited ACK; upgrade2 reserves stream
 * 1. Use the pinned library's settings handlers before any stream exists. */
static int fresh(nghttp2_session *s) {
  return !s->last_sent_stream_id && !s->last_recv_stream_id &&
         !s->remote_settings_received && !s->inflight_settings_head &&
         !s->goaway_flags;
}
int cvpn_h2_remote_alps(nghttp2_session *s, nghttp2_settings_entry *iv, size_t n) {
  nghttp2_frame frame = {0};
  int rv;
  if (!fresh(s) || s->server || s->iframe.state != NGHTTP2_IB_READ_FIRST_SETTINGS)
    return NGHTTP2_ERR_INVALID_STATE;
  frame.settings.hd.type = NGHTTP2_SETTINGS;
  frame.settings.hd.length = n * 6;
  frame.settings.iv = iv;
  frame.settings.niv = n;
  rv = nghttp2_session_on_settings_received(s, &frame, 1);
  if (rv || s->goaway_flags) return rv ? rv : NGHTTP2_ERR_PROTO;
  s->iframe.state = NGHTTP2_IB_READ_HEAD;
  return 0;
}
int cvpn_h2_local_alps(nghttp2_session *s, nghttp2_settings_entry *iv, size_t n) {
  int rv;
  if (!fresh(s) || !s->server || s->iframe.state != NGHTTP2_IB_READ_CLIENT_MAGIC)
    return NGHTTP2_ERR_INVALID_STATE;
  rv = nghttp2_session_update_local_settings(s, iv, n);
  if (rv) return rv;
  s->pending_local_max_concurrent_stream = s->local_settings.max_concurrent_streams;
  s->pending_enable_push = (uint8_t)s->local_settings.enable_push;
  s->pending_no_rfc7540_priorities = 0;
  s->local_settings.no_rfc7540_priorities = 0;
  /* The client's ALPS is empty: still require its magic and wire SETTINGS. */
  return 0;
}
