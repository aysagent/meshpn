#include "profile_h2_alps.h"
#include "nghttp2_session.h"

/* Private integration adapted from native/clean_vpn/http2_alps_adapter.c.
 * Both builds pin nghttp2 534b74b72524e962c18c7146470914632ca7eb2d;
 * re-audit private structure/handler semantics before changing that pin. */
int meshvpn_h2_apply_alps(nghttp2_session *s, const uint8_t *p, size_t n) {
    nghttp2_settings_entry entries[6];
    nghttp2_frame frame = {0};
    unsigned seen = 0;
    if (!s || s->server || s->last_sent_stream_id || s->last_recv_stream_id ||
        s->remote_settings_received || s->inflight_settings_head || s->goaway_flags ||
        s->iframe.state != NGHTTP2_IB_READ_FIRST_SETTINGS)
        return NGHTTP2_ERR_INVALID_STATE;
    if (!n) return 0;
    /* One non-ACK SETTINGS frame; no ACCEPT_CH, unknown frames, duplicate IDs. */
    if (!p || n < 9 || n > 45 || p[0] || p[1] || p[2] != n-9 || (n-9)%6 ||
        p[3] != NGHTTP2_SETTINGS || p[4] || p[5] || p[6] || p[7] || p[8])
        return NGHTTP2_ERR_PROTO;
    for (size_t i=9, j=0; i<n; i+=6, j++) {
        unsigned id = ((unsigned)p[i]<<8) | p[i+1];
        uint32_t value = ((uint32_t)p[i+2]<<24) | ((uint32_t)p[i+3]<<16) |
                         ((uint32_t)p[i+4]<<8) | p[i+5];
        if (id<1 || id>6 || (seen & (1u<<id))) return NGHTTP2_ERR_PROTO;
        seen |= 1u<<id;
        if ((id==1 && value>65536) || (id==2 && value!=0) ||
            (id==4 && value>0x7fffffff) ||
            (id==5 && (value<16384 || value>16777215))) return NGHTTP2_ERR_PROTO;
        entries[j].settings_id=(int32_t)id; entries[j].value=value;
    }
    frame.settings.hd.type=NGHTTP2_SETTINGS;
    frame.settings.hd.length=n-9;
    frame.settings.iv=entries; frame.settings.niv=(n-9)/6;
    /* noack=1: acknowledged by TLS, not by an extra HTTP/2 frame. */
    int rc=nghttp2_session_on_settings_received(s,&frame,1);
    if (rc || s->goaway_flags) return rc ? rc : NGHTTP2_ERR_PROTO;
    s->iframe.state=NGHTTP2_IB_READ_HEAD;
    return 0;
}
