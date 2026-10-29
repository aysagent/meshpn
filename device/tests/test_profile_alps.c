#include "profile_h2_alps.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static nghttp2_session *fresh(void) {
    nghttp2_session *s=NULL;nghttp2_session_callbacks *cb=NULL;
    assert(!nghttp2_session_callbacks_new(&cb));
    assert(!nghttp2_session_client_new(&s,cb,NULL));
    nghttp2_session_callbacks_del(cb);return s;
}
int main(void) {
    uint8_t valid[]={0,0,18,4,0,0,0,0,0, 0,3,0,0,0,1, 0,4,0,16,0,0, 0,6,0,0,32,0};
    nghttp2_session *s=fresh();
    assert(!meshvpn_h2_apply_alps(s,valid,sizeof valid));
    assert(nghttp2_session_get_remote_settings(s,NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE)==1048576);
    assert(meshvpn_h2_apply_alps(s,valid,sizeof valid)==NGHTTP2_ERR_INVALID_STATE);
    const uint8_t *out=NULL;
    assert(nghttp2_session_mem_send2(s,&out)==24); // client magic only, no ALPS ACK
    assert(nghttp2_session_mem_send2(s,&out)==0);
    nghttp2_session_del(s);
    s=fresh();assert(!meshvpn_h2_apply_alps(s,NULL,0));nghttp2_session_del(s);
    for(unsigned mutation=0;mutation<10;mutation++) {
        uint8_t bad[sizeof valid];memcpy(bad,valid,sizeof bad);size_t n=sizeof bad;
        switch(mutation) {
        case 0:bad[4]=1;break;case 1:bad[8]=1;break;case 2:n--;break;
        case 3:bad[17]=128;break;case 4:bad[10]=8;break;
        case 5:bad[22]=3;break;case 6:bad[3]=0;break;
        case 7:bad[10]=1;bad[11]=1;break;
        case 8:bad[10]=2;break;case 9:bad[10]=5;break;
        }
        s=fresh();assert(meshvpn_h2_apply_alps(s,bad,n)==NGHTTP2_ERR_PROTO);
        // Validation must finish before any settings change.
        assert(nghttp2_session_get_remote_settings(s,NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE)==65535);
        nghttp2_session_del(s);
    }
    puts("ALPS validation, remote settings and no synthetic ACK passed");return 0;
}
