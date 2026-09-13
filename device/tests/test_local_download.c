#include <assert.h>
#include "meshvpn_local_download.h"

typedef struct { size_t bytes, calls; int64_t clock, step; bool fail; } state;
static int64_t now(void *ctx) { state *s=ctx; s->clock+=s->step; return s->clock; }
static bool send_block(void *ctx,const char *data,size_t len)
{
    state *s=ctx; s->calls++;
    assert(len==4096);
    for(size_t i=0;i<len;i++) assert(data[i]==0);
    if(s->fail) return false;
    s->bytes+=len; return true;
}
int main(void)
{
    state s={0};
    assert(meshvpn_local_download(&s,send_block,now));
    assert(s.bytes==8388608 && s.calls==2048);
    s=(state){.fail=true};
    assert(!meshvpn_local_download(&s,send_block,now)); assert(s.calls==1 && s.bytes==0);
    s=(state){.step=MESHVPN_LOCAL_DOWNLOAD_BUDGET_US};
    assert(!meshvpn_local_download(&s,send_block,now)); assert(s.calls==0);
    s=(state){.step=1000000};
    assert(!meshvpn_local_download(&s,send_block,now)); assert(s.calls==29);
    return 0;
}
