#include <assert.h>
#include <string.h>
#include "meshvpn_local_upload.h"
typedef struct { unsigned reads; int result; int64_t clock, step; } state;
static int64_t now(void *ctx) { state *s=ctx; s->clock+=s->step; return s->clock; }
static int receive(void *ctx, char *p, size_t n)
{
    state *s=ctx;s->reads++;assert(n<=1024);memset(p,0,n);
    if(s->result<=0)return s->result;
    return s->result==9999?(int)n+1:s->result<(int)n?s->result:(int)n;
}
int main(void)
{
    size_t n;state s={.result=137};
    assert(meshvpn_local_upload(&s,3019,receive,now,&n)&&n==3019&&s.reads==23);
    s=(state){.result=1024};assert(meshvpn_local_upload(&s,MESHVPN_LOCAL_UPLOAD_MAX,receive,now,&n));
    assert(n==MESHVPN_LOCAL_UPLOAD_MAX&&s.reads==8192);
    for(int result=-2;result<=0;result++){
        s=(state){.result=result};assert(!meshvpn_local_upload(&s,100,receive,now,&n)&&n==0&&s.reads==1);
    }
    s=(state){.result=9999};assert(!meshvpn_local_upload(&s,100,receive,now,&n)&&n==0);
    s=(state){.result=1,.step=1000000};assert(!meshvpn_local_upload(&s,100,receive,now,&n)&&n==29);
    s=(state){.result=1,.step=MESHVPN_LOCAL_UPLOAD_BUDGET_US};
    assert(!meshvpn_local_upload(&s,100,receive,now,&n)&&!n&&!s.reads);
    s=(state){0};assert(!meshvpn_local_upload(&s,0,receive,now,&n)&&!s.reads);
    assert(!meshvpn_local_upload(&s,MESHVPN_LOCAL_UPLOAD_MAX+1,receive,now,&n)&&!s.reads);
    return 0;
}
