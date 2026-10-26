#include "meshvpn_ap_echo.h"
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "meshvpn_vpn.h"
#include "meshvpn_vpn_frame.h"
#include "lwip/etharp.h"
#include "lwip/ip4.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

/* Core-thread-owned state; the HTTP worker only supplies immutable config.
 * A single authenticated HTTP worker serializes echo and handshake probes. */
static struct {
    bool active;
    struct netif *ap, *sta;
    meshvpn_ap_echo_config_t c;
    meshvpn_ap_echo_result_t r;
    uint32_t client, nonce;
    uint16_t source_port;
    uint64_t start, last_send, *sent_at, late_until;
    uint8_t *packet, seen[512];
} s_echo;
static uint16_t rd16(const uint8_t *p) { return ((uint16_t)p[0]<<8)|p[1]; }
static uint32_t rd32(const uint8_t *p) { return ((uint32_t)rd16(p)<<16)|rd16(p+2); }
static void wr16(uint8_t *p,uint16_t v) { p[0]=v>>8;p[1]=v; }
static void wr32(uint8_t *p,uint32_t v) { wr16(p,v>>16);wr16(p+2,v); }

static bool echo_tuple(const uint8_t *h,size_t n,bool reply)
{
    if(n<44||h[0]!=0x45||h[9]!=17||(h[6]&0x3f)||h[7])return false;
    uint32_t remote;memcpy(&remote,h+(reply?12:16),4);
    return remote==s_echo.c.target&&rd16(h+(reply?20:22))==s_echo.c.port&&
        rd32(h+28)==0x4d504e45&&rd32(h+32)==s_echo.nonce;
}
void meshvpn_ap_echo_tx(unsigned ifx,const void *frame,size_t length)
{
    const uint8_t *p=frame;
    if(s_echo.active&&!ifx&&p&&length>=58&&p[12]==8&&!p[13]&&echo_tuple(p+14,length-14,false)){
        s_echo.r.accepted++;s_echo.r.mapped_source_port=rd16(p+14+20);
    }
}
bool meshvpn_ap_echo_output(struct pbuf *p,uint32_t destination)
{
    if(!p||destination!=s_echo.client||(!s_echo.active&&(uint64_t)esp_timer_get_time()>s_echo.late_until))return false;
    uint8_t h[44];size_t n=pbuf_copy_partial(p,h,sizeof(h),0);
    if(!echo_tuple(h,n,true)||rd16(h+22)!=s_echo.source_port)return false;
    if(!s_echo.active)return true; /* late replies to the last synthetic tuple */
    unsigned seq=rd32(h+36),length=rd16(h+2);
    if(seq>=s_echo.r.injected||length!=s_echo.c.payload+28||length>p->tot_len)return true;
    if(pbuf_copy_partial(p,s_echo.packet,length,0)!=length)return true;
    uint16_t ip=rd16(s_echo.packet+10),udp=rd16(s_echo.packet+26);
    if(!meshvpn_vpn_repair_checksums(s_echo.packet,length)||ip!=rd16(s_echo.packet+10)||
        (udp&&udp!=rd16(s_echo.packet+26))) { s_echo.r.bad_checksum++;return true; }
    uint8_t mask=1U<<(seq&7);
    if(s_echo.seen[seq/8]&mask)s_echo.r.duplicates++;
    else {
        s_echo.seen[seq/8]|=mask;s_echo.r.received++;
        uint64_t rtt=esp_timer_get_time()-s_echo.sent_at[seq];s_echo.r.rtt_sum_us+=rtt;
        if(rtt>s_echo.r.rtt_max_us)s_echo.r.rtt_max_us=rtt;
    }
    return true;
}
typedef struct { struct netif *ap,*sta;const meshvpn_ap_echo_config_t *c; } begin_t;
static esp_err_t begin(void *arg)
{
    begin_t *b=arg;const meshvpn_ap_echo_config_t *c=b->c;
    if(s_echo.active||meshvpn_vpn_is_enabled()||!b->ap||!b->sta||!netif_is_up(b->ap)||
        !netif_is_link_up(b->ap)||!b->ap->napt||!netif_is_up(b->sta)||!netif_is_link_up(b->sta)||b->sta->napt)return ESP_ERR_INVALID_STATE;
    ip4_addr_t target={.addr=c->target};
    if(!netif_ip4_addr(b->sta)->addr||!netif_ip4_netmask(b->sta)->addr)return ESP_ERR_INVALID_STATE;
    if(!c->packets||c->packets>4096||c->payload<32||c->payload>1200||c->port<1024||
        c->rate_kbps<64||c->rate_kbps>30000||(c->source_port&&c->source_port<1024)||
        (uint64_t)c->packets*(c->payload+28)*8>UINT64_C(10000)*c->rate_kbps||
        !ip4_addr_netcmp(&target,netif_ip4_addr(b->sta),netif_ip4_netmask(b->sta))||
        ip4_addr_cmp(&target,netif_ip4_addr(b->sta))||
        target.addr==(netif_ip4_addr(b->sta)->addr&netif_ip4_netmask(b->sta)->addr)||
        ip4_addr_isbroadcast(&target,b->sta)||ip4_addr_ismulticast(&target))return ESP_ERR_INVALID_ARG;
    uint32_t client=netif_ip4_addr(b->ap)->addr;((uint8_t*)&client)[3]=254;
    ip4_addr_t address={.addr=client};struct eth_addr *mac;const ip4_addr_t *known;
    if(etharp_find_addr(b->ap,&address,&mac,&known)>=0)return ESP_ERR_INVALID_STATE;
    uint8_t *packet=heap_caps_malloc(c->payload+28,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    uint64_t *times=heap_caps_calloc(c->packets,sizeof(uint64_t),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    if(!packet||!times){heap_caps_free(packet);heap_caps_free(times);return ESP_ERR_NO_MEM;}
    memset(&s_echo,0,sizeof(s_echo));s_echo.ap=b->ap;s_echo.sta=b->sta;s_echo.c=*c;
    s_echo.packet=packet;s_echo.sent_at=times;s_echo.client=client;s_echo.nonce=esp_random();
    s_echo.source_port=c->source_port?c->source_port:49152+(esp_random()&16383);
    s_echo.start=esp_timer_get_time();s_echo.active=true;
    return ESP_OK;
}
static esp_err_t pump(void *arg)
{
    bool *complete=arg;uint64_t now=esp_timer_get_time();
    if(meshvpn_vpn_is_enabled()||!netif_is_up(s_echo.ap)||!netif_is_link_up(s_echo.sta))return ESP_ERR_INVALID_STATE;
    unsigned length=s_echo.c.payload+28;
    uint64_t due=(now-s_echo.start)*s_echo.c.rate_kbps/(length*UINT64_C(8000))+1;
    unsigned batch=0;
    while(s_echo.r.injected<s_echo.c.packets&&s_echo.r.injected<due&&batch++<8){
        unsigned seq=s_echo.r.injected;uint8_t *q=s_echo.packet;
        memset(q,0,length);q[0]=0x45;wr16(q+2,length);wr16(q+4,seq);q[8]=64;q[9]=17;
        memcpy(q+12,&s_echo.client,4);memcpy(q+16,&s_echo.c.target,4);
        wr16(q+20,s_echo.source_port);wr16(q+22,s_echo.c.port);wr16(q+24,length-20);
        wr32(q+28,0x4d504e45);wr32(q+32,s_echo.nonce);wr32(q+36,seq);
        if(!meshvpn_vpn_repair_checksums(q,length))return ESP_FAIL;
        struct pbuf *p=pbuf_alloc(PBUF_LINK,length,PBUF_RAM);if(!p)return ESP_ERR_NO_MEM;
        pbuf_take(p,q,length);s_echo.sent_at[seq]=esp_timer_get_time();s_echo.r.injected++;
        s_echo.last_send=esp_timer_get_time();
        if(ip4_input(p,s_echo.ap)!=ERR_OK)return ESP_FAIL;
    }
    now=esp_timer_get_time();
    *complete=(s_echo.r.injected==s_echo.c.packets&&
        (s_echo.r.received==s_echo.c.packets||now-s_echo.last_send>2000000))||now-s_echo.start>12000000;
    return ESP_OK;
}
static esp_err_t finish(void *arg)
{
    meshvpn_ap_echo_result_t *r=arg;s_echo.r.total_us=esp_timer_get_time()-s_echo.start;
    s_echo.r.send_us=s_echo.last_send?s_echo.last_send-s_echo.start:0;
    *r=s_echo.r;s_echo.active=false;s_echo.late_until=esp_timer_get_time()+10000000;
    heap_caps_free(s_echo.packet);heap_caps_free(s_echo.sent_at);s_echo.packet=NULL;s_echo.sent_at=NULL;
    return ESP_OK;
}
esp_err_t meshvpn_ap_echo_run(struct netif *ap,struct netif *sta,
    const meshvpn_ap_echo_config_t *c,meshvpn_ap_echo_result_t *r)
{
    memset(r,0,sizeof(*r));begin_t b={ap,sta,c};esp_err_t error=esp_netif_tcpip_exec(begin,&b);
    if(error!=ESP_OK)return error;
    bool complete=false;
    while(!complete&&(error=esp_netif_tcpip_exec(pump,&complete))==ESP_OK)vTaskDelay(pdMS_TO_TICKS(1));
    esp_netif_tcpip_exec(finish,r);r->error=error;return ESP_OK;
}
