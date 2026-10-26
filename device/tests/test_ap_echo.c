#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "meshvpn_ap_echo.h"
#include "meshvpn_vpn_frame.h"
#include "freertos/FreeRTOS.h"
typedef struct {uint32_t addr;} ip4_addr_t;
typedef int err_t;
struct netif {ip4_addr_t ip,mask;bool up,link,napt;};
struct pbuf {uint8_t *payload;unsigned tot_len;};
struct eth_addr {uint8_t mac[6];};
#define ERR_OK 0
#define PBUF_LINK 1
#define PBUF_RAM 2
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define netif_is_up(n) ((n)->up)
#define netif_is_link_up(n) ((n)->link)
#define netif_ip4_addr(n) (&(n)->ip)
#define netif_ip4_netmask(n) (&(n)->mask)
#define ip4_addr_netcmp(a,b,m) (((a)->addr&(m)->addr)==((b)->addr&(m)->addr))
#define ip4_addr_cmp(a,b) ((a)->addr==(b)->addr)
static bool ip4_addr_isbroadcast(const ip4_addr_t *p,struct netif *n)
{return(p->addr|n->mask.addr)==UINT32_MAX;}
static bool ip4_addr_ismulticast(const ip4_addr_t *p){return(((const uint8_t*)&p->addr)[0]&0xf0)==0xe0;}
static uint64_t clock_us=1000000;
static unsigned allocations,pbufs,drop_mod,corrupt_mod,duplicates;
static int fail_alloc;
static bool arp_busy,vpn,flip_vpn;
static uint64_t esp_timer_get_time(void){return clock_us;}
static uint32_t esp_random(void){return 0x3456789a;}
static void vTaskDelay(unsigned t){assert(t==1);clock_us+=1000;}
static bool meshvpn_vpn_is_enabled(void){return vpn;}
static esp_err_t esp_netif_tcpip_exec(esp_err_t (*fn)(void*),void *p){return fn(p);}
static void *heap_caps_malloc(size_t n,int caps)
{assert(caps==3);if(fail_alloc&&!--fail_alloc)return NULL;void *p=malloc(n);assert(p);allocations++;return p;}
static void *heap_caps_calloc(size_t n,size_t s,int caps)
{void *p=heap_caps_malloc(n*s,caps);if(p)memset(p,0,n*s);return p;}
static void heap_caps_free(void *p){if(p){assert(allocations);allocations--;free(p);}}
static int etharp_find_addr(struct netif *n,const ip4_addr_t *a,struct eth_addr **m,const ip4_addr_t **p)
{assert(n&&a&&m&&p);return arp_busy?0:-1;}
static struct pbuf *pbuf_alloc(int layer,unsigned n,int type)
{assert(layer==PBUF_LINK&&type==PBUF_RAM);struct pbuf *p=calloc(1,sizeof(*p));assert(p);p->payload=malloc(n);assert(p->payload);p->tot_len=n;pbufs++;return p;}
static void pbuf_take(struct pbuf *p,const void *src,unsigned n){assert(n==p->tot_len);memcpy(p->payload,src,n);}
static size_t pbuf_copy_partial(const struct pbuf *p,void *dst,size_t n,size_t off)
{if(off>p->tot_len)return 0;if(n>p->tot_len-off)n=p->tot_len-off;memcpy(dst,p->payload+off,n);return n;}
static err_t ip4_input(struct pbuf *,struct netif *);
#include "ap-echo.inc"
static unsigned char late[1228];static unsigned late_size;
static err_t ip4_input(struct pbuf *p,struct netif *n)
{
 assert(n==s_echo.ap);unsigned len=p->tot_len;uint8_t *h=p->payload;
 uint8_t copy[1228];assert(len<=sizeof(copy));memcpy(copy,h,len);
 assert(meshvpn_vpn_repair_checksums(copy,len)&&!memcmp(copy,h,len));
 unsigned seq=rd32(h+36);
 uint8_t eth[1242]={0};eth[12]=8;memcpy(eth+14,h,len);memcpy(eth+26,&s_echo.sta->ip.addr,4);
 meshvpn_ap_echo_tx(0,eth,len+14);
 if(!drop_mod||seq%drop_mod){
  memcpy(copy+12,h+16,4);memcpy(copy+16,h+12,4);wr16(copy+20,rd16(h+22));wr16(copy+22,rd16(h+20));
  assert(meshvpn_vpn_repair_checksums(copy,len));if(corrupt_mod&&!(seq%corrupt_mod))copy[26]^=1;
  struct pbuf response={copy,len};clock_us+=100;
  assert(meshvpn_ap_echo_output(&response,s_echo.client));
  if(duplicates)assert(meshvpn_ap_echo_output(&response,s_echo.client));
  memcpy(late,copy,len);late_size=len;
 }
 if(flip_vpn)vpn=true;
 free(p->payload);free(p);assert(pbufs);pbufs--;return ERR_OK;
}
static uint32_t addr(unsigned a,unsigned b,unsigned c,unsigned d)
{uint8_t v[4]={a,b,c,d};uint32_t x;memcpy(&x,v,4);return x;}
int main(void)
{
 struct netif ap={.ip={addr(192,168,11,1)},.mask={addr(255,255,255,0)},.up=true,.link=true,.napt=true};
 struct netif sta={.ip={addr(192,168,1,11)},.mask={addr(255,255,255,0)},.up=true,.link=true};
 meshvpn_ap_echo_config_t c={.target=addr(192,168,1,4),.port=55000,.packets=100,.payload=1200,.rate_kbps=5000};
 meshvpn_ap_echo_result_t r;assert(meshvpn_ap_echo_run(&ap,&sta,&c,&r)==ESP_OK);
 assert(!r.error&&r.injected==100&&r.accepted==100&&r.received==100&&!r.bad_checksum&&r.rtt_sum_us==10000);
 assert(!allocations&&!pbufs&&!s_echo.active);
 struct pbuf p={late,late_size};assert(meshvpn_ap_echo_output(&p,s_echo.client));
 late[32]^=1;assert(!meshvpn_ap_echo_output(&p,s_echo.client));late[32]^=1;
 drop_mod=3;assert(meshvpn_ap_echo_run(&ap,&sta,&c,&r)==ESP_OK&&r.received==66&&r.total_us>2000000);drop_mod=0;
 corrupt_mod=5;assert(meshvpn_ap_echo_run(&ap,&sta,&c,&r)==ESP_OK&&r.received==80&&r.bad_checksum==20);corrupt_mod=0;
 duplicates=1;assert(meshvpn_ap_echo_run(&ap,&sta,&c,&r)==ESP_OK&&r.received==100&&r.duplicates==100);duplicates=0;
 for(int i=1;i<=2;i++){fail_alloc=i;assert(meshvpn_ap_echo_run(&ap,&sta,&c,&r)==ESP_ERR_NO_MEM&&!allocations);}
 arp_busy=true;assert(meshvpn_ap_echo_run(&ap,&sta,&c,&r)==ESP_ERR_INVALID_STATE);arp_busy=false;
 vpn=true;assert(meshvpn_ap_echo_run(&ap,&sta,&c,&r)==ESP_ERR_INVALID_STATE);vpn=false;
 meshvpn_ap_echo_config_t bad=c;bad.target=addr(8,8,8,8);assert(meshvpn_ap_echo_run(&ap,&sta,&bad,&r)==ESP_ERR_INVALID_ARG);
 bad=c;bad.target=sta.ip.addr;assert(meshvpn_ap_echo_run(&ap,&sta,&bad,&r)==ESP_ERR_INVALID_ARG);
 bad=c;bad.target=addr(192,168,1,255);assert(meshvpn_ap_echo_run(&ap,&sta,&bad,&r)==ESP_ERR_INVALID_ARG);
 bad=c;bad.payload=1201;assert(meshvpn_ap_echo_run(&ap,&sta,&bad,&r)==ESP_ERR_INVALID_ARG);
 bad=c;bad.packets=4097;assert(meshvpn_ap_echo_run(&ap,&sta,&bad,&r)==ESP_ERR_INVALID_ARG);
 bad=c;bad.port=53;assert(meshvpn_ap_echo_run(&ap,&sta,&bad,&r)==ESP_ERR_INVALID_ARG);
 bad=c;bad.rate_kbps=64;assert(meshvpn_ap_echo_run(&ap,&sta,&bad,&r)==ESP_ERR_INVALID_ARG);
 flip_vpn=true;assert(meshvpn_ap_echo_run(&ap,&sta,&c,&r)==ESP_OK&&r.error==ESP_ERR_INVALID_STATE);flip_vpn=false;vpn=false;
 assert(!allocations&&!pbufs&&!s_echo.active);
 c.packets=4096;c.payload=32;c.rate_kbps=30000;
 assert(meshvpn_ap_echo_run(&ap,&sta,&c,&r)==ESP_OK&&r.received==4096&&!allocations&&!pbufs);
 puts("AP echo: actual packet/checksum construction, pacing, loss/duplicate/corruption accounting, late reply filter, target/range/policy guards and cleanup passed");
}
