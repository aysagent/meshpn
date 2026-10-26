#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "meshvpn_ap_probe.h"
#include "meshvpn_vpn_frame.h"
#include "freertos/FreeRTOS.h"
typedef struct { uint32_t addr; } ip4_addr_t;
typedef int err_t;
#define ERR_OK 0
#define PBUF_LINK 1
#define PBUF_RAM 2
#define pdTRUE 1
struct pbuf { uint8_t *payload; unsigned tot_len; };
typedef err_t (*netif_output_fn)(struct netif *, struct pbuf *, const ip4_addr_t *);
struct netif { ip4_addr_t ip; bool napt, up, link; netif_output_fn output; };
#define netif_is_up(n) ((n)->up)
#define netif_is_link_up(n) ((n)->link)
#define netif_ip4_addr(n) (&(n)->ip)
struct eth_addr { uint8_t mac[6]; };
typedef struct { bool ready; } *SemaphoreHandle_t;
static int64_t clock_us = 1000000;
static unsigned live_sem, live_pbuf, sends, resets, ordinary_output;
static bool reply_enabled = true, corrupt, vpn_enabled, arp_busy, fail_alloc;
static uint32_t random_value = 0x12345678;
static int64_t esp_timer_get_time(void) { return clock_us; }
static uint32_t esp_random(void) { return ++random_value; }
static bool meshvpn_vpn_is_enabled(void) { return vpn_enabled; }
static esp_err_t esp_netif_tcpip_exec(esp_err_t (*fn)(void *), void *arg) { return fn(arg); }
static SemaphoreHandle_t xSemaphoreCreateBinary(void)
{ SemaphoreHandle_t s=calloc(1,sizeof(*s)); assert(s);live_sem++;return s; }
static int xSemaphoreGive(SemaphoreHandle_t s) { assert(s);s->ready=true;return 1; }
static int xSemaphoreTake(SemaphoreHandle_t s,unsigned timeout)
{ assert(s&&timeout==1200);if(s->ready){s->ready=false;return 1;}clock_us+=timeout*1000;return 0; }
static void vSemaphoreDelete(SemaphoreHandle_t s) { assert(s&&live_sem);live_sem--;free(s); }
static int etharp_find_addr(struct netif *n,const ip4_addr_t *a,struct eth_addr **m,const ip4_addr_t **p)
{ assert(n&&a&&m&&p);return arp_busy?0:-1; }
static struct pbuf *pbuf_alloc(int layer,unsigned n,int type)
{
 assert(layer==PBUF_LINK&&type==PBUF_RAM);if(fail_alloc)return NULL;
 struct pbuf *p=calloc(1,sizeof(*p));assert(p);p->payload=malloc(n);assert(p->payload);p->tot_len=n;live_pbuf++;return p;
}
static void pbuf_take(struct pbuf *p,const void *src,unsigned n)
{ assert(n==p->tot_len);memcpy(p->payload,src,n); }
static size_t pbuf_copy_partial(const struct pbuf *p,void *dst,size_t n,size_t off)
{ if(off>p->tot_len)return 0;if(n>p->tot_len-off)n=p->tot_len-off;memcpy(dst,p->payload+off,n);return n; }
static err_t ip4_input(struct pbuf *,struct netif *);
#include "ap-probe.inc"
static err_t ordinary(struct netif *n,struct pbuf *p,const ip4_addr_t *dst)
{
 assert(n==s_ap&&dst);ordinary_output++;
 uint8_t frame[94]={0};frame[12]=8;memcpy(frame+14,p->payload,p->tot_len);
 meshvpn_ap_probe_tx(1,frame,14+p->tot_len);return ERR_OK;
}
static void release(struct pbuf *p)
{ assert(live_pbuf);free(p->payload);free(p);live_pbuf--; }
static err_t ip4_input(struct pbuf *p,struct netif *n)
{
 assert(n==s_ap&&p->tot_len<=80);sends++;
 uint8_t *q=p->payload;unsigned proto=q[9];assert(proto==6||proto==17);
 uint8_t checked[80];memcpy(checked,q,p->tot_len);
 assert(meshvpn_vpn_repair_checksums(checked,p->tot_len)&&!memcmp(checked,q,p->tot_len));
 if(proto==6&&(q[33]&4)){
  assert(r32(q+24)==s_probe.seq+1&&r32(q+28)==s_probe.peer_seq+1);resets++;release(p);return ERR_OK;
 }
 if(proto==17){
  assert(p->tot_len==57&&r16(q+22)==53&&r16(q+24)==37&&q[30]==1&&q[33]==1);
  assert(!memcmp(q+40,"\7example\3com\0\0\1\0\1",17));
 }
 meshvpn_ap_probe_input(p,n);
 uint8_t wire[94]={0};wire[12]=8;memcpy(wire+14,q,p->tot_len);
 memcpy(wire+14+12,&s_sta->ip.addr,4);w16(wire+14+20,40000);
 meshvpn_ap_probe_tx(0,wire,14+p->tot_len);
 if(!reply_enabled){release(p);return ERR_OK;}
 uint8_t reply[80];memcpy(reply,q,p->tot_len);memset(reply+12,1,4);memcpy(reply+16,&s_sta->ip.addr,4);
 w16(reply+20,proto==17?53:80);w16(reply+22,40000);
 if(proto==6){w32(reply+24,0x77665544);w32(reply+28,r32(q+24)+1);reply[33]=0x12;}
 else{reply[30]=0x81;reply[31]=0x80;}
 struct pbuf response={reply,p->tot_len};meshvpn_ap_probe_input(&response,s_sta);
 memcpy(reply+16,q+12,4);w16(reply+22,r16(q+20));assert(meshvpn_vpn_repair_checksums(reply,p->tot_len));
 if(corrupt)reply[proto==17?26:36]^=1;
 ip4_addr_t dst;memcpy(&dst.addr,reply+16,4);clock_us+=5000;
 assert(n->output(n,&response,&dst)==ERR_OK);release(p);return ERR_OK;
}
int main(void)
{
 struct netif ap={.up=true,.link=true,.napt=true,.output=ordinary},sta={.up=true,.link=true};
 uint8_t a[]={192,168,11,1},b[]={192,168,1,11};memcpy(&ap.ip.addr,a,4);memcpy(&sta.ip.addr,b,4);
 /* Registration precedes default Wi-Fi netif start/output initialization. */
 ap.output=NULL;meshvpn_ap_probe_attach(&ap,&sta);assert(s_ap==&ap&&!s_output);
 ap.output=ordinary;
 meshvpn_ap_probe_result_t r[2];assert(meshvpn_ap_probe_run(r)==ESP_OK);
 for(unsigned i=0;i<2;i++)assert(r[i].received&&r[i].checksums_ok&&!r[i].error&&r[i].interface_flags==31);
 assert(r[1].flags==0x12&&resets==1&&sends==3&&!ordinary_output&&!live_sem&&!live_pbuf&&!s_probe.active);
 meshvpn_ap_flow_t flows[8];meshvpn_ap_probe_flows(flows);
 assert(flows[0].stages==15&&flows[0].synthetic&&flows[0].mapped_port==40000);
 corrupt=true;assert(meshvpn_ap_probe_run(r)==ESP_OK);assert(r[0].received&&!r[0].checksums_ok&&r[1].received&&!r[1].checksums_ok);corrupt=false;
 unsigned sent=sends;reply_enabled=false;assert(meshvpn_ap_probe_run(r)==ESP_OK);
 assert(sends==sent+6&&r[0].error==ESP_ERR_TIMEOUT&&r[1].error==ESP_ERR_TIMEOUT&&!s_probe.active);
 reply_enabled=true;arp_busy=true;sent=sends;assert(meshvpn_ap_probe_run(r)==ESP_OK);
 assert(sends==sent&&r[0].error==ESP_ERR_INVALID_STATE&&!s_probe.active);arp_busy=false;
 sta.napt=true;assert(meshvpn_ap_probe_run(r)==ESP_OK&&r[0].interface_flags==63&&sends==sent);sta.napt=false;
 vpn_enabled=true;assert(meshvpn_ap_probe_run(r)==ESP_OK&&r[0].error==ESP_ERR_INVALID_STATE&&sends==sent);vpn_enabled=false;
 fail_alloc=true;assert(meshvpn_ap_probe_run(r)==ESP_OK&&r[0].error==ESP_ERR_NO_MEM&&!s_probe.active);fail_alloc=false;
 /* Refusing a concurrent probe must not release the existing probe's state. */
 s_probe.active=true;s_probe.done=(void*)123;assert(meshvpn_ap_probe_run(r)==ESP_OK&&s_probe.active&&s_probe.done==(void*)123);s_probe.active=false;s_probe.done=NULL;
 /* A real AP client follows the unmodified output and reaches stage 16 too. */
 s_probe.client=0;uint8_t packet[40]={0};packet[0]=0x45;packet[8]=64;packet[9]=6;w16(packet+2,40);
 memcpy(packet+12,a,4);packet[15]=2;memset(packet+16,1,4);w16(packet+20,50123);w16(packet+22,80);
 w32(packet+24,12345);packet[32]=0x50;packet[33]=2;w16(packet+34,32768);assert(meshvpn_vpn_repair_checksums(packet,40));
 struct pbuf *p=pbuf_alloc(PBUF_LINK,40,PBUF_RAM);pbuf_take(p,packet,40);assert(ip4_input(p,&ap)==ERR_OK&&ordinary_output==1);
 meshvpn_ap_probe_flows(flows);bool found=false;
 for(unsigned i=0;i<8;i++)if(flows[i].seq==12345){assert(flows[i].stages==31&&!flows[i].synthetic);found=true;}
 assert(found&&!live_pbuf&&!live_sem);
 puts("AP probe: production packet/checksum construction, synthetic-only interception, timeout, VPN/ARP/role guards, cleanup and handshake stage correlation passed");
}
