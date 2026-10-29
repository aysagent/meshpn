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
struct pbuf { uint8_t *payload; unsigned tot_len, len; };
typedef err_t (*netif_output_fn)(struct netif *, struct pbuf *, const ip4_addr_t *);
struct netif { ip4_addr_t ip, mask; bool napt, up, link; netif_output_fn output; };
#define netif_is_up(n) ((n)->up)
#define netif_is_link_up(n) ((n)->link)
#define netif_ip4_addr(n) (&(n)->ip)
#define netif_ip4_netmask(n) (&(n)->mask)
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
 struct pbuf *p=calloc(1,sizeof(*p));assert(p);p->payload=malloc(n);assert(p->payload);p->len=p->tot_len=n;live_pbuf++;return p;
}
static void pbuf_take(struct pbuf *p,const void *src,unsigned n)
{ assert(n==p->tot_len);memcpy(p->payload,src,n); }
static size_t pbuf_copy_partial(const struct pbuf *p,void *dst,size_t n,size_t off)
{ if(off>p->tot_len)return 0;if(n>p->tot_len-off)n=p->tot_len-off;memcpy(dst,p->payload+off,n);return n; }
static err_t ip4_input(struct pbuf *,struct netif *);
static unsigned csum_sum(unsigned sum,const uint8_t *p,size_t n)
{for(size_t i=0;i<n;i+=2)sum+=(unsigned)p[i]*256+(i+1<n?p[i+1]:0);return sum;}
static unsigned csum_finish(unsigned sum){while(sum>>16)sum=(sum&65535)+(sum>>16);return (~sum)&65535;}
static unsigned inet_chksum(const void *p,unsigned n){return csum_finish(csum_sum(0,p,n));}
static unsigned inet_chksum_pseudo(struct pbuf *p,unsigned proto,unsigned n,const ip4_addr_t *src,const ip4_addr_t *dst)
{return csum_finish(csum_sum(csum_sum(csum_sum(proto+n,(const uint8_t*)&src->addr,4),(const uint8_t*)&dst->addr,4),p->payload,p->len));}
void meshvpn_ap_echo_tx(unsigned i,const void *p,size_t n) { (void)i;(void)p;(void)n; }
bool meshvpn_ap_echo_output(struct pbuf *p,uint32_t d) { (void)p;(void)d;return false; }
esp_err_t meshvpn_ap_echo_run(struct netif *ap,struct netif *sta,
    const meshvpn_ap_echo_config_t *c,meshvpn_ap_echo_result_t *r)
{ (void)ap;(void)sta;(void)c;(void)r;return ESP_FAIL; }
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
 struct pbuf response={.payload=reply,.tot_len=p->tot_len,.len=p->tot_len};meshvpn_ap_probe_input(&response,s_sta);
 memcpy(reply+16,q+12,4);w16(reply+22,r16(q+20));assert(meshvpn_vpn_repair_checksums(reply,p->tot_len));
 if(corrupt)reply[proto==17?26:36]^=1;
 ip4_addr_t dst;memcpy(&dst.addr,reply+16,4);clock_us+=5000;
 assert(n->output(n,&response,&dst)==ERR_OK);release(p);return ERR_OK;
}
static void test_sta_tcp(void)
{
 uint8_t h[120]={0},saved[120];h[0]=0x45;h[9]=6;w16(h+2,40);
 uint8_t peer[]={192,168,1,4};memcpy(h+12,peer,4);memcpy(h+16,&s_sta->ip.addr,4);
 w16(h+20,58000);w16(h+22,80);w32(h+24,0xfffffff0u);h[32]=0x50;h[33]=2;
 meshvpn_sta_tcp_trace_t v;meshvpn_ap_probe_sta_tcp(&v);assert(!v.total_events);
 for(unsigned n=0;n<40;n++)sta_tcp(false,h,n,40);
 meshvpn_ap_probe_sta_tcp(&v);assert(!v.total_events);
 memcpy(saved,h,sizeof(h));sta_tcp(false,h,40,40);assert(!memcmp(h,saved,sizeof(h)));
 sta_tcp(false,h,40,40);meshvpn_ap_probe_sta_tcp(&v);
 assert(v.total_events==2&&v.packets[0]==2&&v.peer_port==58000&&v.initial_seq==0xfffffff0u);
 /* New ISN on a reused tuple starts a new flow; sequence values stay unsigned. */
 w32(h+24,10);sta_tcp(false,h,40,40);meshvpn_ap_probe_sta_tcp(&v);assert(v.total_events==1);
 h[33]=0x10;h[32]=0x80;w16(h+2,52);h[40]=5;h[41]=10;w32(h+42,100);w32(h+46,200);h[50]=0;
 sta_tcp(false,h,52,52);meshvpn_ap_probe_sta_tcp(&v);
 assert(v.count==2&&v.events[1].sack_blocks==1&&v.events[1].sack_left==100&&v.events[1].sack_right==200);
 h[41]=11;sta_tcp(false,h,52,52);meshvpn_ap_probe_sta_tcp(&v);assert(v.total_events==2);
 h[41]=10;h[6]=0x20;sta_tcp(false,h,52,52);h[6]=0;
 w16(h+2,20);sta_tcp(false,h,52,52);w16(h+2,52);
 sta_tcp(false,h,51,52);sta_tcp(false,h,52,51);meshvpn_ap_probe_sta_tcp(&v);assert(v.total_events==2);
 /* TX retains only TCP metadata even for a large body; ring wraps in order. */
 memcpy(h+12,&s_sta->ip.addr,4);memcpy(h+16,peer,4);w16(h+20,80);w16(h+22,58000);
 h[32]=0x50;w16(h+2,1040);w16(h+34,12345);
 for(unsigned i=0;i<100;i++){clock_us+=1000;w32(h+24,4000+i*1000);sta_tcp(true,h,40,1040);}
 meshvpn_ap_probe_sta_tcp(&v);assert(v.count==64&&v.total_events==102);
 assert(v.packets[1]==100&&v.data_bytes[1]==100000);
 assert(v.events[0].seq==40000&&v.events[63].seq==103000);
 assert(v.events[63].window==12345&&v.events[63].payload==1000&&v.events[63].tx);
 assert(v.events[0].elapsed_ms<v.events[63].elapsed_ms);
 w16(h+20,443);sta_tcp(true,h,40,1040);meshvpn_ap_probe_sta_tcp(&v);assert(v.total_events==102);
 w16(h+20,80);w16(h+2,40);assert(meshvpn_vpn_repair_checksums(h,40));
 sta_tcp(true,h,40,40);meshvpn_ap_probe_sta_tcp(&v);
 assert(v.events[63].checksum_checked&&!v.events[63].bad_ip&&!v.events[63].bad_tcp);
 h[34]^=1;sta_tcp(true,h,40,40);meshvpn_ap_probe_sta_tcp(&v);
 assert(v.events[63].checksum_checked&&!v.events[63].bad_ip&&v.events[63].bad_tcp);
 assert(v.checked[1]==2&&!v.bad_ip[1]&&v.bad_tcp[1]==1);
 /* AP tracing has independent tuples/storage and never changes packet bytes. */
 meshvpn_sta_tcp_trace_t old=v,ap;meshvpn_ap_probe_ap_tcp(&ap);assert(!ap.total_events);
 memset(h,0,sizeof(h));h[0]=0x45;h[9]=6;w16(h+2,40);h[32]=0x50;h[33]=2;
 memcpy(h+12,peer,4);memcpy(h+16,&s_ap->ip.addr,4);w16(h+20,58001);w16(h+22,80);w32(h+24,123);
 assert(meshvpn_vpn_repair_checksums(h,40));memcpy(saved,h,sizeof(h));
 wifi_tcp(true,false,h,40,40);assert(!memcmp(h,saved,sizeof(h)));
 meshvpn_ap_probe_ap_tcp(&ap);assert(ap.total_events==1&&ap.peer_port==58001&&!ap.bad_tcp[0]);
 meshvpn_ap_probe_sta_tcp(&v);assert(v.total_events==old.total_events&&v.peer_port==old.peer_port);
}
static void test_tcp_client(void)
{
 uint8_t target[]={192,168,1,1},mask[]={255,255,255,0};uint32_t peer;
 memcpy(&peer,target,4);memcpy(&s_sta->mask.addr,mask,4);
 vpn_enabled=true;assert(meshvpn_ap_probe_tcp_client(peer)==ESP_ERR_INVALID_STATE);vpn_enabled=false;
 uint32_t external=0x01010101;assert(meshvpn_ap_probe_tcp_client(external)==ESP_ERR_INVALID_STATE);
 assert(meshvpn_ap_probe_tcp_client(s_sta->ip.addr)==ESP_ERR_INVALID_STATE);
 uint8_t other[]={192,168,2,1};memcpy(&external,other,4);
 assert(meshvpn_ap_probe_tcp_client(external)==ESP_ERR_INVALID_STATE);
 target[3]=255;memcpy(&external,target,4);assert(meshvpn_ap_probe_tcp_client(external)==ESP_ERR_INVALID_STATE);
 assert(meshvpn_ap_probe_tcp_client(peer)==ESP_OK);
 uint8_t h[40]={0},saved[40];h[0]=0x45;h[9]=6;w16(h+2,40);h[32]=0x50;h[33]=2;
 memcpy(h+12,&s_sta->ip.addr,4);memcpy(h+16,&peer,4);w16(h+20,58003);w16(h+22,80);w32(h+24,1234);
 assert(meshvpn_vpn_repair_checksums(h,40));memcpy(saved,h,40);
 sta_tcp(true,h,40,40);assert(!memcmp(h,saved,40));
 meshvpn_sta_tcp_trace_t v;meshvpn_ap_probe_sta_tcp(&v);
 assert(v.client&&v.armed&&v.total_events==1&&v.local_port==58003&&v.peer_port==80);
 memcpy(h+12,&peer,4);memcpy(h+16,&s_sta->ip.addr,4);w16(h+20,80);w16(h+22,58003);h[33]=0x12;
 assert(meshvpn_vpn_repair_checksums(h,40));sta_tcp(false,h,40,40);
 meshvpn_ap_probe_sta_tcp(&v);assert(v.total_events==2&&!v.bad_tcp[0]&&!v.bad_tcp[1]);
 w16(h+22,58004);sta_tcp(false,h,40,40);meshvpn_ap_probe_sta_tcp(&v);assert(v.total_events==2);
 w16(h+22,58003);clock_us+=120000000;sta_tcp(false,h,40,40);
 meshvpn_ap_probe_sta_tcp(&v);assert(!v.armed&&v.client&&v.total_events==2);
 assert(meshvpn_ap_probe_tcp_client(0)==ESP_OK);meshvpn_ap_probe_sta_tcp(&v);
 assert(!v.armed&&!v.client&&!v.total_events);
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
 /* Independent checksum observation never repairs or mutates incoming bytes. */
 memset(s_checksums,0,sizeof(s_checksums));assert(meshvpn_vpn_repair_checksums(packet,sizeof(packet)));
 struct pbuf observed={.payload=packet,.tot_len=40,.len=40};
 meshvpn_ap_probe_input(&observed,&sta);assert(s_checksums[0].checked==1&&!s_checksums[0].bad_ip&&!s_checksums[0].bad_tcp);
 packet[8]++;for(unsigned i=0;i<32;i++)meshvpn_ap_probe_input(&observed,&sta);
 assert(s_checksums[0].bad_ip==1&&!s_checksums[0].bad_tcp);
 assert(meshvpn_vpn_repair_checksums(packet,40));packet[33]^=0x40;
 for(unsigned i=0;i<32;i++)meshvpn_ap_probe_input(&observed,&sta);
 assert(s_checksums[0].bad_tcp==1&&s_checksums[0].checked==3);
 observed.len=10;for(unsigned i=0;i<32;i++)meshvpn_ap_probe_input(&observed,&sta);
 assert(s_checksums[0].skipped==1);
 memset(s_checksums,0,sizeof(s_checksums));assert(meshvpn_vpn_repair_checksums(packet,40));
 uint8_t ethernet[54]={0};ethernet[12]=8;memcpy(ethernet+14,packet,40);
 meshvpn_ap_probe_tx(0,ethernet,sizeof(ethernet));assert(s_checksums[2].checked==1&&!s_checksums[2].bad_tcp);
 ethernet[14+33]^=0x40;
 for(unsigned i=0;i<32;i++)meshvpn_ap_probe_tx(0,ethernet,sizeof(ethernet));
 assert(s_checksums[2].bad_tcp==1&&s_checksums[2].checked==2);
 test_sta_tcp();test_tcp_client();
 /* Forwarded USB SYNs get their own ingress stage; USB admin is excluded. */
 uint8_t uh[40]={0};uh[0]=0x45;uh[9]=6;w16(uh+2,40);uh[32]=0x50;uh[33]=2;
 uint8_t usrc[]={192,168,10,2},udst[]={192,168,13,1};memcpy(uh+12,usrc,4);memcpy(uh+16,udst,4);
 w16(uh+20,58002);w16(uh+22,80);w32(uh+24,76543);
 struct netif usb={.ip={.addr=0x010aa8c0}};struct pbuf up={.payload=uh,.len=40,.tot_len=40};
 meshvpn_ap_probe_usb_input(&up,&usb);bool saw_usb=false;
 for(unsigned i=0;i<8;i++)if(s_flows[i].seq==76543){assert(s_flows[i].stages==32);saw_usb=true;}
 assert(saw_usb);unsigned previous_next=s_next;memcpy(uh+16,&usb.ip.addr,4);w32(uh+24,76544);
 meshvpn_ap_probe_usb_input(&up,&usb);assert(s_next==previous_next);

 /* ARP observer is bounded, accepts only Ethernet IPv4 ARP, and never mutates. */
 uint8_t arp[42]={0};w16(arp+12,0x0806);w16(arp+14,1);w16(arp+16,0x0800);
 arp[18]=6;arp[19]=4;w16(arp+20,1);memcpy(arp+28,usrc,4);memcpy(arp+38,udst,4);
 uint8_t saved_arp[42];memcpy(saved_arp,arp,42);meshvpn_arp_event_t arps[8];
 meshvpn_ap_probe_arp(0,0,NULL,42);meshvpn_ap_probe_arp(0,0,arp,41);meshvpn_ap_probe_arp(2,0,arp,42);
 assert(meshvpn_ap_probe_arp_snapshot(arps)==0);
 for(unsigned i=0;i<10;i++){arp[27]=i;meshvpn_ap_probe_arp(0,i&1,arp,42);}
 assert(meshvpn_ap_probe_arp_snapshot(arps)==8&&arps[0].sender_mac[5]==2&&arps[7].sender_mac[5]==9);
 assert(arps[7].tx&&arps[7].operation==1&&!memcmp(&arps[7].sender,usrc,4));
 arp[27]=0;assert(!memcmp(saved_arp,arp,42));arp[19]=16;meshvpn_ap_probe_arp(0,0,arp,42);
 assert(meshvpn_ap_probe_arp_snapshot(arps)==8&&arps[7].sender_mac[5]==9);
 puts("AP probe: packet/checksums, ownership, guards, handshake stages, bounded TCP/SACK and ARP traces passed");
}
