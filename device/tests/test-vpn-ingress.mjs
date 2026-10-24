// Compile the production input hook. Model lwIP's netif-bound PCB filtering:
// decrypted WG replies must enter the stable vp interface, for TCP and UDP.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root=new URL('../',import.meta.url);
const text=fs.readFileSync(new URL('components/meshvpn_vpn/meshvpn_vpn.c',root),'utf8');
const injectStart=text.indexOf('static esp_err_t inject_packet(');
const injectEnd=text.indexOf('int meshvpn_vpn_dns_socket(',injectStart);
if(injectStart<0||injectEnd<injectStart)throw Error('Production socket RX injector not found');
const injectCode=text.slice(injectStart,injectEnd);
if(!injectCode.includes('pbuf_alloc(PBUF_LINK, len, PBUF_RAM)'))
  throw Error('Socket RX must reserve Ethernet headroom for forwarded replies');
if(injectCode.includes('pbuf_alloc(PBUF_RAW,'))
  throw Error('PBUF_RAW cannot be forwarded through etharp_output');
if(!text.includes('esp_netif_tcpip_exec(inject_batch, rx_batch)'))
  throw Error('Socket RX must inject a recv batch with one lwIP context switch');
const code=text.slice(text.indexOf('int meshvpn_vpn_input('),text.indexOf('static esp_err_t inject_packet(',text.indexOf('int meshvpn_vpn_input(')));
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-vpn-ingress-'));
const source=`
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "meshvpn_vpn_frame.h"
#define IP_REASSEMBLY 0
#define IPADDR_BROADCAST 0xffffffff
#define LOCK() ((void)0)
#define UNLOCK() ((void)0)
#define COUNT(field) (++s.field)
typedef struct {uint32_t addr;} ip4_addr_t;
struct pbuf;
struct netif {ip4_addr_t ip;int (*output)(struct netif*,struct pbuf*,const ip4_addr_t*);};
struct pbuf {uint16_t len,tot_len;void *payload;};
static struct netif s_vpn,wg,usb,ap,*s_usb=&usb,*s_ap=&ap;
static struct {unsigned packets_in,bytes_in,rx_dropped,mtu_feedback,mtu_feedback_failed;} s;
static unsigned freed,delivered,napt_passes,depth;
static bool enabled(void){return true;}
static struct netif *meshvpn_wg_netif(void){return &wg;}
static bool lan(const ip4_addr_t *ip,struct netif *n){return n&&memcmp(&ip->addr,&n->ip.addr,3)==0;}
static bool tunnel_policy(void){return true;}
static bool ip4_addr_ismulticast(const ip4_addr_t *a){return ((const uint8_t*)&a->addr)[0]>=224;}
#define PBUF_LINK 0
#define PBUF_RAM 0
#define ERR_OK 0
static uint8_t response_bytes[128];
static struct pbuf response;
static struct pbuf *pbuf_alloc(int layer,unsigned length,int type){(void)layer;(void)type;assert(length<=sizeof(response_bytes));response=(struct pbuf){length,length,response_bytes};return &response;}
static void pbuf_take(struct pbuf*p,const void*data,unsigned length){assert(length==p->len);memcpy(p->payload,data,length);}
static int mtu_output(struct netif*n,struct pbuf*p,const ip4_addr_t*dst){
 assert(n==&usb&&dst->addr==((uint32_t)192|((uint32_t)168<<8)|(10u<<16)|(2u<<24)));
 uint8_t *b=p->payload;assert(b[20]==3&&b[21]==4&&b[26]==5&&b[27]==120);
 assert(b[40]==192&&b[41]==168&&b[42]==10&&b[43]==2);return 0;
}
#define netif_ip4_addr(n) (&(n)->ip)
#define ip4_addr_cmp(a,b) ((a)->addr==(b)->addr)
#define ip4_addr_isany_val(a) (!(a).addr)
static unsigned pbuf_copy_partial(struct pbuf*p,void*out,unsigned len,unsigned off){
 if(off>=p->tot_len)return 0;
 if(len>p->tot_len-off)len=p->tot_len-off;
 memcpy(out,(uint8_t*)p->payload+off,len);return len;
}
// Header checksum implementation is not under test in this ingress identity model.
static unsigned inet_chksum(const void*p,unsigned len){(void)p;(void)len;return 0;}
static void pbuf_free(struct pbuf*p){(void)p;freed++;}
int meshvpn_vpn_input(struct pbuf*,struct netif*);
static void ip4_input(struct pbuf*p,struct netif*n){
 assert(++depth<3); // no recursion loop
 if(!meshvpn_vpn_input(p,n)){
   napt_passes++;
   if(n==&s_vpn)delivered++; // TCP/UDP bound to vp reject wg ingress
   pbuf_free(p);
 }
 depth--;
}
${code}
static void run(unsigned protocol){
 uint8_t packet[40]={0x45};packet[3]=protocol==6?40:28;packet[9]=protocol;
 packet[12]=1;packet[13]=1;packet[14]=1;packet[15]=1;
 packet[16]=10;packet[19]=7;memcpy(&s_vpn.ip.addr,packet+16,4);
 packet[32]=0x50;packet[33]=0x10; // TCP header, no MSS edit
 if(protocol==17)packet[25]=8; // UDP length
 struct pbuf p={packet[3],packet[3],packet};
 unsigned before_rx=s.packets_in,before_delivered=delivered,before_free=freed,before_nat=napt_passes;
 ip4_input(&p,&wg);
 assert(s.packets_in==before_rx+1&&delivered==before_delivered+1);
 assert(freed==before_free+1&&napt_passes==before_nat+1); // ownership/NAPT exactly once
 // socket transport already enters vp and must not be redirected again
 ip4_input(&p,&s_vpn);assert(s.packets_in==before_rx+1&&delivered==before_delivered+2);
 // Wrong inner destination remains blocked before delivery/NAPT.
 packet[19]=8;unsigned dropped=s.rx_dropped;
 ip4_input(&p,&wg);assert(s.rx_dropped==dropped+1&&delivered==before_delivered+2);
}
int main(void){run(6);run(17);
 uint8_t ip[1500]={0x45,0,5,220};ip[6]=0x40;ip[8]=64;ip[9]=17;
 uint8_t client[]={192,168,10,2},gateway[]={192,168,10,1};
 memcpy(ip+12,client,4);ip[16]=1;ip[17]=1;ip[18]=1;ip[19]=1;
 ip[20]=0xc0;ip[21]=1;ip[23]=53;ip[24]=5;ip[25]=200;
 memcpy(&usb.ip.addr,gateway,4);usb.output=mtu_output;
 struct pbuf p={sizeof(ip),sizeof(ip),ip};
 assert(meshvpn_vpn_input(&p,&usb)==1&&s.mtu_feedback==1&&!s.mtu_feedback_failed);
 ip[6]=0;assert(meshvpn_vpn_input(&p,&usb)==0); // DF clear reaches lwIP fragmentation
 puts("VPN ingress: WG replies reach vp-bound TCP/DNS, single NAPT/ownership, invalid destination blocked");}
`;
const file=path.join(dir,'test.c'),bin=path.join(dir,'test');fs.writeFileSync(file,source);
execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
 '-I'+new URL('components/meshvpn_vpn/include',root).pathname,file,
 new URL('components/meshvpn_vpn/meshvpn_vpn_frame.c',root).pathname,'-o',bin],{stdio:'inherit'});
execFileSync(bin,{stdio:'inherit'});
