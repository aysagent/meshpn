// Exercise the production netif output boundary with real IPv4 validation.
// A LAN-sourced ICMP must not reach native exit and kill an authenticated peer.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root=new URL('../',import.meta.url);
const text=fs.readFileSync(new URL('components/meshvpn_vpn/meshvpn_vpn.c',root),'utf8');
function section(a,b){const x=text.indexOf(a),y=text.indexOf(b,x);if(x<0||y<x)throw Error(a);return text.slice(x,y);}
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-vpn-output-'));
fs.writeFileSync(path.join(dir,'test.c'),`
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "meshvpn_vpn.h"
#include "meshvpn_vpn_frame.h"
typedef int err_t;
typedef struct { uint32_t addr; } ip4_addr_t;
struct netif { ip4_addr_t ip; };
struct pbuf { unsigned tot_len; uint8_t data[1500]; };
static struct netif s_vpn;
static meshvpn_vpn_status_t s;
static struct {char transport[32];} s_config;
static unsigned sent, wg_sent;
#define LOCK() ((void)0)
#define UNLOCK() ((void)0)
#define COUNT(k) (s.k++)
#define netif_ip4_addr(n) (&(n)->ip)
#define ip4_addr_cmp(a,b) ((a)->addr==(b)->addr)
#define ERR_OK 0
#define ERR_BUF -1
#define ERR_VAL -2
#define ERR_RTE -3
#define ERR_MEM -4
#define PBUF_RAW 0
#define PBUF_RAM 0
static int64_t esp_timer_get_time(void){return 1;}
static bool enabled(void){return true;}
static bool meshvpn_wg_up(void){return true;}
static void pbuf_copy_partial(struct pbuf*p,void*d,unsigned n,unsigned off){memcpy(d,p->data+off,n);}
static struct pbuf *pbuf_alloc(int a,unsigned n,int b){(void)a;(void)b;struct pbuf*p=calloc(1,sizeof(*p));p->tot_len=n;return p;}
static void pbuf_take(struct pbuf*p,const void*d,unsigned n){memcpy(p->data,d,n);}
static void pbuf_free(struct pbuf*p){free(p);}
static err_t meshvpn_wg_output(struct pbuf*p,const ip4_addr_t*d){(void)p;(void)d;wg_sent++;return ERR_OK;}
esp_err_t meshvpn_vpn_send_ipv4(const uint8_t*p,uint16_t n){
 assert(n>=20);assert(!memcmp(p+12,&s_vpn.ip.addr,4));sent++;return ESP_OK;
}
${section('static void tuple(', 'void meshvpn_vpn_lan_egress(')}
${section('static err_t output(', 'static err_t net_init(')}
int main(void){
 inet_pton(AF_INET,"10.99.0.4",&s_vpn.ip.addr);
 const char *transports[]={"tcp","udp","tls","boring-tls"};
 for(unsigned t=0;t<4;t++)for(unsigned proto=0;proto<3;proto++){
  strcpy(s_config.transport,transports[t]);
  struct pbuf p={.tot_len=60,.data={0x45,0,0,60}};
  p.data[8]=63;p.data[9]=(unsigned[]){1,6,17}[proto];
  p.data[32]=0x50;p.data[20]=3;p.data[25]=40;
  inet_pton(AF_INET,"192.168.12.2",p.data+12);inet_pton(AF_INET,"1.1.1.1",p.data+16);
  unsigned before=sent,drops=s.tx_dropped;
  assert(output(&s_vpn,&p,NULL)==ERR_RTE&&sent==before&&s.tx_dropped==drops+1);
  memcpy(p.data+12,&s_vpn.ip.addr,4);
  assert(output(&s_vpn,&p,NULL)==ERR_OK&&sent==before+1);
 }
 assert(s.socket_tx_source_other==12&&s.socket_tx_source_tunnel==12);
 struct pbuf bad={.tot_len=10};assert(output(&s_vpn,&bad,NULL)==ERR_VAL);
 bad.tot_len=1500;assert(output(&s_vpn,&bad,NULL)==ERR_BUF);
 strcpy(s_config.transport,"wireguard");
 struct pbuf wg={.tot_len=28,.data={0x45,0,0,28}};wg.data[9]=1;wg.data[20]=8;
 assert(output(&s_vpn,&wg,NULL)==ERR_OK&&wg_sent==1&&sent==12);
 return 0;
}
`);
execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
 ...['tests/stubs','components/meshvpn_profiled_tls/include','components/meshvpn_config/include','components/meshvpn_vpn/include'].map(p=>'-I'+new URL(p,root).pathname),
 path.join(dir,'test.c'),new URL('components/meshvpn_vpn/meshvpn_vpn_frame.c',root).pathname,'-o',path.join(dir,'test')],{stdio:'inherit'});
execFileSync(path.join(dir,'test'),{stdio:'inherit'});
console.log('VPN output: untranslated LAN sources rejected before transport; valid tunnel traffic and WireGuard preserved');
