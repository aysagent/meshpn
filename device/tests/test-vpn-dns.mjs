// Execute production DNS binding, cache epochs and final STA egress guard.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root = new URL('../',import.meta.url);
const vpn = fs.readFileSync(new URL('components/meshvpn_vpn/meshvpn_vpn.c',root),'utf8');
const proxy = fs.readFileSync(new URL('components/meshvpn_routing/meshvpn_dns_proxy.c',root),'utf8');
function section(s,from,to) { const a=s.indexOf(from),b=s.indexOf(to,a); if(a<0||b<a)throw Error(from);return s.slice(a,b); }
const source = `
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "meshvpn_vpn.h"
#include "meshvpn_vpn_frame.h"
#include "meshvpn_dns_proxy.h"
#include "meshvpn_dns_wire.h"
#define DNS_UDP_MAX 1232
#define LOCK() ((void)0)
#define UNLOCK() ((void)0)
#define COUNT(name) (++s_stats.name)
#define portMAX_DELAY 0
typedef int SemaphoreHandle_t;
static meshvpn_vpn_status_t s;
static meshvpn_vpn_config_t s_config;
static meshvpn_dns_stats_t s_stats;
static uint32_t s_probe_epoch;
static int s_vpn;
static int64_t now=1000000;
static int64_t esp_timer_get_time(void){return now;}
static void xSemaphoreTake(int m,int d){(void)m;(void)d;}
static void xSemaphoreGive(int m){(void)m;}
static bool binding_fail,bound_device,bound_source;
static int netif_get_index(int*n){assert(n==&s_vpn);return 7;}
static char*netif_index_to_name(int i,char*out){assert(i==7);return strcpy(out,"vp0");}
bool meshvpn_vpn_is_connected(void){return s.connected;}
static size_t test_strlcpy(char*d,const char*p,size_t n){size_t len=strlen(p);if(n){size_t c=len<n-1?len:n-1;memcpy(d,p,c);d[c]=0;}return len;}
#define strlcpy test_strlcpy
static int test_setsockopt(int f,int l,int o,const void*v,socklen_t n){
 assert(f==3&&l==SOL_SOCKET&&o==SO_BINDTODEVICE&&n==sizeof(struct ifreq));
 assert(!strcmp(((const struct ifreq*)v)->ifr_name,"vp0"));bound_device=true;return binding_fail?-1:0;
}
static int test_bind(int f,const struct sockaddr*a,socklen_t n){
 assert(f==3&&bound_device&&n==sizeof(struct sockaddr_in));
 assert(((const struct sockaddr_in*)a)->sin_addr.s_addr==inet_addr(s.address));bound_source=true;return 0;
}
#define setsockopt test_setsockopt
#define bind test_bind
${section(vpn,'static bool tunnel_policy(','struct netif *meshvpn_vpn_route(')}
${section(vpn,'int meshvpn_vpn_dns_socket(','esp_err_t meshvpn_vpn_check_internet(')}
#undef COUNT
#define COUNT(name) (++s.name)
${section(vpn,'bool meshvpn_vpn_sta_egress_allowed(','static err_t output(')}
#undef COUNT
#define COUNT(name) (++s_stats.name)
${section(proxy,'#define CACHE_SLOTS ','static void timeout(')}
int main(void){
 uint32_t resolver=inet_addr("9.9.9.9");
 assert(meshvpn_vpn_dns_socket(3,&resolver)==0&&!bound_device);
 s.enabled=s.kill_switch=true;assert(meshvpn_vpn_dns_socket(3,&resolver)==-1&&!bound_device);
 s.connected=true;strcpy(s.address,"10.99.0.2");strcpy(s.transport,"tls");
 assert(meshvpn_vpn_dns_socket(3,&resolver)==0&&bound_source&&resolver==inet_addr("1.1.1.1"));
 strcpy(s.transport,"wireguard");strcpy(s_config.wg_dns,"8.8.8.8");
 assert(meshvpn_vpn_dns_socket(3,&resolver)==0&&resolver==inet_addr("8.8.8.8"));
 bound_source=false;binding_fail=true;assert(meshvpn_vpn_dns_socket(3,&resolver)==-1&&!bound_source);
 binding_fail=false;s.connected=false;s.kill_switch=false;
 bound_device=false;assert(meshvpn_vpn_dns_socket(3,&resolver)==0&&!bound_device);
 uint8_t frame[14+28]={0};frame[12]=8;frame[14]=0x45;frame[23]=17;frame[36]=0;frame[37]=53;
 assert(meshvpn_vpn_sta_egress_allowed(frame,sizeof(frame)));
 s.kill_switch=true;assert(!meshvpn_vpn_sta_egress_allowed(frame,sizeof(frame))&&s.direct_dns_blocked==1);
 frame[23]=6;assert(!meshvpn_vpn_sta_egress_allowed(frame,sizeof(frame)));
 frame[37]=123;assert(meshvpn_vpn_sta_egress_allowed(frame,sizeof(frame))); // time sync retained
 strcpy(s.server,"192.0.2.1:53");strcpy(s.transport,"udp");frame[23]=17;frame[37]=53;
 memcpy(frame+30,(uint8_t[]){192,0,2,1},4);assert(meshvpn_vpn_sta_egress_allowed(frame,sizeof(frame)));
 frame[23]=6;assert(!meshvpn_vpn_sta_egress_allowed(frame,sizeof(frame))); // wrong outer protocol
 s_cache=calloc(CACHE_SLOTS,sizeof(*s_cache));assert(s_cache);s_cache_lock=1;
 uint8_t query[]={0x73,0x52,1,0,0,1,0,0,0,0,0,0,1,'a',0,0,1,0,1};
 uint8_t reply[512],out[512];unsigned n=meshvpn_dns_reply(query,sizeof(query),reply,sizeof(reply),0,false,inet_addr("198.18.0.1"));assert(n);
 uint32_t g=cache_generation();cache_put(query,sizeof(query),reply,n,g,0);
 assert(cache_get(query,sizeof(query),out,0)==(int)n);
 s_probe_epoch++;assert(!cache_get(query,sizeof(query),out,s_probe_epoch)); // direct answer never reused in VPN
 cache_put(query,sizeof(query),reply,n,g,0);assert(!cache_get(query,sizeof(query),out,s_probe_epoch)); // stale completion
 cache_put(query,sizeof(query),reply,n,g,s_probe_epoch);assert(cache_get(query,sizeof(query),out,s_probe_epoch)==(int)n);
 meshvpn_dns_clear_cache();assert(!cache_get(query,sizeof(query),out,s_probe_epoch));
 cache_put(query,sizeof(query),reply,n,g,s_probe_epoch);assert(!cache_get(query,sizeof(query),out,s_probe_epoch));
 free(s_cache);
 puts("DNS policy: bound VPN source/interface, no disconnected fallback, final STA DNS guard, cache generations and stale responses passed");
}
`;
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-dns-policy-')),file=path.join(dir,'test.c'),binary=path.join(dir,'test');
fs.writeFileSync(file,source);
execFileSync(process.env.CC||'cc',['-std=c11','-D_DEFAULT_SOURCE','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=undefined',
  ...['tests/stubs','components/meshvpn_config/include','components/meshvpn_vpn/include','components/meshvpn_routing/include'].map(p=>'-I'+new URL(p,root).pathname),
  file,new URL('components/meshvpn_vpn/meshvpn_vpn_frame.c',root).pathname,
  new URL('components/meshvpn_routing/meshvpn_dns_wire.c',root).pathname,'-o',binary],{stdio:'inherit'});
execFileSync(binary,{stdio:'inherit'});
