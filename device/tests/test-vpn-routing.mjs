// Compile the actual route selector against a minimal IPv4/netif model.
// This tests policy, not lwIP's NAPT implementation or hardware forwarding.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const file=fs.readFileSync(new URL('../components/meshvpn_vpn/meshvpn_vpn.c',import.meta.url),'utf8');
const start=file.indexOf('static bool lan('),end=file.indexOf('static void notify_socket_tx(',start);
if(start<0||end<start)throw Error('Production route selector not found');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-vpn-route-'));
const source=`
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
typedef struct ip4_addr {uint32_t addr;} ip4_addr_t;
struct netif {ip4_addr_t ip,mask;};
static struct netif s_vpn={{0x0a630002},{0xffffffff}},usb={{0xc0a80701},{0xffffff00}},ap={{0xc0a80401},{0xffffff00}};
static struct netif *s_usb=&usb,*s_ap=&ap;
static bool s_ready=true;
static struct { bool enabled,kill_switch,connected; char transport[32];
  uint32_t socket_rx_to_usb,socket_rx_to_ap,socket_last_return_src,socket_last_return_dst;
  int64_t socket_last_return_us; } s={.enabled=true,.kill_switch=true,.transport="socket"};
#define LOCK() ((void)0)
#define UNLOCK() ((void)0)
#define esp_timer_get_time() 1234
#define netif_ip4_addr(n) (&(n)->ip)
#define netif_ip4_netmask(n) (&(n)->mask)
#define ip4_addr_netcmp(a,b,m) (((a)->addr&(m)->addr)==((b)->addr&(m)->addr))
#define ip4_addr_cmp(a,b) ((a)->addr==(b)->addr)
#define ip4_addr_ismulticast(a) (((a)->addr&0xf0000000)==0xe0000000)
#define IPADDR_BROADCAST 0xffffffff
static bool plain_transport(const char*n){return n&&(!strcmp(n,"socket")||!strcmp(n,"udp"));}
${file.slice(start,end)}
int main(void){
ip4_addr_t client={0xc0a80702},apclient={0xc0a80402},wan={0x01010101},sta={0xc0a8010a};
assert(meshvpn_vpn_route(&client,&wan)==&s_vpn);
assert(meshvpn_vpn_route(&apclient,&wan)==&s_vpn);
assert(meshvpn_vpn_route(&sta,&wan)==NULL); /* outer tunnel bypass */
assert(meshvpn_vpn_route(&usb.ip,&wan)==NULL); /* board services */
assert(meshvpn_vpn_route(&client,&apclient)==NULL);
assert(meshvpn_vpn_route(&wan,&client)==NULL);assert(s.socket_rx_to_usb==1);
assert(meshvpn_vpn_route(&wan,&apclient)==NULL);assert(s.socket_rx_to_ap==1);
assert(meshvpn_vpn_route(NULL,&wan)==NULL);
s.enabled=false;assert(meshvpn_vpn_route(&client,&wan)==NULL);
assert(meshvpn_vpn_route(&s_vpn.ip,&wan)==&s_vpn); /* old DNS cannot leak */
s.enabled=true;s.kill_switch=false;
assert(meshvpn_vpn_route(&client,&wan)==NULL);assert(meshvpn_vpn_route(&apclient,&wan)==NULL);
assert(meshvpn_vpn_route(&s_vpn.ip,&wan)==&s_vpn); /* bound probe NEVER uses fallback */
s.connected=true;assert(meshvpn_vpn_route(&client,&wan)==&s_vpn);
assert(meshvpn_vpn_route(&apclient,&wan)==&s_vpn);
s.connected=false;s.kill_switch=true;
assert(meshvpn_vpn_route(&client,&wan)==&s_vpn);
s.connected=true;strcpy(s.transport,"udp");
assert(meshvpn_vpn_route(&client,&wan)==&s_vpn);
assert(meshvpn_vpn_route(&wan,&client)==NULL);assert(s.socket_rx_to_usb==2);
s_usb=NULL;assert(meshvpn_vpn_route(&apclient,&wan)==&s_vpn);
return 0;
}`;
fs.writeFileSync(path.join(dir,'test.c'),source);
execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',path.join(dir,'test.c'),'-o',path.join(dir,'test')]);
execFileSync(path.join(dir,'test'));
console.log('Production VPN routing policy: USB/AP, outer bypass, local access and disconnected blackhole passed');
