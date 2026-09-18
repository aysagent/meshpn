// Production probe; socket boundary mocked to verify binding, deadlines and
// stale-result rejection. No claim of real server reachability.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root=new URL('../',import.meta.url);
const text=fs.readFileSync(new URL('components/meshvpn_vpn/meshvpn_vpn.c',root),'utf8');
const code=text.slice(text.indexOf('esp_err_t meshvpn_vpn_check_internet('),text.indexOf('static esp_err_t wg_poll('));
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-vpn-probe-'));
const source=`
#define _DEFAULT_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include "meshvpn_vpn.h"
#define ESP_ERR_INVALID_STATE 9
#define LOCK() ((void)0)
#define UNLOCK() ((void)0)
static meshvpn_vpn_status_t s;
static uint32_t s_probe_epoch;
static int s_vpn;
static bool bound_device,bound_address,binding_fail,change_epoch;
static int select_result=1,socket_error=0,connections;
static int64_t esp_timer_get_time(void){return 1000000;}
static int netif_get_index(int*n){assert(n==&s_vpn);return 7;}
static char *netif_index_to_name(int n,char*out){assert(n==7);return strcpy(out,"vp0");}
static int fake_socket(int f,int t,int p){assert(f==AF_INET&&t==SOCK_STREAM&&p==IPPROTO_TCP);bound_device=bound_address=false;return 3;}
static int fake_setsockopt(int f,int level,int option,const void*value,socklen_t len){
 assert(f==3&&level==SOL_SOCKET&&option==SO_BINDTODEVICE&&len==sizeof(struct ifreq));
 assert(!strcmp(((const struct ifreq*)value)->ifr_name,"vp0"));
 if(binding_fail){errno=ENODEV;return -1;}bound_device=true;return 0;
}
static int fake_bind(int f,const struct sockaddr*a,socklen_t len){
 assert(f==3&&bound_device&&len==sizeof(struct sockaddr_in));
 assert(((const struct sockaddr_in*)a)->sin_addr.s_addr==inet_addr("10.0.0.7"));bound_address=true;return 0;
}
static int fake_fcntl(int f,int op,int flags){assert(f==3&&op==F_SETFL&&flags==O_NONBLOCK);return 0;}
static int fake_connect(int f,const struct sockaddr*a,socklen_t len){
 assert(f==3&&bound_device&&bound_address&&len==sizeof(struct sockaddr_in));
 assert(((const struct sockaddr_in*)a)->sin_addr.s_addr==inet_addr("1.1.1.1"));
 assert(((const struct sockaddr_in*)a)->sin_port==htons(443));connections++;errno=EINPROGRESS;return -1;
}
static int fake_select(int n,fd_set*r,fd_set*w,fd_set*e,struct timeval*t){
 assert(n==4&&!r&&w&&!e&&t->tv_sec==5&&!t->tv_usec);
 if(change_epoch)s_probe_epoch++;
 return select_result;
}
static int fake_getsockopt(int f,int level,int op,void*out,socklen_t*len){
 assert(f==3&&level==SOL_SOCKET&&op==SO_ERROR&&*len==sizeof(int));*(int*)out=socket_error;return 0;
}
static int fake_close(int f){assert(f==3);return 0;}
#define socket fake_socket
#define setsockopt fake_setsockopt
#define bind fake_bind
#define fcntl fake_fcntl
#define connect fake_connect
#define select fake_select
#define getsockopt fake_getsockopt
#define close fake_close
${code}
int main(void){
 assert(meshvpn_vpn_check_internet()==ESP_ERR_INVALID_STATE&&!connections);
 s.enabled=true;s.connected=true;strcpy(s.address,"10.0.0.7");
 s.kill_switch=false; // probe must still never use DIRECT fallback
 assert(meshvpn_vpn_check_internet()==ESP_OK&&s.probe_ok&&s.probe_at_us==1000000);
 select_result=0;assert(meshvpn_vpn_check_internet()==ESP_OK&&!s.probe_ok&&s.probe_error==ETIMEDOUT);
 select_result=1;socket_error=ECONNREFUSED;assert(meshvpn_vpn_check_internet()==ESP_OK&&!s.probe_ok&&s.probe_error==ECONNREFUSED);
 binding_fail=true;int calls=connections;
 assert(meshvpn_vpn_check_internet()==ESP_OK&&!s.probe_ok&&connections==calls);
 binding_fail=false;socket_error=0;change_epoch=true;s.probe_at_us=0;
 assert(meshvpn_vpn_check_internet()==ESP_ERR_INVALID_STATE&&!s.probe_at_us);
 puts("VPN probe: forced interface/source, bounded timeout, failures and stale-result rejection passed");
}
`;
const file=path.join(dir,'test.c'),bin=path.join(dir,'test');fs.writeFileSync(file,source);
execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
 '-I'+new URL('tests/stubs',root).pathname,'-I'+new URL('components/meshvpn_config/include',root).pathname,
 '-I'+new URL('components/meshvpn_vpn/include',root).pathname,file,'-o',bin],{stdio:'inherit'});
execFileSync(bin,{stdio:'inherit'});
