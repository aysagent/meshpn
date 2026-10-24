import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const production=fs.readFileSync(new URL('../components/meshvpn_vpn/meshvpn_wireguard.c',import.meta.url),'utf8');
const a=production.indexOf('bool meshvpn_wg_clock_ready('),b=production.indexOf('struct netif *meshvpn_wg_netif(',a);
if(a<0||b<a)throw Error('Clock bootstrap implementation not found');
const source=`
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#define ESP_SNTP_OPMODE_POLL 0
static unsigned init_calls,server_calls;
static time_t current;
static time_t test_time(time_t*result){if(result)*result=current;return current;}
#define time test_time
static void esp_sntp_setoperatingmode(unsigned m){assert(m==ESP_SNTP_OPMODE_POLL);}
static void esp_sntp_setservername(unsigned i,const char*name){struct in_addr a;assert(i==0&&inet_pton(AF_INET,name,&a)==1);server_calls++;}
static void esp_sntp_init(void){init_calls++;}
${production.slice(a,b)}
int main(void){
 assert(!meshvpn_wg_clock_ready()&&init_calls==1&&server_calls==1);
 assert(!meshvpn_wg_clock_ready()&&init_calls==1&&server_calls==1);
 current=1800000000;assert(meshvpn_wg_clock_ready()&&init_calls==1);
}
`;
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-wg-clock-')),file=path.join(dir,'test.c'),binary=path.join(dir,'test');
fs.writeFileSync(file,source);
execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=undefined',file,'-o',binary],{stdio:'inherit'});
execFileSync(binary,{stdio:'inherit'});
console.log('WG clock: one numeric NTP bootstrap, no DNS dependency, ready only after time is valid');
