// Inject failure at every permanent allocation/task-creation boundary in init.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root = new URL('../', import.meta.url);
const production = fs.readFileSync(new URL('components/meshvpn_vpn/meshvpn_vpn.c', root), 'utf8');
const start = production.indexOf('esp_err_t meshvpn_vpn_init(void)');
if (start < 0) throw Error('Production init missing');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'meshpn-vpn-init-'));
const source = `
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CONFIG_MESHVPN_VPN_ENABLE 1
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define MESHVPN_VPN_SLOTS 256
#define MESHVPN_VPN_WORKER_PRIORITY 6
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 12
#define ESP_ERR_INVALID_STATE 20
#define pdPASS 1
typedef int esp_err_t;
typedef void *TaskHandle_t;
typedef struct { unsigned char data[1400]; } packet_t;
typedef struct { unsigned char data[45000]; } meshvpn_vpn_tx_batch_t;
typedef struct { unsigned char data[56000]; } rx_worker_buffers_t;
static struct { bool implemented; char state[24],transport[24],address[24]; uint32_t wg_handshake_age; } s;
typedef struct { uint8_t bytes[4]; } ip4_addr_t;
#define IP4_ADDR(p,a,b,c,d) (*(p)=(ip4_addr_t){{a,b,c,d}})
static void ip4addr_ntoa_r(const ip4_addr_t *ip,char *out,size_t len) {
 snprintf(out,len,"%u.%u.%u.%u",ip->bytes[0],ip->bytes[1],ip->bytes[2],ip->bytes[3]);
}
${production.slice(production.indexOf('static ip4_addr_t tunnel_address(void)'),production.indexOf('esp_err_t meshvpn_vpn_validate_config('))}
static bool s_ready, fail_netif;
static packet_t *s_queue;
static meshvpn_vpn_tx_batch_t *s_socket_tx_batch;
static TaskHandle_t s_socket_tx_task, s_socket_rx_task;
static unsigned step, fail_step, live_allocs, live_tasks, netif_adds;
static unsigned entropy_starts;
#if CONFIG_MESHVPN_PROFILED_TLS_ENABLE && CONFIG_IDF_TARGET_ESP32P4
static void bootloader_random_enable(void) { assert(!step && !live_tasks); entropy_starts++; }
#endif
static void *rx_arg;
static size_t copy_string(char *d,const char *p,size_t n) {
 size_t len=strlen(p); assert(len<n); memcpy(d,p,len+1); return len;
}
static void *heap_caps_calloc(size_t n,size_t size,unsigned caps) {
 assert(caps==(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT));
 if(++step==fail_step)return NULL;
 void *p=calloc(n,size);assert(p);live_allocs++;return p;
}
static void release(void *p) { if(p){assert(live_allocs);live_allocs--;free(p);} }
static void socket_tx_worker(void *p) { (void)p; }
static void worker(void *p) { (void)p; }
static int xTaskCreate(void (*fn)(void *),const char *name,unsigned stack,void *arg,unsigned prio,TaskHandle_t *out) {
 assert(name && prio==6 && live_allocs==3);
 if(fn==socket_tx_worker){assert(stack==4096 && arg==s_socket_tx_batch);}
 else {assert(fn==worker && stack==6144 && arg);rx_arg=arg;}
 if(++step==fail_step)return 0;
 *out=fn==worker?(void *)2:(void *)1;live_tasks++;return pdPASS;
}
static void vTaskDelete(TaskHandle_t h) { assert(h && live_tasks);live_tasks--; }
static esp_err_t add_netif(void *p) { assert(!p && !s_ready);netif_adds++;s_ready=true;return ESP_OK; }
static esp_err_t esp_netif_tcpip_exec(esp_err_t (*fn)(void *),void *arg) {
 return fail_netif?ESP_FAIL:fn(arg);
}
#define free release
#define strlcpy copy_string
${production.slice(start)}
#undef free
int main(void) {
 fail_netif=true;assert(meshvpn_vpn_init()==ESP_FAIL);
 assert(!step && !live_allocs && !live_tasks && !s.implemented);
 fail_netif=false;
 for(fail_step=1;fail_step<=5;fail_step++) {
   step=0;assert(meshvpn_vpn_init()==ESP_ERR_NO_MEM);
   assert(!s.implemented && !live_allocs && !live_tasks);
   assert(!s_queue && !s_socket_tx_batch && !s_socket_rx_task && !s_socket_tx_task);
   assert(netif_adds==1); /* Failed startup retry must not re-add the same netif. */
 }
 fail_step=0;step=0;assert(meshvpn_vpn_init()==ESP_OK);
 char expected[24];snprintf(expected,sizeof(expected),"10.99.0.%d",CONFIG_MESHVPN_TUNNEL_HOST_OCTET);assert(!strcmp(s.address,expected));
 assert(s.implemented && live_allocs==3 && live_tasks==2 && rx_arg);
 assert(meshvpn_vpn_init()==ESP_ERR_INVALID_STATE && netif_adds==1 && step==5);
 assert(entropy_starts==CONFIG_MESHVPN_PROFILED_TLS_ENABLE);
 vTaskDelete(s_socket_rx_task);vTaskDelete(s_socket_tx_task);
 release(rx_arg);release(s_queue);release(s_socket_tx_batch);
 assert(!live_allocs && !live_tasks);
 puts("VPN startup: allocation/task failure cleanup, retry, RX storage and duplicate-init guard passed");
}
`;
const file = path.join(dir, 'test.c'), binary = path.join(dir, 'test');
fs.writeFileSync(file, source);
for (const host of [2,3,4]) for (const profiled of [0,1]) {
execFileSync(process.env.CC || 'cc', ['-std=c11', '-Wall', '-Wextra', '-Werror',
  '-DCONFIG_MESHVPN_TUNNEL_HOST_OCTET='+host, '-DCONFIG_IDF_TARGET_ESP32P4=1', '-DCONFIG_MESHVPN_PROFILED_TLS_ENABLE='+profiled,
  '-fsanitize=address,undefined', file, '-o', binary], {stdio:'inherit'});
execFileSync(binary, [], {stdio:'inherit'});
}
