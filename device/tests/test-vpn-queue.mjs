// Production enqueue, batch drain and failure bookkeeping; not a network model.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root = new URL('../', import.meta.url);
const text = fs.readFileSync(new URL('components/meshvpn_vpn/meshvpn_vpn.c', root), 'utf8');
function section(from, to) {
  const a = text.indexOf(from), b = text.indexOf(to, a);
  if (a < 0 || b < a) throw Error(from);
  return text.slice(a, b);
}
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'meshpn-vpn-queue-'));
const source = `
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "meshvpn_vpn.h"
#include "meshvpn_vpn_stream.h"
#define ESP_ERR_INVALID_STATE 9
#define LOCK() ((void)0)
#define UNLOCK() ((void)0)
static meshvpn_vpn_status_t s;
typedef struct { uint16_t len; int64_t time; uint8_t data[MESHVPN_VPN_MTU]; } packet_t;
static packet_t storage[MESHVPN_VPN_SLOTS], *s_queue = storage;
static unsigned s_head, s_count, s_probe_epoch;
static int64_t now = 10000000;
static int64_t esp_timer_get_time(void) { return now; }
static void flush_nat(void) {}
static size_t strlcpy(char *d, const char *p, size_t n) {
 size_t len=strlen(p); if(n){size_t c=len<n-1?len:n-1;memcpy(d,p,c);d[c]=0;}return len;
}
${section('static void state_core(', 'typedef struct { uint32_t g;')}
${section('esp_err_t meshvpn_vpn_send_ipv4(', '/* RX is injected')}
${section('static void socket_failure(', 'static void __attribute__((unused)) worker(')}
int main(void) {
 s.enabled=s.connected=true;s.kill_switch=true;s.generation=1;
 uint8_t packet[100]={0x45,0,0,100};packet[9]=17;packet[25]=80;
 for(unsigned i=0;i<MESHVPN_VPN_SLOTS;i++) {
   packet[28]=i; assert(meshvpn_vpn_send_ipv4(packet,sizeof(packet))==ESP_OK);
 }
 assert(meshvpn_vpn_send_ipv4(packet,sizeof(packet))==ESP_ERR_NO_MEM);
 assert(s.queue_full==1 && s_count==MESHVPN_VPN_SLOTS && s.queue_high_water==MESHVPN_VPN_SLOTS);
 meshvpn_vpn_tx_batch_t b={0}; load_tx_batch(&b,1);
 assert(b.count==MESHVPN_VPN_BATCH_FRAMES &&
        s_count==MESHVPN_VPN_SLOTS-MESHVPN_VPN_BATCH_FRAMES &&
        s.queue_depth==MESHVPN_VPN_SLOTS-MESHVPN_VPN_BATCH_FRAMES);
 for(unsigned i=0;i<8;i++)assert(b.data[i*104+4+28]==i);
 for(unsigned base=MESHVPN_VPN_BATCH_FRAMES;base<MESHVPN_VPN_SLOTS;base+=MESHVPN_VPN_BATCH_FRAMES) {
   load_tx_batch(&b,1);assert(b.count==MESHVPN_VPN_BATCH_FRAMES);
   for(unsigned i=0;i<MESHVPN_VPN_BATCH_FRAMES;i++)
     assert(b.data[i*104+4+28]==(uint8_t)(base+i));
 }
 assert(!s_count);
 load_tx_batch(&b,1);assert(!b.count); /* never waits for a full batch */
 assert(meshvpn_vpn_send_ipv4(packet,sizeof(packet))==ESP_OK);
 now+=1000001;
 assert(meshvpn_vpn_send_ipv4(packet,sizeof(packet))==ESP_OK);
 load_tx_batch(&b,1);assert(b.count==1 && s.queue_expired==1 && !s_count);
 assert(meshvpn_vpn_send_ipv4(packet,sizeof(packet))==ESP_OK);
 load_tx_batch(&b,2);assert(!b.count && s_count==1); /* stale worker cannot consume new generation */
 socket_failure(1,ETIMEDOUT,"rx_frame_timeout");
 state_core(1,"backoff",false,ETIMEDOUT);
 assert(!s.connected && s.socket_rx_timeouts==1 && !s_count);
 assert(s.tx_dropped==1);
 state_core(1,"up",true,0);
 assert(!s.last_error && s.socket_last_failure_error==ETIMEDOUT);
 assert(s.socket_last_failure_us==now && !strcmp(s.socket_last_failure_reason,"rx_frame_timeout"));
 socket_failure(0,EIO,"send");assert(s.socket_last_failure_error==ETIMEDOUT);
 s.generation=2;state_core(2,"up",true,0);
 assert(s.socket_last_failure_generation==1); /* history remains explicitly old */
 socket_failure(2,EPIPE,"send");assert(s.socket_last_failure_error==EPIPE && s.socket_rx_timeouts==1);
 puts("Socket queue: bounded drain/order, expiry, generations, overload and retained failure history passed");
}
`;
const file = path.join(dir, 'test.c'), bin = path.join(dir, 'test');
fs.writeFileSync(file, source);
execFileSync(process.env.CC || 'cc', ['-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
  '-I' + new URL('tests/stubs', root).pathname,
  '-I' + new URL('components/meshvpn_config/include', root).pathname,
  '-I' + new URL('components/meshvpn_vpn/include', root).pathname, file,
  new URL('components/meshvpn_vpn/meshvpn_vpn_frame.c', root).pathname,
  new URL('components/meshvpn_vpn/meshvpn_vpn_stream.c', root).pathname, '-o', bin], {stdio: 'inherit'});
execFileSync(bin, {stdio: 'inherit'});
