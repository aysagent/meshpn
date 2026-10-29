// Exercise the production TX worker at deterministic scheduler boundaries.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root = new URL('../', import.meta.url);
const production = fs.readFileSync(new URL('components/meshvpn_vpn/meshvpn_vpn.c', root), 'utf8');
const begin = production.indexOf('static void socket_tx_worker(');
const end = production.indexOf('static void __attribute__((unused)) worker(', begin);
if (begin < 0 || end < begin) throw Error('Production worker missing');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'meshpn-worker-stop-'));
const source = `
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include "meshvpn_vpn_stream.h"
typedef void esp_tls_t;
typedef void *SemaphoreHandle_t;
typedef void *TaskHandle_t;
#define LOCK() ((void)0)
#define UNLOCK() ((void)0)
#define pdTRUE 1
#define portMAX_DELAY 0xffffffffu
#define pdMS_TO_TICKS(n) (n)
static struct {
 int fd; uint32_t epoch,generation; bool active,datagram,tls,tx_stopped;
 esp_tls_t *tls_conn; SemaphoreHandle_t tls_io_mutex;
 int tx_error; char tx_reason[24];
} s_socket;
static struct { unsigned tx_dropped,socket_send_calls,socket_send_bytes,
 socket_send_would_block,packets_out,bytes_out; } s;
static TaskHandle_t s_socket_rx_task=(void *)1;
static jmp_buf finished;
static unsigned waits,notifications,shutdowns,link_calls;
static bool cancel_only;
static bool cancel_after_select, partial_then_cancel, cancelled;
static unsigned writes;
static unsigned ulTaskNotifyTake(int clear,unsigned ticks) {
 (void)clear;(void)ticks;
 if(waits++)longjmp(finished,1);
 return 1;
}
static void xTaskNotifyGive(TaskHandle_t task) {
 assert(task==s_socket_rx_task);assert(s_socket.tx_stopped);notifications++;
}
static void vTaskDelay(unsigned n) { (void)n; }
static bool socket_link_current(uint32_t e,uint32_t g,int fd) {
 assert(e==s_socket.epoch && g==s_socket.generation && fd==s_socket.fd);
 link_calls++; return !cancel_only && !cancelled;
}
static bool load_udp_packet(uint8_t *p,uint16_t *length,uint32_t g) {
 (void)g;memset(p,0,20);*length=20;return true;
}
static void load_tx_batch(meshvpn_vpn_tx_batch_t *b,uint32_t g) {
 (void)g;uint8_t p[20]={0};assert(meshvpn_vpn_tx_append(b,p,20));
}
static int64_t esp_timer_get_time(void) { return 100; }
static ssize_t tunnel_write(esp_tls_t *t,SemaphoreHandle_t m,int fd,const void *p,size_t n) {
 (void)t;(void)m;(void)p;(void)n;assert(fd==s_socket.fd);
 writes++;
 if(partial_then_cancel)return 1;
 errno=ECONNRESET;return -1;
}
static bool tls_would_block(ssize_t n) { (void)n;return false; }
static int selected(int n,fd_set *r,fd_set *w,fd_set *e,struct timeval *t) {
 (void)n;(void)r;(void)w;(void)e;(void)t;
 if(cancel_after_select || (partial_then_cancel && writes))cancelled=true;
 return 1;
}
static int shut(int fd,int how) {
 assert(fd==s_socket.fd && how==SHUT_RDWR);
 /* RX is allowed to close/reuse fd as soon as tx_stopped is published. */
 assert(!s_socket.tx_stopped);shutdowns++;return 0;
}
static size_t copy_string(char *d,const char *s,size_t n) {
 size_t len=strlen(s),copy=len<n-1?len:n-1;memcpy(d,s,copy);d[copy]=0;return len;
}
#define select selected
#define shutdown shut
#define strlcpy copy_string
${production.slice(begin,end)}
static void run(bool active,bool datagram,bool tls,bool cancel) {
 memset(&s_socket,0,sizeof(s_socket));memset(&s,0,sizeof(s));
 s_socket.fd=42;s_socket.epoch=9;s_socket.generation=3;
 s_socket.active=active;s_socket.datagram=datagram;s_socket.tls=tls;
 waits=notifications=shutdowns=link_calls=writes=0;cancel_only=cancel;cancelled=false;
 meshvpn_vpn_tx_batch_t batch={0};
 if(!setjmp(finished))socket_tx_worker(&batch);
 assert(s_socket.tx_stopped && notifications==1);
 assert(shutdowns==(unsigned)(active&&!cancel&&!cancel_after_select&&!partial_then_cancel));
 if(cancel_after_select)assert(writes==0 && s.tx_dropped==1);
 if(partial_then_cancel)assert(writes==1 && s.tx_dropped==1);
}
int main(int argc,char **argv) {
 if(argc>1 && !strcmp(argv[1],"early"))run(false,false,true,false);
 else {
  run(true,true,false,false);run(true,false,false,false);run(true,false,true,false);run(true,false,true,true);
  cancel_after_select=true;run(true,false,false,false);run(true,false,true,false);cancel_after_select=false;
  partial_then_cancel=true;run(true,false,false,false);run(true,false,true,false);
 }
 puts("TX worker stop acknowledgement and last socket access ordering passed");
}
`;
const file=path.join(dir,'test.c'), binary=path.join(dir,'test');fs.writeFileSync(file,source);
execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror','-Wno-sign-compare','-fsanitize=address,undefined',
  '-I'+new URL('components/meshvpn_vpn/include',root).pathname,file,
  ...['meshvpn_vpn_frame.c','meshvpn_vpn_stream.c'].map(f=>new URL('components/meshvpn_vpn/'+f,root).pathname),
  '-o',binary],{stdio:'inherit'});
for(const scenario of ['early','active'])execFileSync(binary,[scenario],{stdio:'inherit'});
