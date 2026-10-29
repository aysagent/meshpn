#define _DARWIN_C_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include "meshvpn_net_bench.h"
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define pdPASS 1
#ifndef SO_BINDTODEVICE
#define SO_BINDTODEVICE 10000
#endif
#define ESP_ERR_INVALID_STATE 99
#define portMUX_TYPE pthread_mutex_t
#define portMUX_INITIALIZER_UNLOCKED PTHREAD_MUTEX_INITIALIZER
#define portENTER_CRITICAL(l) pthread_mutex_lock(l)
#define portEXIT_CRITICAL(l) pthread_mutex_unlock(l)
typedef int esp_netif_t;
typedef struct {struct {uint32_t addr;} ip,netmask;} esp_netif_ip_info_t;
static bool vpn_enabled, allocation_fail;
static esp_netif_t netif;
static bool meshvpn_vpn_is_enabled(void){return __atomic_load_n(&vpn_enabled,__ATOMIC_RELAXED);}
static void *heap_caps_malloc(size_t n,int caps){(void)caps;return allocation_fail?NULL:malloc(n);}
static void *heap_caps_calloc(size_t n,size_t size,int caps){(void)caps;return allocation_fail?NULL:calloc(n,size);}
static uint64_t esp_timer_get_time(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000+t.tv_nsec/1000;}
static esp_netif_t *esp_netif_get_handle_from_ifkey(const char *s){assert(!strcmp(s,"WIFI_STA_DEF")||!strcmp(s,"WIFI_AP_DEF"));return &netif;}
static bool esp_netif_is_netif_up(esp_netif_t *n){return n==&netif;}
static int esp_netif_get_ip_info(esp_netif_t*n,esp_netif_ip_info_t*i){(void)n;i->ip.addr=inet_addr("10.0.0.2");i->netmask.addr=inet_addr("255.255.255.0");return ESP_OK;}
static int esp_netif_get_netif_impl_name(esp_netif_t*n,char*s){(void)n;strcpy(s,"test");return ESP_OK;}
static void vTaskDelay(int ticks){usleep(ticks*1000);}
static void vTaskDelete(void *p){(void)p;pthread_exit(NULL);}
static void *start_thread(void *fn){((void(*)(void*))fn)(NULL);return NULL;}
static int xTaskCreate(void(*f)(void*),const char*n,int stack,void*a,int priority,void*out){
 (void)n;(void)stack;(void)a;(void)priority;(void)out;pthread_t t;
 if(pthread_create(&t,NULL,start_thread,(void*)f))return 0;pthread_detach(t);return pdPASS;
}
static int mock_setsockopt(int fd,int level,int option,const void *value,socklen_t length){
 if(option==SO_BINDTODEVICE)return 0;return setsockopt(fd,level,option,value,length);
}
static int local_address(int fd,const struct sockaddr *a,socklen_t len,bool connect_it){
 struct sockaddr_in b=*(const struct sockaddr_in*)a;b.sin_addr.s_addr=inet_addr("127.0.0.1");
 return connect_it?connect(fd,(struct sockaddr*)&b,len):bind(fd,(struct sockaddr*)&b,len);
}
#define setsockopt mock_setsockopt
#define bind(fd,a,n) local_address(fd,a,n,false)
#define connect(fd,a,n) local_address(fd,a,n,true)
static int peer_accept(int fd,struct sockaddr *p,socklen_t *n){
 int accepted=accept(fd,p,n);if(accepted>=0)((struct sockaddr_in*)p)->sin_addr.s_addr=inet_addr("10.0.0.1");return accepted;
}
static ssize_t peer_recvfrom(int fd,void *p,size_t n,int flags,struct sockaddr *peer,socklen_t *size){
 ssize_t received=recvfrom(fd,p,n,flags,peer,size);if(received>=0)((struct sockaddr_in*)peer)->sin_addr.s_addr=inet_addr("10.0.0.1");return received;
}
#define accept peer_accept
#define recvfrom peer_recvfrom
#include "bench-production.inc"
static meshvpn_net_bench_result_t wait_done(void){
 meshvpn_net_bench_result_t r;uint64_t end=now()+7000000;
 do{usleep(10000);meshvpn_net_bench_status(&r);}while(r.running&&now()<end);
 assert(!r.running);return r;
}
static void server_test(meshvpn_net_bench_config_t c){
 c.server=true;c.ap=true;
 assert(meshvpn_net_bench_start(&c)==ESP_OK);
 meshvpn_net_bench_result_t r;uint64_t end=now()+1000000;
 do {usleep(1000);meshvpn_net_bench_status(&r);}while(r.running&&!r.listening&&now()<end);
 assert(r.running&&r.listening&&r.server&&!r.connected);
 int fd=socket(AF_INET,c.udp?SOCK_DGRAM:SOCK_STREAM,0);assert(fd>=0);
 struct sockaddr_in peer={.sin_family=AF_INET,.sin_port=htons(c.port),.sin_addr.s_addr=c.target};
 assert(!connect(fd,(struct sockaddr*)&peer,sizeof(peer)));assert(!fcntl(fd,F_SETFL,O_NONBLOCK));
 uint8_t hello[32]={0},received[8192];memcpy(hello,"MNB1",4);put(hello+4,c.nonce);put(hello+8,c.download);
 put(hello+12,c.seconds);put(hello+16,c.rate_kbps);put(hello+20,c.udp?1200:8192);
 if(c.udp){ /* An unarmed nonce must neither start nor get an echo. */
  put(hello+4,c.nonce+1);assert(send(fd,hello,32,0)==32);usleep(20000);
  assert(recv(fd,received,sizeof(received),0)<0&&(errno==EAGAIN||errno==EWOULDBLOCK));
  meshvpn_net_bench_status(&r);assert(!r.connected&&!r.bytes);put(hello+4,c.nonce);
 }
 end=now()+1000000;
 assert(!exchange(fd,hello,32,true,c.udp,end));assert(!exchange(fd,received,32,false,c.udp,end));assert(!memcmp(hello,received,32));
 size_t bytes=0;unsigned packets=0;memset(received,0x5a,sizeof(received));memcpy(received,"MND1",4);put(received+4,c.nonce);
 end=now()+1100000;
 while(now()<end){
  if(ready(fd,!c.download,end)<0)break;
  if(!c.download&&c.udp)put(received+8,packets);
  int n=c.download?recv(fd,received,sizeof(received),0):send(fd,received,c.udp?1200:8192,0);
  if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))continue;
  if(n<=0)break;
  if(c.udp&&c.download)assert(n==1200&&!memcmp(received,"MND1",4)&&get(received+4)==c.nonce);
  bytes+=n;packets++;
  if(!c.download){usleep(1000);if(packets==100)break;}
 }
 close(fd);r=wait_done();assert(!r.error&&r.connected&&!r.listening&&r.bytes>0&&bytes>0);
 if(!c.download)assert(r.bytes==bytes); /* Exact receiver accounting, no sender-only success. */
 if(c.udp)assert(!r.invalid&&!r.duplicates);
 usleep(100000);
}
int main(int argc,char **argv){
 assert(argc==3);int port=atoi(argv[1]),server_port=atoi(argv[2]);
 uint8_t data[1200]={0},seen[UDP_SEEN_BYTES]={0};
 meshvpn_net_bench_result_t sequence={.nonce=7352};
 memcpy(data,"MND1",4);put(data+4,sequence.nonce);
 for(unsigned i=0;i<4;i++){
  put(data+8,(unsigned[]){0,3,3,1}[i]);
  if(accept_udp(data,sizeof(data),seen,&sequence))sequence.packets++;
 }
 assert(sequence.packets==3&&sequence.duplicates==1&&sequence.reordered==1);
 assert(sequence.sequence_span==4&&sequence.sequence_span-sequence.packets==1);
 put(data+8,UINT32_MAX);assert(!accept_udp(data,sizeof(data),seen,&sequence));
 put(data+8,UDP_SEQUENCE_LIMIT);assert(!accept_udp(data,sizeof(data),seen,&sequence));
 put(data+8,2);put(data+4,1);assert(!accept_udp(data,sizeof(data),seen,&sequence));
 assert(!accept_udp(data,3,seen,&sequence)&&sequence.invalid==4);
 put(data+4,sequence.nonce);assert(accept_udp(data,sizeof(data),seen,&sequence));sequence.packets++;
 assert(sequence.sequence_span==sequence.packets); /* late packet closes the gap */
 meshvpn_net_bench_config_t c={.target=inet_addr("10.0.0.1"),.nonce=100,.port=port,.seconds=1,.rate_kbps=1000};
 assert(meshvpn_net_bench_start(NULL)==ESP_ERR_INVALID_ARG);
 c.target=inet_addr("8.8.8.8");assert(meshvpn_net_bench_start(&c)==ESP_ERR_INVALID_ARG);c.target=inet_addr("10.0.0.1");
 c.seconds=61;assert(meshvpn_net_bench_start(&c)==ESP_ERR_INVALID_ARG);c.seconds=1;
 vpn_enabled=true;assert(meshvpn_net_bench_start(&c)==ESP_ERR_INVALID_STATE);vpn_enabled=false;
 for(int udp=0;udp<2;udp++)for(int down=0;down<2;down++){
  c.udp=udp;c.download=down;c.nonce++;
  assert(meshvpn_net_bench_start(&c)==ESP_OK);
  assert(meshvpn_net_bench_start(&c)==ESP_ERR_INVALID_STATE);
  meshvpn_net_bench_result_t r=wait_done();assert(!r.error&&r.bytes>0&&r.nonce==c.nonce);
  assert(r.source==inet_addr("10.0.0.2")&&!r.invalid);usleep(800000);
 }
 c.udp=false;c.seconds=60;c.nonce++;
 assert(meshvpn_net_bench_start(&c)==ESP_OK);usleep(100000);meshvpn_net_bench_cancel();assert(wait_done().error==ECANCELED);
 usleep(100000);c.nonce++;
 assert(meshvpn_net_bench_start(&c)==ESP_OK);usleep(100000);__atomic_store_n(&vpn_enabled,true,__ATOMIC_RELAXED);
 assert(wait_done().error==ECANCELED);__atomic_store_n(&vpn_enabled,false,__ATOMIC_RELAXED);
 allocation_fail=true;assert(meshvpn_net_bench_start(&c)==ESP_OK);assert(wait_done().error==ENOMEM);
 allocation_fail=false;c.seconds=1;c.port=server_port;
 for(int udp=0;udp<2;udp++)for(int down=0;down<2;down++){
  c.udp=udp;c.download=down;c.nonce++;c.port++;server_test(c);
 }
 c.server=true;c.ap=true;c.target=inet_addr("10.1.0.1");c.port++;
 assert(meshvpn_net_bench_start(&c)==ESP_OK);assert(wait_done().error==EINVAL);
 c.target=inet_addr("10.0.0.1");c.udp=true;c.port++;
 assert(meshvpn_net_bench_start(&c)==ESP_OK);usleep(100000);meshvpn_net_bench_cancel();assert(wait_done().error==ECANCELED);
 c.port++;assert(meshvpn_net_bench_start(&c)==ESP_OK);assert(wait_done().error==ETIMEDOUT);
 c.port++;assert(meshvpn_net_bench_start(&c)==ESP_OK);usleep(100000);__atomic_store_n(&vpn_enabled,true,__ATOMIC_RELAXED);
 assert(wait_done().error==ECANCELED);__atomic_store_n(&vpn_enabled,false,__ATOMIC_RELAXED);
 puts("P4 benchmark worker: client/server TCP/UDP directions, nonce, subnet, busy, cancel, VPN transition, OOM and bounds passed");return 0;
}
