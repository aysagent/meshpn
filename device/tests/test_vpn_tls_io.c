/* Real mbedTLS over nonblocking loopback TCP; production I/O wrappers/framer. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include "meshvpn_vpn.h"
#include "meshvpn_vpn_stream.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
typedef struct {mbedtls_ssl_context ssl;} esp_tls_t;
typedef pthread_mutex_t* SemaphoreHandle_t;
typedef void* esp_tls_error_handle_t;
#define ESP_TLS_ERR_SSL_WANT_READ MBEDTLS_ERR_SSL_WANT_READ
#define ESP_TLS_ERR_SSL_WANT_WRITE MBEDTLS_ERR_SSL_WANT_WRITE
#define portMAX_DELAY 0
static pthread_mutex_t stats_lock=PTHREAD_MUTEX_INITIALIZER;
static meshvpn_vpn_status_t s;
#define LOCK() pthread_mutex_lock(&stats_lock)
#define UNLOCK() pthread_mutex_unlock(&stats_lock)
#define ESP_LOGW(tag, format, ...) do { if (0) fprintf(stderr, format, __VA_ARGS__); } while (0)
static const char *TAG="test";
static int64_t esp_timer_get_time(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return(int64_t)t.tv_sec*1000000+t.tv_nsec/1000;}
static void xSemaphoreTake(SemaphoreHandle_t m,int d){(void)d;assert(!pthread_mutex_lock(m));}
static void xSemaphoreGive(SemaphoreHandle_t m){assert(!pthread_mutex_unlock(m));}
static ssize_t esp_tls_conn_write(esp_tls_t*t,const void*b,size_t n){return mbedtls_ssl_write(&t->ssl,b,n);}
static ssize_t esp_tls_conn_read(esp_tls_t*t,void*b,size_t n){return mbedtls_ssl_read(&t->ssl,b,n);}
static ssize_t esp_tls_get_bytes_avail(esp_tls_t*t){return mbedtls_ssl_get_bytes_avail(&t->ssl);}
static esp_err_t esp_tls_get_error_handle(esp_tls_t*t,void**h){(void)t;*h=NULL;return ESP_FAIL;}
static esp_err_t esp_tls_get_and_clear_last_error(void*h,int*c,int*f){(void)h;*c=*f=0;return ESP_OK;}
#include "vpn-tls-io.inc"
static esp_tls_t connection;
static pthread_mutex_t io_lock=PTHREAD_MUTEX_INITIALIZER;
static int socket_fd;
#ifndef PACKETS
#define PACKETS 128
#endif
static void pause_ms(void){struct timespec t={.tv_nsec=1000000};nanosleep(&t,NULL);}
static void*writer(void*unused){
 (void)unused;uint8_t frame[1404];
 for(unsigned i=0;i<PACKETS;i++){
  unsigned length=i%16==0?1400:100;memset(frame,0,4+length);uint8_t*p=frame+4;
  meshvpn_vpn_frame_header(frame,length);p[0]=0x45;p[2]=length>>8;p[3]=length;p[8]=64;p[9]=1;
  memcpy(p+12,(uint8_t[]){10,99,0,2,198,18,0,1},8);p[20]=8;p[27]=i;
  assert(meshvpn_vpn_repair_checksums(p,length));
  size_t used=0;int64_t deadline=esp_timer_get_time()+10000000;
  while(used<4+length){
   assert(esp_timer_get_time()<deadline);
   ssize_t n=tunnel_write(&connection,&io_lock,socket_fd,frame+used,4+length-used);
   if(n>0)used+=n;else{assert(tls_would_block(n));pause_ms();}
  }
 }
 return NULL;
}
static unsigned received;
static bool packet_received(void*ctx,const uint8_t*p,size_t n){
 (void)ctx;assert(n==(received%16==0?1400:100)&&p[9]==1&&p[20]==0&&p[27]==(uint8_t)received);
 assert(!memcmp(p+12,(uint8_t[]){198,18,0,1,10,99,0,2},8));received++;return true;
}
int main(int argc,char**argv){
 (void)TAG;assert(argc==3);
 mbedtls_net_context socket;mbedtls_net_init(&socket);
 assert(!mbedtls_net_connect(&socket,"127.0.0.1",argv[1],MBEDTLS_NET_PROTO_TCP));socket_fd=socket.fd;
 mbedtls_ssl_config config;mbedtls_ssl_config_init(&config);mbedtls_ssl_init(&connection.ssl);
 mbedtls_entropy_context entropy;mbedtls_entropy_init(&entropy);
 mbedtls_ctr_drbg_context rng;mbedtls_ctr_drbg_init(&rng);
 assert(!mbedtls_ctr_drbg_seed(&rng,mbedtls_entropy_func,&entropy,(const unsigned char*)"local-io-test",13));
 assert(!mbedtls_ssl_config_defaults(&config,MBEDTLS_SSL_IS_CLIENT,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT));
 mbedtls_x509_crt ca;mbedtls_x509_crt_init(&ca);
 assert(!mbedtls_x509_crt_parse_file(&ca,argv[2]));
 mbedtls_ssl_conf_ca_chain(&config,&ca,NULL);
 mbedtls_ssl_conf_authmode(&config,MBEDTLS_SSL_VERIFY_REQUIRED);mbedtls_ssl_conf_rng(&config,mbedtls_ctr_drbg_random,&rng);
 mbedtls_ssl_conf_min_tls_version(&config,MBEDTLS_SSL_VERSION_TLS1_2);
 mbedtls_ssl_conf_max_tls_version(&config,MBEDTLS_SSL_VERSION_TLS1_2);
 assert(!mbedtls_ssl_setup(&connection.ssl,&config));
 assert(!mbedtls_ssl_set_hostname(&connection.ssl,"loopback-test"));
 mbedtls_ssl_set_bio(&connection.ssl,&socket,mbedtls_net_send,mbedtls_net_recv,NULL);
 assert(!mbedtls_ssl_handshake(&connection.ssl));assert(!mbedtls_net_set_nonblock(&socket));
 pthread_t thread;assert(!pthread_create(&thread,NULL,writer,NULL));
 meshvpn_vpn_rx_stream_t decoder={0};uint8_t buffer[8192];
 int64_t deadline=esp_timer_get_time()+20000000+(int64_t)PACKETS*30000;
 while(received<PACKETS){
  assert(esp_timer_get_time()<deadline);
  fd_set rd;FD_ZERO(&rd);FD_SET(socket_fd,&rd);struct timeval tv={.tv_usec=10000};
  int ready=select(socket_fd+1,&rd,NULL,NULL,&tv);assert(ready>=0);
  if(ready||tls_has_pending(&connection,&io_lock)){
   ssize_t n=tunnel_read(&connection,&io_lock,socket_fd,buffer,sizeof(buffer));
   if(n>0)assert(meshvpn_vpn_rx_feed(&decoder,buffer,n,esp_timer_get_time(),packet_received,NULL));
   else assert(tls_would_block(n));
  }
 }
 assert(!pthread_join(thread,NULL));
 assert(s.transport_read.calls&&s.transport_write.calls&&s.tls_lock_wait.calls);
 printf("TLS_IO_OK packets=%u read_calls=%llu write_calls=%llu\n",received,
  (unsigned long long)s.transport_read.calls,(unsigned long long)s.transport_write.calls);
 mbedtls_net_free(&socket);mbedtls_ssl_free(&connection.ssl);mbedtls_ssl_config_free(&config);
 mbedtls_x509_crt_free(&ca);mbedtls_ctr_drbg_free(&rng);mbedtls_entropy_free(&entropy);return 0;
}
