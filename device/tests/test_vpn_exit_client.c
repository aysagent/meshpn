/* Production firmware framing/checksums over loopback TCP, UDP or mbedTLS. */
#define _POSIX_C_SOURCE 200809L
#include "meshvpn_vpn_frame.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
static unsigned received;
static uint8_t expected[1400];static size_t length;
static bool packet(void *ctx,const uint8_t *p,size_t n){(void)ctx;assert(n==length&&!memcmp(expected,p,n));received++;return true;}
int main(int argc,char **argv){
 int status=0;assert(argc==4||argc==6);bool tls=!strcmp(argv[1],"tls"),udp=!strcmp(argv[1],"udp");
 mbedtls_net_context net;mbedtls_net_init(&net);assert(!mbedtls_net_connect(&net,"127.0.0.1",argv[2],udp?MBEDTLS_NET_PROTO_UDP:MBEDTLS_NET_PROTO_TCP));
 struct timeval timeout={.tv_sec=5};assert(!setsockopt(net.fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)));assert(!setsockopt(net.fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)));
 mbedtls_ssl_context ssl;mbedtls_ssl_init(&ssl);mbedtls_ssl_config cfg;mbedtls_ssl_config_init(&cfg);
 mbedtls_x509_crt ca,client;mbedtls_x509_crt_init(&ca);mbedtls_x509_crt_init(&client);mbedtls_pk_context key;mbedtls_pk_init(&key);
 mbedtls_entropy_context entropy;mbedtls_entropy_init(&entropy);mbedtls_ctr_drbg_context rng;mbedtls_ctr_drbg_init(&rng);
 if(tls){
  assert(!mbedtls_ctr_drbg_seed(&rng,mbedtls_entropy_func,&entropy,(const unsigned char*)"real-exit",9));
  assert(!mbedtls_ssl_config_defaults(&cfg,MBEDTLS_SSL_IS_CLIENT,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT));
  mbedtls_ssl_conf_rng(&cfg,mbedtls_ctr_drbg_random,&rng);assert(!mbedtls_x509_crt_parse_file(&ca,argv[3]));
  mbedtls_ssl_conf_ca_chain(&cfg,&ca,NULL);mbedtls_ssl_conf_authmode(&cfg,MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_min_tls_version(&cfg,MBEDTLS_SSL_VERSION_TLS1_2);mbedtls_ssl_conf_max_tls_version(&cfg,MBEDTLS_SSL_VERSION_TLS1_2);
  if(argc==6){assert(!mbedtls_x509_crt_parse_file(&client,argv[4]));assert(!mbedtls_pk_parse_keyfile(&key,argv[5],NULL,mbedtls_ctr_drbg_random,&rng));assert(!mbedtls_ssl_conf_own_cert(&cfg,&client,&key));}
  assert(!mbedtls_ssl_setup(&ssl,&cfg));assert(!mbedtls_ssl_set_hostname(&ssl,"exit.meshpn.test"));
  mbedtls_ssl_set_bio(&ssl,&net,mbedtls_net_send,mbedtls_net_recv,NULL);
  int r=mbedtls_ssl_handshake(&ssl);if(r){fprintf(stderr,"TLS rejected: %d\n",r);status=3;goto cleanup;}
 }
 for(unsigned i=0;i<64;i++){
  length=i%3?100:1400;memset(expected,i,length);expected[0]=0x45;expected[2]=length>>8;expected[3]=length;expected[6]=expected[7]=0;
  expected[8]=64;expected[9]=1;memcpy(expected+12,(uint8_t[]){10,99,0,2,198,18,0,1},8);expected[20]=8;expected[21]=0;
  assert(meshvpn_vpn_repair_checksums(expected,length));
  uint8_t wire[1404];meshvpn_vpn_frame_header(wire,length);memcpy(wire+4,expected,length);
  size_t n=length+(udp?0:4),pos=0;uint8_t *start=udp?wire+4:wire;
  while(pos<n){size_t part=udp?n:(pos==0?2:n-pos);int r=tls?mbedtls_ssl_write(&ssl,start+pos,part):mbedtls_net_send(&net,start+pos,part);assert(r>0);pos+=r;}
  /* In-memory TUN echoes the exact IP packet; no synthetic transport. */
  meshvpn_vpn_decoder_t decoder={0};uint8_t input[1404];unsigned before=received;
  while(received==before){int r=tls?mbedtls_ssl_read(&ssl,input,sizeof(input)):mbedtls_net_recv(&net,input,sizeof(input));assert(r>0);
   if(udp)assert(packet(NULL,input,r));else assert(meshvpn_vpn_decode(&decoder,input,r,packet,NULL));}
 }
 assert(received==64);puts("REAL_EXIT_CLIENT_OK packets=64");
 cleanup:
 mbedtls_net_free(&net);mbedtls_ssl_free(&ssl);mbedtls_ssl_config_free(&cfg);mbedtls_x509_crt_free(&ca);mbedtls_x509_crt_free(&client);mbedtls_pk_free(&key);mbedtls_ctr_drbg_free(&rng);mbedtls_entropy_free(&entropy);return status;
}
