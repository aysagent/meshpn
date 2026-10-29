// Host-only probe against the SDK's mbedTLS sources, not the firmware config.
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/net_sockets.h"
#include "psa/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
static const int ciphers[]={0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0xc013,0xc014,0x009c,0x009d,0x002f,0x0035,0};
static const uint16_t groups[]={4588,29,23,24,0};
static const uint16_t sigs[]={0x0904,0x0905,0x0906,0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601,0};
static int send_capture(void*ctx,const unsigned char*p,size_t n){return fwrite(p,1,n,(FILE*)ctx)==n?(int)n:MBEDTLS_ERR_SSL_INTERNAL_ERROR;}
static int recv_wait(void*ctx,unsigned char*p,size_t n){(void)ctx;(void)p;(void)n;return MBEDTLS_ERR_SSL_WANT_READ;}
int main(int argc,char**argv){
 if(argc!=4)return 2;
 int result=1,rc;FILE*f=NULL;
 mbedtls_ssl_context ssl;mbedtls_ssl_config cfg;mbedtls_entropy_context entropy;mbedtls_ctr_drbg_context rng;mbedtls_x509_crt ca;mbedtls_net_context net;
 mbedtls_ssl_init(&ssl);mbedtls_ssl_config_init(&cfg);mbedtls_entropy_init(&entropy);mbedtls_ctr_drbg_init(&rng);mbedtls_x509_crt_init(&ca);mbedtls_net_init(&net);
 if(psa_crypto_init()!=PSA_SUCCESS)goto done;
 if(mbedtls_ctr_drbg_seed(&rng,mbedtls_entropy_func,&entropy,(const unsigned char*)"meshpn-probe",12))goto done;
 if(mbedtls_ssl_config_defaults(&cfg,MBEDTLS_SSL_IS_CLIENT,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT))goto done;
 mbedtls_ssl_conf_rng(&cfg,mbedtls_ctr_drbg_random,&rng);mbedtls_ssl_conf_authmode(&cfg,MBEDTLS_SSL_VERIFY_REQUIRED);
 const char*alpn[]={"h2","http/1.1",NULL};if(mbedtls_ssl_conf_alpn_protocols(&cfg,alpn))goto done;
 mbedtls_ssl_conf_min_tls_version(&cfg,MBEDTLS_SSL_VERSION_TLS1_2);
 mbedtls_ssl_conf_max_tls_version(&cfg,!strcmp(argv[3],"tls12")?MBEDTLS_SSL_VERSION_TLS1_2:MBEDTLS_SSL_VERSION_TLS1_3);
 if(!strcmp(argv[3],"prefs")||!strcmp(argv[1],"connect")){
   mbedtls_ssl_conf_ciphersuites(&cfg,ciphers);mbedtls_ssl_conf_groups(&cfg,groups);mbedtls_ssl_conf_sig_algs(&cfg,sigs);
   mbedtls_ssl_conf_encrypt_then_mac(&cfg,MBEDTLS_SSL_ETM_DISABLED);
 }
 if(!strcmp(argv[1],"connect")){
   if(mbedtls_x509_crt_parse_file(&ca,argv[3]))goto done;
   mbedtls_ssl_conf_ca_chain(&cfg,&ca,NULL);
 }
 if(mbedtls_ssl_setup(&ssl,&cfg)||mbedtls_ssl_set_hostname(&ssl,"exit.meshpn.test"))goto done;
 if(!strcmp(argv[1],"capture")){
   f=fopen(argv[2],"wb");if(!f)goto done;
   mbedtls_ssl_set_bio(&ssl,f,send_capture,recv_wait,NULL);
   rc=mbedtls_ssl_handshake(&ssl);if(rc!=MBEDTLS_ERR_SSL_WANT_READ){fprintf(stderr,"capture error %d\n",rc);goto done;}
 }else if(!strcmp(argv[1],"connect")){
   if(mbedtls_net_connect(&net,"127.0.0.1",argv[2],MBEDTLS_NET_PROTO_TCP))goto done;
   mbedtls_ssl_conf_read_timeout(&cfg,5000);
   mbedtls_ssl_set_bio(&ssl,&net,mbedtls_net_send,mbedtls_net_recv,mbedtls_net_recv_timeout);
   if((rc=mbedtls_ssl_handshake(&ssl))!=0){fprintf(stderr,"handshake error %d\n",rc);goto done;}
   if(mbedtls_ssl_get_verify_result(&ssl))goto done;
   unsigned char exporter[32];const char*label="EXPORTER-clean-vpn-bind";
   if(mbedtls_ssl_export_keying_material(&ssl,exporter,32,label,strlen(label),NULL,0,0))goto done;
   printf("%s ",mbedtls_ssl_get_version(&ssl));for(size_t i=0;i<32;i++)printf("%02x",exporter[i]);puts("");
   mbedtls_ssl_close_notify(&ssl);
 }else goto done;
 result=0;
done:
 if(f)fclose(f);
 mbedtls_net_free(&net);mbedtls_ssl_free(&ssl);mbedtls_ssl_config_free(&cfg);mbedtls_x509_crt_free(&ca);mbedtls_ctr_drbg_free(&rng);mbedtls_entropy_free(&entropy);mbedtls_psa_crypto_free();return result;
}
