/* Production trust store + connect function; ESP-TLS boundary is backed by real
 * host mbedTLS, with no alternate verification policy in the adapter. */
#define _DEFAULT_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <net/if.h>
#include <pthread.h>
#include "meshvpn_vpn_trust.h"
#include "meshvpn_vpn_client_identity.h"
#include "meshvpn_vpn_frame.h"
#include "nvs.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#define CONFIG_MBEDTLS_SSL_PROTO_TLS1_2 1
#define CONFIG_MBEDTLS_HAVE_TIME_DATE 1
#define ESP_TLS_VER_TLS_1_2 12
#define ESP_ERR_ESP_TLS_CONNECTION_TIMEOUT 900
#define ESP_TLS_ERR_TYPE_SYSTEM 1
#define MALLOC_CAP_INTERNAL 1
#define MALLOC_CAP_8BIT 2
#define MALLOC_CAP_SPIRAM 4
#define portMUX_TYPE pthread_mutex_t
#define portMUX_INITIALIZER_UNLOCKED PTHREAD_MUTEX_INITIALIZER
#define portENTER_CRITICAL(p) pthread_mutex_lock(p)
#define portEXIT_CRITICAL(p) pthread_mutex_unlock(p)
#define ESP_LOGI(tag, ...) do{(void)tag;}while(0)
#define ESP_LOGW(tag, ...) do{(void)tag;}while(0)
static void *heap_caps_malloc(size_t n,int caps){assert(caps==(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT));return malloc(n);}
static char stored[MESHVPN_VPN_CA_MAX+1];
static bool storage_error;
static bool corrupt_empty, read_error;
static unsigned writes;
esp_err_t nvs_open(const char*n,int mode,nvs_handle_t*out){assert(!strcmp(n,"meshvpn"));(void)mode;*out=1;return ESP_OK;}
void nvs_close(nvs_handle_t n){assert(n==1);}
esp_err_t nvs_get_blob(nvs_handle_t n,const char*k,void*out,size_t*len){
 assert(n==1&&!strcmp(k,"vpn_tls_ca"));if(storage_error)return ESP_FAIL;
 size_t size=strlen(stored)+1;if(!out){*len=size;return ESP_OK;}if(read_error)return ESP_FAIL;if(*len<size)return ESP_ERR_INVALID_SIZE;
 if(corrupt_empty && size==1){*(char*)out='x';*len=1;return ESP_OK;}
 memcpy(out,stored,size);*len=size;return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t n,const char*k,const void*value,size_t length){
 const char*v=value;assert(length==strlen(v)+1);
 assert(n==1&&!strcmp(k,"vpn_tls_ca"));if(storage_error)return ESP_FAIL;strcpy(stored,v);writes++;return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t n){assert(n==1);return storage_error?ESP_FAIL:ESP_OK;}
#include "trust-production.inc"
static meshvpn_client_identity_t *test_identity;
static bool identity_read_error;
esp_err_t meshvpn_client_identity_load(meshvpn_client_identity_t **out){*out=NULL;if(identity_read_error)return ESP_FAIL;if(!test_identity)return ESP_ERR_NVS_NOT_FOUND;*out=malloc(sizeof(**out));assert(*out);memcpy(*out,test_identity,sizeof(**out));return ESP_OK;}
void meshvpn_client_identity_free(meshvpn_client_identity_t *id){if(id){memset(id,0,sizeof(*id));free(id);}}
typedef struct {
 mbedtls_x509_crt client;mbedtls_pk_context key;
 mbedtls_ssl_context ssl;mbedtls_ssl_config conf;mbedtls_x509_crt ca;
 mbedtls_net_context net;mbedtls_entropy_context entropy;mbedtls_ctr_drbg_context rng;
 int result;unsigned flags;
} esp_tls_t;
typedef struct {struct ifreq *if_name;int timeout_ms,tls_version;bool skip_common_name;
 const char *common_name;const unsigned char *cacert_buf;size_t cacert_bytes;
 const unsigned char *clientcert_buf,*clientkey_buf;size_t clientcert_bytes,clientkey_bytes;} esp_tls_cfg_t;
typedef esp_tls_t *esp_tls_error_handle_t;
typedef struct {int sdk_error,mbedtls_error,verify_flags;char reason[48];} meshvpn_vpn_tls_diag_t;
static unsigned handshakes;
static esp_tls_t *esp_tls_init(void){
 esp_tls_t*t=calloc(1,sizeof(*t));assert(t);mbedtls_x509_crt_init(&t->client);mbedtls_pk_init(&t->key);mbedtls_ssl_init(&t->ssl);mbedtls_ssl_config_init(&t->conf);
 mbedtls_x509_crt_init(&t->ca);mbedtls_net_init(&t->net);mbedtls_entropy_init(&t->entropy);mbedtls_ctr_drbg_init(&t->rng);return t;
}
static void esp_tls_conn_destroy(esp_tls_t*t){
 mbedtls_x509_crt_free(&t->client);mbedtls_pk_free(&t->key);
 mbedtls_ssl_free(&t->ssl);mbedtls_ssl_config_free(&t->conf);mbedtls_x509_crt_free(&t->ca);
 mbedtls_net_free(&t->net);mbedtls_ctr_drbg_free(&t->rng);mbedtls_entropy_free(&t->entropy);free(t);
}
static int esp_tls_conn_new_sync(const char*host,size_t hostlen,int port,const esp_tls_cfg_t*c,esp_tls_t*t){
 assert(hostlen==strlen(host)&&c->tls_version==12&&c->cacert_buf&&c->cacert_bytes&&c->common_name&&!c->skip_common_name);
 assert(!strcmp(c->if_name->ifr_name,"lo0"));handshakes++;
 char service[8];snprintf(service,sizeof(service),"%d",port);
 assert(!mbedtls_net_connect(&t->net,"127.0.0.1",service,MBEDTLS_NET_PROTO_TCP));
 assert(!mbedtls_ctr_drbg_seed(&t->rng,mbedtls_entropy_func,&t->entropy,(const unsigned char*)"trust-test",10));
 assert(!mbedtls_ssl_config_defaults(&t->conf,MBEDTLS_SSL_IS_CLIENT,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT));
 assert(!mbedtls_x509_crt_parse(&t->ca,c->cacert_buf,c->cacert_bytes));
 mbedtls_ssl_conf_ca_chain(&t->conf,&t->ca,NULL);mbedtls_ssl_conf_authmode(&t->conf,MBEDTLS_SSL_VERIFY_REQUIRED);
 mbedtls_ssl_conf_rng(&t->conf,mbedtls_ctr_drbg_random,&t->rng);
 mbedtls_ssl_conf_min_tls_version(&t->conf,MBEDTLS_SSL_VERSION_TLS1_2);mbedtls_ssl_conf_max_tls_version(&t->conf,MBEDTLS_SSL_VERSION_TLS1_2);
 if(c->clientcert_buf){assert(c->clientkey_buf);assert(!mbedtls_x509_crt_parse(&t->client,c->clientcert_buf,c->clientcert_bytes));
 assert(!mbedtls_pk_parse_key(&t->key,c->clientkey_buf,c->clientkey_bytes,NULL,0,mbedtls_ctr_drbg_random,&t->rng));
 assert(!mbedtls_ssl_conf_own_cert(&t->conf,&t->client,&t->key));}
 assert(!mbedtls_ssl_setup(&t->ssl,&t->conf));assert(!mbedtls_ssl_set_hostname(&t->ssl,c->common_name));
 mbedtls_ssl_set_bio(&t->ssl,&t->net,mbedtls_net_send,mbedtls_net_recv,NULL);
 t->result=mbedtls_ssl_handshake(&t->ssl);t->flags=mbedtls_ssl_get_verify_result(&t->ssl);
 return t->result? -1:1;
}
static esp_err_t esp_tls_get_conn_sockfd(esp_tls_t*t,int*fd){*fd=t->net.fd;return ESP_OK;}
static esp_err_t esp_tls_get_error_handle(esp_tls_t*t,esp_tls_error_handle_t*h){*h=t;return ESP_OK;}
static esp_err_t esp_tls_get_and_clear_error_type(esp_tls_error_handle_t h,int type,int*error){(void)h;(void)type;*error=0;return ESP_OK;}
static esp_err_t esp_tls_get_and_clear_last_error(esp_tls_error_handle_t h,int*error,int*flags){*error=h->result;*flags=h->flags;return ESP_FAIL;}
static bool clock_ready=true;
static time_t test_time(time_t *out){time_t now=clock_ready?time(NULL):0;if(out)*out=now;return now;}
#define time test_time
#include "tls-production.inc"
#undef time
static char *readfile(const char*name){FILE*f=fopen(name,"rb");assert(f);assert(!fseek(f,0,SEEK_END));long n=ftell(f);rewind(f);assert(n>0&&n<8192);char*p=calloc(n+1,1);assert(fread(p,1,n,f)==(size_t)n);fclose(f);return p;}
int main(int argc,char**argv){
 assert(argc==6||argc==8);
 if(argc==8){test_identity=calloc(1,sizeof(*test_identity));char *cert=readfile(argv[6]),*key=readfile(argv[7]);strcpy(test_identity->certificate,cert);strcpy(test_identity->private_key,key);free(cert);free(key);}
char *ca=readfile(argv[2]),*leaf=readfile(argv[5]);
 assert(!meshvpn_vpn_ca_configured());char *loaded=(void*)1;assert(meshvpn_vpn_ca_load(&loaded)!=ESP_OK&&!loaded);
 assert(!meshvpn_vpn_ca_valid("garbage"));assert(!meshvpn_vpn_ca_valid(leaf));
 assert(meshvpn_vpn_ca_save(ca)==ESP_OK&&meshvpn_vpn_ca_configured());
 assert(meshvpn_vpn_ca_load(&loaded)==ESP_OK&&!strcmp(loaded,ca));free(loaded);
 char *bundle=calloc(MESHVPN_VPN_CA_MAX+1,1);while(strlen(bundle)+strlen(ca)<=MESHVPN_VPN_CA_MAX)strcat(bundle,ca);
 assert(strlen(bundle)>4000);assert(meshvpn_vpn_ca_save(bundle)==ESP_OK);
 assert(meshvpn_vpn_ca_load(&loaded)==ESP_OK&&!strcmp(loaded,bundle));free(bundle);free(loaded);
 assert(meshvpn_vpn_ca_save(ca)==ESP_OK);
 unsigned before=writes;assert(meshvpn_vpn_ca_save("-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----")==ESP_ERR_INVALID_ARG&&writes==before);
 char *junk=malloc(strlen(ca)+100);snprintf(junk,strlen(ca)+100,"%s\nPRIVATE KEY",ca);assert(!meshvpn_vpn_ca_valid(junk));free(junk);
 storage_error=true;assert(meshvpn_vpn_ca_save(ca)==ESP_FAIL);storage_error=false;
 assert(meshvpn_vpn_tls_name_valid("clean-vpn"));assert(meshvpn_vpn_tls_name_valid("exit.example"));
 assert(!meshvpn_vpn_tls_name_valid("*.example"));assert(!meshvpn_vpn_tls_name_valid("exit..example"));assert(!meshvpn_vpn_tls_name_valid("exit.example/"));
 assert(!meshvpn_vpn_tls_name_valid("-exit"));assert(!meshvpn_vpn_tls_name_valid("exit-.example"));assert(!meshvpn_vpn_tls_name_valid(""));
 char server[64];snprintf(server,sizeof(server),"192.0.2.1:%s",argv[1]);
 clock_ready=false;
 esp_tls_t *early=NULL;int early_fd=-1;
 assert(meshvpn_vpn_tls_connect(server,"exit.example","lo0",&early,&early_fd)!=ESP_OK&&!handshakes);
 meshvpn_vpn_tls_diag_t early_diag;meshvpn_vpn_tls_get_diag(&early_diag);assert(!strcmp(early_diag.reason,"waiting_for_clock"));
 clock_ready=true;
 identity_read_error=true;
 assert(meshvpn_vpn_tls_connect(server,"exit.example","lo0",&early,&early_fd)!=ESP_OK&&!early&&!handshakes);
 meshvpn_vpn_tls_get_diag(&early_diag);assert(!strcmp(early_diag.reason,"client_identity_unreadable"));
 identity_read_error=false;
 for(int i=0;i<3;i++){
  esp_tls_t*t=NULL;int fd=-1;esp_err_t err=meshvpn_vpn_tls_connect(server,argv[3],"lo0",&t,&fd);
  meshvpn_vpn_tls_diag_t d;meshvpn_vpn_tls_get_diag(&d);if(strcmp(d.reason,argv[4]))fprintf(stderr,"expected=%s got=%s sdk=%d tls=%d flags=%x\n",argv[4],d.reason,d.sdk_error,d.mbedtls_error,d.verify_flags);assert(!strcmp(d.reason,argv[4]));
  if(!strcmp(argv[4],"verified")){assert(err==ESP_OK&&t&&fd>=0&&!d.verify_flags);assert(fcntl(fd,F_GETFL)&O_NONBLOCK);esp_tls_conn_destroy(t);}
  else if(!strcmp(argv[4],"handshake_failed")){assert(err!=ESP_OK&&!t&&errno==EPROTO);}
  else {assert(err!=ESP_OK&&!t&&errno==EACCES&&d.verify_flags);}
 }
 assert(handshakes==3);assert(meshvpn_vpn_ca_save("")==ESP_OK&&!meshvpn_vpn_ca_configured());
 assert(meshvpn_vpn_ca_load(&loaded)==ESP_ERR_NVS_NOT_FOUND&&!loaded);
 corrupt_empty=true;assert(meshvpn_vpn_ca_load(&loaded)==ESP_ERR_INVALID_SIZE&&!loaded);corrupt_empty=false;
 read_error=true;assert(meshvpn_vpn_ca_load(&loaded)==ESP_FAIL&&!loaded);read_error=false;
 esp_tls_t*t=NULL;int fd=-1;assert(meshvpn_vpn_tls_connect(server,"exit.example","lo0",&t,&fd)!=ESP_OK&&!t&&handshakes==3);
 meshvpn_vpn_tls_diag_t d;meshvpn_vpn_tls_get_diag(&d);assert(!strcmp(d.reason,"ca_missing_or_unreadable"));
 meshvpn_client_identity_free(test_identity);free(ca);free(leaf);puts("TLS_TRUST_OK");return 0;
}
