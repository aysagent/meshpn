/* Production credential validation and atomic NVS record, host storage faults. */
#include "meshvpn_vpn_client_identity.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include "nvs.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
static int alloc_fail;
static void *heap_caps_malloc(size_t n,int flags){assert(flags==3);if(alloc_fail&&!--alloc_fail)return NULL;return malloc(n);}
static void esp_fill_random(void *out,size_t n){FILE*f=fopen("/dev/urandom","rb");assert(f&&fread(out,1,n,f)==n);fclose(f);}
static unsigned char stored[13000],staged[13000];static size_t stored_n,staged_n;
static bool read_fail,write_fail,commit_fail;
esp_err_t nvs_open(const char *name,int mode,nvs_handle_t *h){assert(!strcmp(name,"meshvpn"));(void)mode;*h=1;return ESP_OK;}
void nvs_close(nvs_handle_t h){assert(h==1);staged_n=0;}
esp_err_t nvs_get_blob(nvs_handle_t h,const char *key,void *out,size_t *n){assert(h==1&&!strcmp(key,"vpn_tls_client"));if(read_fail)return ESP_FAIL;if(!stored_n)return ESP_ERR_NVS_NOT_FOUND;if(!out){*n=stored_n;return ESP_OK;}assert(*n>=stored_n);memcpy(out,stored,stored_n);*n=stored_n;return ESP_OK;}
esp_err_t nvs_set_blob(nvs_handle_t h,const char *key,const void *data,size_t n){assert(h==1&&!strcmp(key,"vpn_tls_client")&&n<=sizeof(staged));if(write_fail)return ESP_FAIL;memcpy(staged,data,n);staged_n=n;return ESP_OK;}
esp_err_t nvs_commit(nvs_handle_t h){assert(h==1);if(commit_fail)return ESP_FAIL;memcpy(stored,staged,staged_n);stored_n=staged_n;return ESP_OK;}
#include "client-identity-production.inc"
static char *readfile(const char *p){FILE*f=fopen(p,"rb");assert(f);fseek(f,0,SEEK_END);long n=ftell(f);rewind(f);assert(n>0&&n<8192);char *s=calloc(1,n+1);assert(fread(s,1,n,f)==(size_t)n);fclose(f);return s;}
int main(int argc,char **argv){
 assert(argc==6);char *cert=readfile(argv[1]),*key=readfile(argv[2]),*wrong=readfile(argv[3]),*ca=readfile(argv[4]),*server=readfile(argv[5]);
 meshvpn_client_identity_t *id=(void*)1;
 assert(meshvpn_client_identity_load(&id)==ESP_ERR_NVS_NOT_FOUND&&!id);
 assert(meshvpn_client_identity_valid(cert,key));assert(!meshvpn_client_identity_valid(cert,wrong));
 assert(!meshvpn_client_identity_valid(ca,key));assert(!meshvpn_client_identity_valid(server,key));
 assert(!meshvpn_client_identity_valid(cert,""));assert(!meshvpn_client_identity_valid("",key));
 char *junk=malloc(strlen(key)+100);snprintf(junk,strlen(key)+100,"%s\nsecret junk",key);assert(!meshvpn_client_identity_valid(cert,junk));free(junk);
 assert(meshvpn_client_identity_save(cert,key)==ESP_OK&&meshvpn_client_identity_configured());
 assert(meshvpn_client_identity_load(&id)==ESP_OK&&!strcmp(id->certificate,cert)&&!strcmp(id->private_key,key));meshvpn_client_identity_free(id);
 size_t old=stored_n;unsigned char backup[13000];memcpy(backup,stored,old);
 write_fail=true;assert(meshvpn_client_identity_save("","")==ESP_FAIL);write_fail=false;
 commit_fail=true;assert(meshvpn_client_identity_save("","")==ESP_FAIL);commit_fail=false;
 assert(old==stored_n&&!memcmp(stored,backup,old));
 for(int fail=1;fail<=2;fail++){alloc_fail=fail;assert(meshvpn_client_identity_load(&id)==ESP_ERR_NO_MEM&&!id);}alloc_fail=0;
 read_fail=true;assert(meshvpn_client_identity_load(&id)==ESP_FAIL&&!id);read_fail=false;
 stored[stored_n-1]='x';assert(meshvpn_client_identity_load(&id)==ESP_ERR_INVALID_SIZE&&!id);memcpy(stored,backup,old);
 stored[0]=0;assert(meshvpn_client_identity_load(&id)==ESP_ERR_INVALID_SIZE&&!id);memcpy(stored,backup,old);
 assert(meshvpn_client_identity_save("","")==ESP_OK&&!meshvpn_client_identity_configured());
 assert(meshvpn_client_identity_load(&id)==ESP_ERR_NVS_NOT_FOUND&&!id);
 stored[0]='x';assert(meshvpn_client_identity_load(&id)==ESP_ERR_INVALID_SIZE&&!id);
 free(cert);free(key);free(wrong);free(ca);free(server);puts("Client identity validation/storage/OOM passed");
}
