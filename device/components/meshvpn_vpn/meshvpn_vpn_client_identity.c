#include "meshvpn_vpn_client_identity.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include "esp_random.h"
#include "esp_heap_caps.h"
#include "nvs.h"
#include <string.h>
#include <stdlib.h>

static int identity_rng(void *ctx,unsigned char *out,size_t n)
{ (void)ctx;esp_fill_random(out,n);return 0; }
/* Reject parser-ignored junk and key material hidden in a certificate bundle. */
static bool pem_blocks(const char *pem,const char *begin,const char *end,bool multiple)
{
    unsigned count=0;const char *p=pem;
    while(*p){
        p+=strspn(p," \r\n\t");if(!*p)break;
        if(strncmp(p,begin,strlen(begin)))return false;
        const char *q=strstr(p+strlen(begin),end);if(!q)return false;
        p=q+strlen(end);if(++count>1&&!multiple)return false;
    }
    return count>0;
}
bool meshvpn_client_identity_valid(const char *cert,const char *key)
{
    if(!cert||!key||!*cert||!*key||strlen(cert)>MESHVPN_CLIENT_CERT_MAX||strlen(key)>MESHVPN_CLIENT_KEY_MAX)return false;
    if(!pem_blocks(cert,"-----BEGIN CERTIFICATE-----","-----END CERTIFICATE-----",true))return false;
    if(!pem_blocks(key,"-----BEGIN PRIVATE KEY-----","-----END PRIVATE KEY-----",false)&&
       !pem_blocks(key,"-----BEGIN EC PRIVATE KEY-----","-----END EC PRIVATE KEY-----",false)&&
       !pem_blocks(key,"-----BEGIN RSA PRIVATE KEY-----","-----END RSA PRIVATE KEY-----",false))return false;
    mbedtls_x509_crt chain;mbedtls_x509_crt_init(&chain);
    mbedtls_pk_context pk;mbedtls_pk_init(&pk);
    bool ok=mbedtls_x509_crt_parse(&chain,(const unsigned char*)cert,strlen(cert)+1)==0&&
        !chain.MBEDTLS_PRIVATE(ca_istrue)&&
        mbedtls_x509_crt_check_key_usage(&chain,MBEDTLS_X509_KU_DIGITAL_SIGNATURE)==0&&
        mbedtls_x509_crt_check_extended_key_usage(&chain,MBEDTLS_OID_CLIENT_AUTH,MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH))==0&&
        mbedtls_pk_parse_key(&pk,(const unsigned char*)key,strlen(key)+1,NULL,0,identity_rng,NULL)==0&&
        mbedtls_pk_check_pair(&chain.pk,&pk,identity_rng,NULL)==0;
    mbedtls_pk_free(&pk);mbedtls_x509_crt_free(&chain);return ok;
}
void meshvpn_client_identity_free(meshvpn_client_identity_t *id)
{ if(id){mbedtls_platform_zeroize(id,sizeof(*id));free(id);} }
esp_err_t meshvpn_client_identity_load(meshvpn_client_identity_t **out)
{
    if(!out)return ESP_ERR_INVALID_ARG;
    *out=NULL;
    nvs_handle_t h;esp_err_t err=nvs_open("meshvpn",NVS_READONLY,&h);if(err!=ESP_OK)return err;
    size_t n=0;err=nvs_get_blob(h,"vpn_tls_client",NULL,&n);
    char *blob=NULL;meshvpn_client_identity_t *id=NULL;
    if(err==ESP_OK&&(n<1||n>MESHVPN_CLIENT_CERT_MAX+MESHVPN_CLIENT_KEY_MAX+2))err=ESP_ERR_INVALID_SIZE;
    size_t capacity=n;
    if(err==ESP_OK){
        blob=heap_caps_malloc(n,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
        if(!blob)err=ESP_ERR_NO_MEM;else err=nvs_get_blob(h,"vpn_tls_client",blob,&n);
    }
    nvs_close(h);
    if(err==ESP_OK){
        if(n!=capacity)err=ESP_ERR_INVALID_SIZE;
        else if(n==1)err=blob[0]==0?ESP_ERR_NVS_NOT_FOUND:ESP_ERR_INVALID_SIZE;
        else{
            char *end=memchr(blob,0,n);size_t a=end?(size_t)(end-blob):n;
            size_t b=n-a-1;
            if(!end||!a||a>MESHVPN_CLIENT_CERT_MAX||b<2||b>MESHVPN_CLIENT_KEY_MAX+1||blob[n-1]||memchr(end+1,0,b-1))err=ESP_ERR_INVALID_SIZE;
            else{
                id=heap_caps_malloc(sizeof(*id),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
                if(!id)err=ESP_ERR_NO_MEM;
                else{memset(id,0,sizeof(*id));memcpy(id->certificate,blob,a);memcpy(id->private_key,end+1,b);
                    if(!meshvpn_client_identity_valid(id->certificate,id->private_key))err=ESP_ERR_INVALID_ARG;}
            }
        }
    }
    if(blob){mbedtls_platform_zeroize(blob,capacity);free(blob);}
    if(err!=ESP_OK)meshvpn_client_identity_free(id);else *out=id;
    return err;
}
bool meshvpn_client_identity_configured(void)
{
    nvs_handle_t h;if(nvs_open("meshvpn",NVS_READONLY,&h)!=ESP_OK)return false;
    size_t n=0;esp_err_t e=nvs_get_blob(h,"vpn_tls_client",NULL,&n);nvs_close(h);
    return e==ESP_OK&&n>1&&n<=MESHVPN_CLIENT_CERT_MAX+MESHVPN_CLIENT_KEY_MAX+2;
}
esp_err_t meshvpn_client_identity_save(const char *cert,const char *key)
{
    if(!cert||!key)return ESP_ERR_INVALID_ARG;
    bool clear=!*cert&&!*key;
    if(!clear&&!meshvpn_client_identity_valid(cert,key))return ESP_ERR_INVALID_ARG;
    size_t a=strlen(cert)+1,n=clear?1:a+strlen(key)+1;
    char *blob=heap_caps_malloc(n,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);if(!blob)return ESP_ERR_NO_MEM;
    memcpy(blob,cert,a);if(!clear)memcpy(blob+a,key,n-a);
    nvs_handle_t h;esp_err_t e=nvs_open("meshvpn",NVS_READWRITE,&h);
    if(e==ESP_OK){e=nvs_set_blob(h,"vpn_tls_client",blob,n);if(e==ESP_OK)e=nvs_commit(h);nvs_close(h);}
    mbedtls_platform_zeroize(blob,n);free(blob);return e;
}
