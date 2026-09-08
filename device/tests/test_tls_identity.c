#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Include production implementation to simulate a reboot of its static state. */
#include "../components/meshvpn_web/meshvpn_web_tls.c"
static unsigned char saved[8192];
static size_t saved_size;
esp_err_t nvs_open(const char *ns,int mode,nvs_handle_t *out)
{(void)ns;(void)mode;*out=1;return ESP_OK;}
esp_err_t nvs_get_blob(nvs_handle_t nvs,const char *key,void *out,size_t *size)
{
    (void)nvs;(void)key;
    if(!saved_size)return ESP_ERR_NVS_NOT_FOUND;
    if(!out){*size=saved_size;return ESP_OK;}
    if(*size<saved_size)return ESP_ERR_INVALID_SIZE;
    memcpy(out,saved,saved_size);*size=saved_size;return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t nvs,const char *key,const void *data,size_t size)
{(void)nvs;(void)key;assert(size<=sizeof(saved));memcpy(saved,data,size);saved_size=size;return ESP_OK;}
esp_err_t nvs_commit(nvs_handle_t nvs){(void)nvs;return ESP_OK;}
void nvs_close(nvs_handle_t nvs){(void)nvs;}
void esp_fill_random(void *buf,size_t size)
{
    FILE *f=fopen("/dev/urandom","rb");assert(f);
    assert(fread(buf,1,size,f)==size);fclose(f);
}
static char *read_pem(const char *path)
{
    FILE *f=fopen(path,"rb");assert(f);
    char *data=calloc(1,4096);assert(data);
    size_t n=fread(data,1,4095,f);assert(n>0&&!ferror(f)&&feof(f));fclose(f);return data;
}
static void reboot_identity(void){free(s_identity);s_identity=NULL;assert(meshvpn_web_tls_init()==ESP_OK);}
int main(int argc,char **argv)
{
    assert(argc==3);
    assert(meshvpn_web_tls_init()==ESP_OK);
    assert(saved_size<2048); /* compact EC identity, not a padded 6 KiB blob */
    char fingerprint[96];strcpy(fingerprint,meshvpn_web_tls_fingerprint());
    assert(strlen(fingerprint)==95);
    reboot_identity();assert(!strcmp(fingerprint,meshvpn_web_tls_fingerprint()));
    assert(meshvpn_web_tls_import("not a certificate","bad key")==ESP_ERR_INVALID_ARG);
    char *crt=read_pem(argv[1]),*key=read_pem(argv[2]);
    assert(meshvpn_web_tls_import(crt,meshvpn_web_tls_key())==ESP_ERR_INVALID_ARG);
    assert(meshvpn_web_tls_import(crt,key)==ESP_OK);
    assert(!strcmp(fingerprint,meshvpn_web_tls_fingerprint())); /* active identity unchanged */
    reboot_identity();assert(strcmp(fingerprint,meshvpn_web_tls_fingerprint()));
    assert(!strcmp(crt,meshvpn_web_tls_cert()));
    free(crt);free(key);free(s_identity);s_identity=NULL;
    puts("TLS identity generation, persistence, key validation and import passed");
}
