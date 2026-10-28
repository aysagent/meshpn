#include <assert.h>
#include <stdio.h>
#include "meshvpn_config.h"
#include "nvs.h"
static char saved[128];
static esp_err_t open_error, write_error, commit_error;
static unsigned writes, commits, closes;
esp_err_t nvs_open(const char *ns, int mode, nvs_handle_t *out)
{ assert(!strcmp(ns,"meshvpn")); (void)mode; *out=1; return open_error; }
void nvs_close(nvs_handle_t n) { (void)n; closes++; }
esp_err_t nvs_get_str(nvs_handle_t n,const char *key,char *out,size_t *len)
{
    (void)n; assert(!strcmp(key,"hostname")); if(!saved[0])return ESP_ERR_NVS_NOT_FOUND;
    if(*len<strlen(saved)+1)return ESP_ERR_INVALID_SIZE;
    strcpy(out,saved);*len=strlen(saved)+1;return ESP_OK;
}
esp_err_t nvs_set_str(nvs_handle_t n,const char *key,const char *value)
{ (void)n;assert(!strcmp(key,"hostname"));writes++;if(write_error)return write_error;strcpy(saved,value);return ESP_OK; }
esp_err_t nvs_commit(nvs_handle_t n) { (void)n;commits++;return commit_error; }
int main(void)
{
    char out[64];
    assert(meshvpn_config_load_hostname(out)==ESP_OK&&!strcmp(out,MESHVPN_HOSTNAME_DEFAULT));
    assert(meshvpn_config_load_hostname(NULL)==ESP_ERR_INVALID_ARG);
    assert(meshvpn_config_save_hostname("Desk-2.LOCAL")==ESP_OK);
    assert(meshvpn_config_load_hostname(out)==ESP_OK&&!strcmp(out,"desk-2"));
    assert(meshvpn_hostname_local_query("desk-2.local",out));
    assert(meshvpn_hostname_local_query("desk-2.home.arpa",out));
    assert(!meshvpn_hostname_local_query("desk-2.local.evil",out));
    assert(!meshvpn_hostname_local_query("d",out));
    assert(!meshvpn_hostname_local_query("meshpn.local",out));
    const char *invalid[]={"", ".local", "a.b", "-a", "a-", "https://dongle.local", "a/", "a b", "имя", "a\n", NULL};
    unsigned before=writes;
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++)assert(meshvpn_config_save_hostname(invalid[i])==ESP_ERR_INVALID_ARG);
    assert(writes==before);
    char longest[71];memset(longest,'a',63);strcpy(longest+63,".local");
    assert(meshvpn_config_save_hostname(longest)==ESP_OK);
    assert(meshvpn_config_load_hostname(out)==ESP_OK&&strlen(out)==63);
    memset(longest,'a',64);longest[64]=0;
    assert(meshvpn_config_save_hostname(longest)==ESP_ERR_INVALID_ARG);
    open_error=ESP_FAIL;assert(meshvpn_config_load_hostname(out)==ESP_FAIL);assert(meshvpn_config_save_hostname("test")==ESP_FAIL);
    open_error=ESP_ERR_NVS_NOT_FOUND;assert(meshvpn_config_load_hostname(out)==ESP_OK&&!strcmp(out,MESHVPN_HOSTNAME_DEFAULT));
    open_error=ESP_OK;write_error=ESP_FAIL;before=commits;
    assert(meshvpn_config_save_hostname("test")==ESP_FAIL&&commits==before);
    write_error=ESP_OK;commit_error=ESP_FAIL;assert(meshvpn_config_save_hostname("test")==ESP_FAIL);
    assert(closes>0);
    puts("Hostname normalization, suffix boundaries, default, persistence and NVS errors passed");
}
