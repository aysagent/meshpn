#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "meshvpn_config.h"
#include "nvs.h"

static esp_err_t open_error, read_error, write_error, commit_error;
static bool present;
static uint8_t saved;
static unsigned closes, commits;
esp_err_t nvs_open(const char *ns,int mode,nvs_handle_t *out)
{ assert(!strcmp(ns,"meshvpn"));(void)mode;*out=1;return open_error; }
void nvs_close(nvs_handle_t nvs) { (void)nvs;closes++; }
esp_err_t nvs_get_u8(nvs_handle_t nvs,const char *key,uint8_t *value)
{
    (void)nvs;assert(!strcmp(key,"web_https"));
    if(read_error)return read_error;
    if(!present)return ESP_ERR_NVS_NOT_FOUND;
    *value=saved;return ESP_OK;
}
esp_err_t nvs_set_u8(nvs_handle_t nvs,const char *key,uint8_t value)
{
    (void)nvs;assert(!strcmp(key,"web_https"));
    if(write_error)return write_error;
    saved=value;present=true;return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t nvs) { (void)nvs;commits++;return commit_error; }
int main(void)
{
    bool enabled;
    assert(meshvpn_config_load_https(NULL)==ESP_ERR_INVALID_ARG);
    assert(meshvpn_config_load_https(&enabled)==ESP_OK);
    assert(enabled==!!CONFIG_MESHVPN_WEB_HTTPS);
    open_error=ESP_ERR_NVS_NOT_FOUND;
    assert(meshvpn_config_load_https(&enabled)==ESP_OK);
    assert(enabled==!!CONFIG_MESHVPN_WEB_HTTPS);
    open_error=ESP_FAIL;
    assert(meshvpn_config_load_https(&enabled)==ESP_FAIL);
    assert(meshvpn_config_save_https(true)==ESP_FAIL);
    open_error=ESP_OK;
    for(unsigned i=0;i<4;i++) {
        bool next=i%2;
        assert(meshvpn_config_save_https(next)==ESP_OK);
        assert(meshvpn_config_load_https(&enabled)==ESP_OK&&enabled==next);
    }
    unsigned before=commits;
    write_error=ESP_FAIL;
    assert(meshvpn_config_save_https(false)==ESP_FAIL&&commits==before);
    write_error=ESP_OK;commit_error=ESP_FAIL;
    assert(meshvpn_config_save_https(true)==ESP_FAIL);
    commit_error=ESP_OK;read_error=ESP_FAIL;
    assert(meshvpn_config_load_https(&enabled)==ESP_FAIL);
    read_error=ESP_OK;saved=2;
    assert(meshvpn_config_load_https(&enabled)==ESP_ERR_INVALID_ARG);
    present=false; /* factory reset/missing setting returns to build default */
    assert(meshvpn_config_load_https(&enabled)==ESP_OK&&enabled==!!CONFIG_MESHVPN_WEB_HTTPS);
    assert(closes>0);
    puts("HTTPS NVS mode, defaults, persistence and error propagation passed");
}
