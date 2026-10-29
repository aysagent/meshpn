#include "meshvpn_vpn_profiles.h"
#include "meshvpn_config.h"
#include "nvs.h"
#include "esp_heap_caps.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
static meshpn_tls_profile_t *alloc_profile(void){return heap_caps_malloc(sizeof(meshpn_tls_profile_t),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);}
esp_err_t meshvpn_vpn_profile_slot(unsigned slot,meshpn_tls_profile_t*out){
 if(slot>=MESHPN_PROFILE_SLOTS||!out)return ESP_ERR_INVALID_ARG;
 nvs_handle_t h;esp_err_t e=nvs_open("meshvpn",NVS_READONLY,&h);if(e!=ESP_OK)return e;
 char key[16];snprintf(key,sizeof(key),"tls_p%u",slot);size_t n=sizeof(*out);
 e=nvs_get_blob(h,key,out,&n);nvs_close(h);
 if(e==ESP_OK){
  const unsigned char *raw=(const unsigned char*)out;
  if(n!=sizeof(*out)||raw[offsetof(meshpn_tls_profile_t,grease)]>1||raw[offsetof(meshpn_tls_profile_t,http1)]>1||!meshpn_profile_valid(out))return ESP_ERR_INVALID_SIZE;
 }
 return e;
}
esp_err_t meshvpn_vpn_profile_load(const char*id,meshpn_tls_profile_t*out){
 if(!id||!out)return ESP_ERR_INVALID_ARG;
 if(!strcmp(id,meshpn_builtin_profile.id)){*out=meshpn_builtin_profile;return ESP_OK;}
 for(unsigned i=0;i<MESHPN_PROFILE_SLOTS;i++){
  esp_err_t e=meshvpn_vpn_profile_slot(i,out);
  if(e==ESP_OK&&!strcmp(id,out->id))return ESP_OK;
  if(e!=ESP_OK&&e!=ESP_ERR_NVS_NOT_FOUND)return e;
 }return ESP_ERR_NVS_NOT_FOUND;
}
bool meshvpn_vpn_profile_exists(const char*id){
 if(id&&!strcmp(id,meshpn_builtin_profile.id))return true;
 meshpn_tls_profile_t*p=alloc_profile();if(!p)return false;
 bool found=meshvpn_vpn_profile_load(id,p)==ESP_OK;free(p);return found;
}
esp_err_t meshvpn_vpn_profile_save(const meshpn_tls_profile_t*p){
 if(!meshpn_profile_valid(p)||!strcmp(p->id,meshpn_builtin_profile.id))return ESP_ERR_INVALID_ARG;
 meshpn_tls_profile_t*old=alloc_profile();if(!old)return ESP_ERR_NO_MEM;
 unsigned vacant=MESHPN_PROFILE_SLOTS;esp_err_t e=ESP_OK;
 for(unsigned i=0;i<MESHPN_PROFILE_SLOTS;i++){
  e=meshvpn_vpn_profile_slot(i,old);
  if(e==ESP_ERR_NVS_NOT_FOUND){if(vacant==MESHPN_PROFILE_SLOTS)vacant=i;continue;}
  if(e!=ESP_OK)goto done;
  if(!strcmp(old->id,p->id)){e=ESP_ERR_INVALID_STATE;goto done;}
 }
 if(vacant==MESHPN_PROFILE_SLOTS){e=ESP_ERR_NO_MEM;goto done;}
 nvs_handle_t h;e=nvs_open("meshvpn",NVS_READWRITE,&h);
 if(e==ESP_OK){char key[16];snprintf(key,sizeof(key),"tls_p%u",vacant);e=nvs_set_blob(h,key,p,sizeof(*p));if(e==ESP_OK)e=nvs_commit(h);nvs_close(h);}
done:free(old);return e;
}
esp_err_t meshvpn_vpn_profile_delete(const char*id){
 if(!id||!strcmp(id,meshpn_builtin_profile.id))return ESP_ERR_INVALID_ARG;
 meshvpn_vpn_config_t cfg={0};esp_err_t e=meshvpn_config_load_vpn(&cfg);
 if(e!=ESP_OK)return e;
 bool selected=!strcmp(cfg.tls_profile,id);memset(&cfg,0,sizeof(cfg));
 if(selected)return ESP_ERR_INVALID_STATE;
 meshpn_tls_profile_t*p=alloc_profile();if(!p)return ESP_ERR_NO_MEM;
 for(unsigned i=0;i<MESHPN_PROFILE_SLOTS;i++){
  e=meshvpn_vpn_profile_slot(i,p);if(e==ESP_ERR_NVS_NOT_FOUND)continue;if(e!=ESP_OK)break;
  if(strcmp(p->id,id))continue;
  nvs_handle_t h;e=nvs_open("meshvpn",NVS_READWRITE,&h);
  if(e==ESP_OK){char key[16];snprintf(key,sizeof(key),"tls_p%u",i);e=nvs_erase_key(h,key);if(e==ESP_OK)e=nvs_commit(h);nvs_close(h);}free(p);return e;
 }
 free(p);return e==ESP_OK?ESP_ERR_NVS_NOT_FOUND:e;
}
