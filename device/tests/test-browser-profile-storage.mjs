import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
const root=new URL('../',import.meta.url).pathname;
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-profile-storage-'));
const json=path.join(os.homedir(),'esp/esp-idf-meshpn-v5.5.5/components/json/cJSON');
const source=fs.readFileSync(root+'components/meshvpn_vpn/meshvpn_vpn_profiles.c','utf8').replace(/^#include .*/gm,'');
const web=fs.readFileSync(root+'components/meshvpn_web/meshvpn_web.c','utf8');
const handlers=web.slice(web.indexOf('static void profile_metadata'),web.indexOf('static void vpn_wipe(void *p, size_t len);'));
assert(handlers.includes('handler_browser_profiles'));
fs.writeFileSync(dir+'/test.c',`
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "cJSON.h"
#include "profile_model.h"
#define CONFIG_MESHVPN_PROFILED_TLS_ENABLE 1
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_ARG 1
#define ESP_ERR_INVALID_SIZE 2
#define ESP_ERR_NO_MEM 3
#define ESP_ERR_NVS_NOT_FOUND 4
#define ESP_ERR_INVALID_STATE 5
#define ESP_ERR_NOT_SUPPORTED 6
#define NVS_READONLY 0
#define NVS_READWRITE 1
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define HTTP_GET 0
#define HTTP_POST 1
typedef int esp_err_t;typedef int nvs_handle_t;
typedef struct {char tls_profile[32];char secret[65];} meshvpn_vpn_config_t;
typedef struct {int method;const char *uri;} httpd_req_t;
static meshvpn_vpn_config_t cfg;
static unsigned char disk[MESHPN_PROFILE_SLOTS][sizeof(meshpn_tls_profile_t)];
static size_t sizes[MESHPN_PROFILE_SLOTS];static int fail_stage;static bool alloc_fail,auth=true,preview_ok=true;
static unsigned previews,writes;static cJSON*request,*response;
static void *heap_caps_malloc(size_t n,int caps){assert(caps==3);return alloc_fail?NULL:malloc(n);}
static int slot(const char*k){assert(!strncmp(k,"tls_p",5)&&strlen(k)==6);int i=k[5]-'0';assert(i>=0&&i<MESHPN_PROFILE_SLOTS);return i;}
static int nvs_open(const char*ns,int mode,nvs_handle_t*h){assert(!strcmp(ns,"meshvpn"));(void)mode;*h=1;return fail_stage==1?ESP_FAIL:ESP_OK;}
static int nvs_get_blob(nvs_handle_t h,const char*k,void*out,size_t*n){assert(h==1);int i=slot(k);if(fail_stage==2)return ESP_FAIL;if(!sizes[i])return ESP_ERR_NVS_NOT_FOUND;if(*n<sizes[i])return ESP_ERR_INVALID_SIZE;*n=sizes[i];memcpy(out,disk[i],*n);return ESP_OK;}
static int nvs_set_blob(nvs_handle_t h,const char*k,const void*p,size_t n){assert(h==1&&n==sizeof(meshpn_tls_profile_t));if(fail_stage==3)return ESP_FAIL;int i=slot(k);memcpy(disk[i],p,n);sizes[i]=n;writes++;return ESP_OK;}
static int nvs_commit(nvs_handle_t h){assert(h==1);return fail_stage==4?ESP_FAIL:ESP_OK;}
static int nvs_erase_key(nvs_handle_t h,const char*k){assert(h==1);if(fail_stage==3)return ESP_FAIL;sizes[slot(k)]=0;return ESP_OK;}
static void nvs_close(nvs_handle_t h){assert(h==1);}
static int meshvpn_config_load_vpn(meshvpn_vpn_config_t*p){*p=cfg;return ESP_OK;}
${source}
static int meshvpn_web_require_auth(httpd_req_t*r){(void)r;return auth?ESP_OK:ESP_FAIL;}
static int error(httpd_req_t*r,const char*code,const char*message){(void)r;assert(code&&message);return ESP_FAIL;}
static int ok(httpd_req_t*r){(void)r;return ESP_OK;}
static cJSON*body(httpd_req_t*r,size_t limit){(void)r;assert(limit==4096||limit==128);return cJSON_Duplicate(request,true);}
static int send_json(httpd_req_t*r,cJSON*j){(void)r;cJSON_Delete(response);response=j;return ESP_OK;}
static bool meshpn_preview_stub(const meshpn_tls_profile_t*p,meshvpn_profile_check_t*out){assert(meshpn_profile_valid(p));memset(out,0,sizeof(*out));previews++;return preview_ok;}
#define meshpn_profile_preview meshpn_preview_stub
static int meshvpn_profiled_tls_run(int(*fn)(void*),void*arg,uint32_t*spare){*spare=1000;return fn(arg);}
${handlers}
int main(void){
 strcpy(cfg.tls_profile,meshpn_builtin_profile.id);strcpy(cfg.secret,"unchanged private secret");
 meshpn_tls_profile_t p=meshpn_builtin_profile,out;
 assert(meshvpn_vpn_profile_load(p.id,&out)==ESP_OK&&!memcmp(&p,&out,sizeof(p)));
 assert(meshvpn_vpn_profile_save(&p)==ESP_ERR_INVALID_ARG);
 strcpy(p.id,"p-one");assert(meshvpn_vpn_profile_save(&p)==ESP_OK);
 assert(meshvpn_vpn_profile_save(&p)==ESP_ERR_INVALID_STATE);
 assert(meshvpn_vpn_profile_load(p.id,&out)==ESP_OK&&!memcmp(&p,&out,sizeof(p)));
 strcpy(cfg.tls_profile,p.id);assert(meshvpn_vpn_profile_delete(p.id)==ESP_ERR_INVALID_STATE);
 strcpy(cfg.tls_profile,meshpn_builtin_profile.id);
 for(unsigned i=1;i<4;i++){snprintf(p.id,sizeof(p.id),"p-%u",i);assert(meshvpn_vpn_profile_save(&p)==ESP_OK);}
 strcpy(p.id,"p-full");assert(meshvpn_vpn_profile_save(&p)==ESP_ERR_NO_MEM);
 assert(meshvpn_vpn_profile_delete("p-one")==ESP_OK);assert(meshvpn_vpn_profile_load("p-one",&out)==ESP_ERR_NVS_NOT_FOUND);
 assert(meshvpn_vpn_profile_save(&p)==ESP_OK);
 for(int stage=1;stage<=4;stage++){fail_stage=stage;strcpy(p.id,"p-fault");if(stage>=3)sizes[0]=0;assert(meshvpn_vpn_profile_save(&p)!=ESP_OK);fail_stage=0;}
 memset(sizes,0,sizeof(sizes));strcpy(p.id,"p-corrupt");assert(meshvpn_vpn_profile_save(&p)==ESP_OK);
 disk[0][offsetof(meshpn_tls_profile_t,grease)]=2;assert(meshvpn_vpn_profile_load(p.id,&out)==ESP_ERR_INVALID_SIZE);
 memset(sizes,0,sizeof(sizes));
 httpd_req_t req={HTTP_GET,"/api/vpn/profiles"};
 auth=false;assert(handler_browser_profiles(&req)==ESP_FAIL);auth=true;
 assert(handler_browser_profiles(&req)==ESP_OK&&cJSON_GetArraySize(cJSON_GetObjectItem(response,"profiles"))==1);
 alloc_fail=true;assert(handler_browser_profiles(&req)==ESP_FAIL);alloc_fail=false;
 FILE*f=fopen(PROFILE_FILE,"rb");assert(f);char buf[4097];size_t n=fread(buf,1,4096,f);assert(n<4096);buf[n]=0;fclose(f);
 request=cJSON_Parse(buf);assert(request);req.method=HTTP_POST;
 unsigned before=writes;preview_ok=false;assert(handler_browser_profiles(&req)==ESP_FAIL&&writes==before);preview_ok=true;
 assert(handler_browser_profiles(&req)==ESP_OK&&writes==before+1);
 const char*id=cJSON_GetObjectItem(request,"id")->valuestring;strcpy(cfg.tls_profile,id);
 assert(handler_browser_profiles(&req)==ESP_FAIL); // duplicate cannot replace selected model
 cJSON*del=cJSON_CreateObject();cJSON_AddStringToObject(del,"id",id);cJSON_Delete(request);request=del;req.uri="/api/vpn/profiles/delete";
 assert(handler_browser_profiles(&req)==ESP_FAIL);strcpy(cfg.tls_profile,meshpn_builtin_profile.id);assert(handler_browser_profiles(&req)==ESP_OK);
 assert(!strcmp(cfg.secret,"unchanged private secret"));assert(previews==3);
 cJSON_Delete(request);cJSON_Delete(response);
 puts("Profile API/storage: auth, preview-before-write, immutable IDs, selected deletion, limits, NVS failures, corrupt blobs and secret preservation passed");
}
`);
const captures=JSON.parse(fs.readFileSync(process.argv[2]));fs.writeFileSync(dir+'/profile.json',JSON.stringify(captures.profiles[0]));
execFileSync('cc',['-std=c11','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-fsanitize=address,undefined','-DPROFILE_FILE="'+dir+'/profile.json"','-I'+root+'components/meshvpn_profiled_tls/include','-I'+json,dir+'/test.c',root+'components/meshvpn_profiled_tls/profile_model.c',json+'/cJSON.c','-o',dir+'/test'],{stdio:'inherit'});
execFileSync(dir+'/test',[],{stdio:'inherit'});
console.log('Storage test artifacts: '+dir);
