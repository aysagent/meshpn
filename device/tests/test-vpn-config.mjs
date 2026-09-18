// Actual HTTP handler + actual validators, host HTTP/NVS boundaries only.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {execFileSync} from 'node:child_process';
const root=new URL('../',import.meta.url);
const read=name=>fs.readFileSync(new URL(name,root),'utf8');
function section(text,from,to){const a=text.indexOf(from),b=text.indexOf(to,a);if(a<0||b<a)throw Error(from);return text.slice(a,b);}
const handler=section(read('components/meshvpn_web/meshvpn_web.c'),'static void vpn_wipe(','static esp_err_t handler_unimplemented(');
const validate=section(read('components/meshvpn_vpn/meshvpn_vpn.c'),'esp_err_t meshvpn_vpn_validate_config(','static esp_err_t apply_config(');
const wg=section(read('components/meshvpn_vpn/meshvpn_wireguard.c'),'static bool decode_key(','bool meshvpn_wg_clock_ready(');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-vpn-config-'));
const source=`
#define _DEFAULT_SOURCE
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "meshvpn_vpn.h"
#include "meshvpn_vpn_frame.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"
#include "cJSON.h"
#define ESP_ERR_NOT_SUPPORTED 55
#define CONFIG_MESHVPN_USB_SUBNET_OCTET_2 7
typedef struct {uint32_t addr;} ip4_addr_t;
#define ip4addr_aton(s,a) inet_pton(AF_INET,s,&(a)->addr)
#define ip4_addr1(a) (((uint8_t*)&(a)->addr)[0])
#define ip4_addr2(a) (((uint8_t*)&(a)->addr)[1])
#define ip4_addr3(a) (((uint8_t*)&(a)->addr)[2])
#define strlcpy test_strlcpy
static size_t test_strlcpy(char*d,const char*s,size_t n){size_t l=strlen(s);if(n){size_t c=l<n-1?l:n-1;memcpy(d,s,c);d[c]=0;}return l;}
${wg}
${validate}
typedef int httpd_req_t;
static meshvpn_vpn_config_t saved;
static bool auth=true,save_fail=false,apply_fail=false;
static unsigned saves,applies,cache_clears;
static const char *last_error_message;
static cJSON *request;
static esp_err_t meshvpn_web_require_auth(httpd_req_t*r){(void)r;return auth?ESP_OK:ESP_FAIL;}
static cJSON *body(httpd_req_t*r,int max){(void)r;assert(max==1024);return cJSON_Duplicate(request,true);}
static esp_err_t error(httpd_req_t*r,const char*s,const char*m){(void)r;(void)s;last_error_message=m;return ESP_FAIL;}
static esp_err_t send_json(httpd_req_t*r,cJSON*j){(void)r;assert(!j->child);cJSON_Delete(j);return ESP_OK;}
esp_err_t meshvpn_config_load_vpn(meshvpn_vpn_config_t*c){*c=saved;return ESP_OK;}
esp_err_t meshvpn_config_save_vpn(const meshvpn_vpn_config_t*c){if(save_fail)return ESP_FAIL;saved=*c;saves++;return ESP_OK;}
esp_err_t meshvpn_vpn_start(const meshvpn_vpn_config_t*c){assert(c->enabled==saved.enabled);applies++;return apply_fail?ESP_FAIL:ESP_OK;}
esp_err_t meshvpn_vpn_check_internet(void){return ESP_OK;}
void meshvpn_vpn_get_status(meshvpn_vpn_status_t*s){memset(s,0,sizeof(*s));s->implemented=true;}
static void meshvpn_dns_clear_cache(void){cache_clears++;}
${handler}
static void replace(const char*k,const char*v){cJSON_DeleteItemFromObject(request,k);cJSON_AddStringToObject(request,k,v);}
int main(void){
httpd_req_t r=0;strcpy(saved.wg_dns,"1.1.1.1");saved.wg_keepalive=25;
request=cJSON_Parse("{\\"enabled\\":true,\\"transport\\":\\"socket\\",\\"server\\":\\"192.0.2.1:8765\\"}");assert(request);
auth=false;assert(handler_vpn_config(&r)==ESP_FAIL&&!saves);auth=true;
assert(handler_vpn_config(&r)==ESP_FAIL&&!saves);cJSON_AddBoolToObject(request,"allow_plaintext",true);
save_fail=true;assert(handler_vpn_config(&r)==ESP_FAIL&&!applies);save_fail=false;
assert(handler_vpn_config(&r)==ESP_OK&&saves==1&&applies==1);
replace("transport","wireguard");replace("server","192.0.2.1:51820");
replace("wg_address","10.6.0.2");replace("wg_dns","1.1.1.1");
assert(handler_vpn_config(&r)==ESP_FAIL); /* no keys */
unsigned char raw[32];memset(raw,7,sizeof(raw));unsigned char key[45];size_t len;
assert(!mbedtls_base64_encode(key,sizeof(key),&len,raw,sizeof(raw))&&len==44);key[44]=0;
replace("wg_private_key",(char*)key);replace("wg_public_key",(char*)key);replace("wg_preshared_key",(char*)key);
replace("wg_address","10.0.0.7/24");unsigned before_bad_address=saves;
assert(handler_vpn_config(&r)==ESP_FAIL&&saves==before_bad_address&&strstr(last_error_message,"Address:"));
assert(!strstr(last_error_message,(char*)key));
replace("wg_address","10.0.0.7/24,fd42:42:42::7/64");
assert(handler_vpn_config(&r)==ESP_FAIL&&strstr(last_error_message,"Address:"));
replace("wg_address","10.6.0.2");replace("server","vpn.example.com:51820");
assert(handler_vpn_config(&r)==ESP_FAIL&&strstr(last_error_message,"Endpoint/server:"));
replace("server","192.0.2.1:51820");replace("wg_dns","1.1.1.1,8.8.8.8");
assert(handler_vpn_config(&r)==ESP_FAIL&&strstr(last_error_message,"DNS:"));
replace("wg_dns","1.1.1.1");
assert(handler_vpn_config(&r)==ESP_OK&&saves==2);
replace("wg_private_key","");replace("wg_preshared_key","");
assert(handler_vpn_config(&r)==ESP_OK&&!strcmp(saved.wg_private_key,(char*)key)&&saved.wg_preshared_key[0]);
cJSON_AddBoolToObject(request,"wg_clear_psk",true);assert(handler_vpn_config(&r)==ESP_OK&&!saved.wg_preshared_key[0]);
replace("wg_address","192.168.7.2");assert(handler_vpn_config(&r)==ESP_FAIL);
replace("wg_address","192.168.4.2");assert(handler_vpn_config(&r)==ESP_FAIL);
replace("wg_address","10.6.0.2");replace("wg_public_key","invalid");assert(handler_vpn_config(&r)==ESP_FAIL);
assert(strstr(last_error_message,"PublicKey:"));
replace("wg_public_key",(char*)key);cJSON_AddNumberToObject(request,"wg_keepalive",-1);assert(handler_vpn_config(&r)==ESP_FAIL);
cJSON_DeleteItemFromObject(request,"wg_keepalive");
replace("wg_private_key","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");assert(handler_vpn_config(&r)==ESP_FAIL);
assert(strstr(last_error_message,"PrivateKey:"));
cJSON_Delete(request);assert(cache_clears==applies&&applies==saves);
request=cJSON_Parse("{\\"enabled\\":false,\\"transport\\":\\"wireguard\\",\\"server\\":\\"192.0.2.1:51820\\",\\"kill_switch\\":false}");
assert(handler_vpn_config(&r)==ESP_OK&&saved.allow_direct);
cJSON_DeleteItemFromObject(request,"kill_switch");
assert(handler_vpn_config(&r)==ESP_OK&&saved.allow_direct); /* omitted preserves */
cJSON_AddBoolToObject(request,"kill_switch",true);assert(handler_vpn_config(&r)==ESP_OK&&!saved.allow_direct);
replace("kill_switch","bad");assert(handler_vpn_config(&r)==ESP_FAIL);
cJSON_DeleteItemFromObject(request,"kill_switch");apply_fail=true;
assert(handler_vpn_config(&r)==ESP_FAIL);apply_fail=false;
assert(handler_vpn_restart(&r)==ESP_FAIL); /* disabled */
saved.enabled=true;assert(handler_vpn_restart(&r)==ESP_OK);
apply_fail=true;assert(handler_vpn_restart(&r)==ESP_FAIL);apply_fail=false;
assert(handler_vpn_check(&r)==ESP_OK);
auth=false;assert(handler_vpn_restart(&r)==ESP_FAIL);assert(handler_vpn_check(&r)==ESP_FAIL);
cJSON_Delete(request);
puts("VPN HTTP/config: auth, validation, key preservation/clear, storage errors and no reboot passed");
}
`;
const file=path.join(dir,'test.c'),bin=path.join(dir,'test');fs.writeFileSync(file,source);
const idf=process.env.IDF_PATH,json=path.join(idf,'components/json/cJSON');
execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
  '-I'+new URL('tests/stubs',root).pathname,'-I'+new URL('components/meshvpn_config/include',root).pathname,
  '-I'+new URL('components/meshvpn_vpn/include',root).pathname,'-I'+json,
  '-I'+path.join(idf,'components/mbedtls/mbedtls/include'),file,
  new URL('components/meshvpn_vpn/meshvpn_vpn_frame.c',root).pathname,path.join(json,'cJSON.c'),process.argv[2],'-lm','-o',bin],{stdio:'inherit'});
execFileSync(bin,{stdio:'inherit'});
