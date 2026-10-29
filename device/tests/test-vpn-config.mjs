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
#include "meshvpn_vpn_profile.h"
#include "meshvpn_vpn_trust.h"
#include "meshvpn_vpn_client_identity.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"
#include "cJSON.h"
#define ESP_ERR_NOT_SUPPORTED 55
#define CONFIG_MESHVPN_USB_SUBNET_OCTET_2 10
#define CONFIG_MESHVPN_AP_SUBNET_OCTET_2 11
typedef struct {uint32_t addr;} ip4_addr_t;
#define ip4addr_aton(s,a) inet_pton(AF_INET,s,&(a)->addr)
#define ip4_addr1(a) (((uint8_t*)&(a)->addr)[0])
#define ip4_addr2(a) (((uint8_t*)&(a)->addr)[1])
#define ip4_addr3(a) (((uint8_t*)&(a)->addr)[2])
#define strlcpy test_strlcpy
static size_t test_strlcpy(char*d,const char*s,size_t n){size_t l=strlen(s);if(n){size_t c=l<n-1?l:n-1;memcpy(d,s,c);d[c]=0;}return l;}
static bool plain_transport(const char*n){return n&&(!strcmp(n,"tcp")||!strcmp(n,"socket")||!strcmp(n,"udp")||!strcmp(n,"tls"));}
${wg}
${section(read('components/meshvpn_vpn/meshvpn_vpn_trust.c'),'bool meshvpn_vpn_tls_name_valid(', 'bool meshvpn_vpn_ca_valid(')}
${validate}
enum { HTTP_POST, HTTP_GET };
typedef struct { int method; } httpd_req_t;
static meshvpn_vpn_config_t saved;
static bool ca_configured=false;
bool meshvpn_vpn_ca_configured(void){return ca_configured;}
static bool load_fail=false;
static bool auth=true,save_fail=false,apply_fail=false;
static unsigned saves,applies,cache_clears;
static const char *last_error_message;
static cJSON *request;
static unsigned ca_saves,identity_saves;
esp_err_t meshvpn_client_identity_save(const char*c,const char*k){if(save_fail)return ESP_FAIL;if((*c||*k)&&(strcmp(c,"cert")||strcmp(k,"key")))return ESP_ERR_INVALID_ARG;identity_saves++;return ESP_OK;}
static bool ca_load_fail;
static char exported_ca[32];
esp_err_t meshvpn_vpn_ca_load(char **pem){*pem=NULL;if(ca_load_fail)return ESP_FAIL;if(!ca_configured)return ESP_ERR_NVS_NOT_FOUND;*pem=malloc(3);memcpy(*pem,"ca",3);return ESP_OK;}

esp_err_t meshvpn_vpn_ca_save(const char *p){if(!strcmp(p,"bad"))return ESP_ERR_INVALID_ARG;if(save_fail)return ESP_FAIL;ca_configured=*p!=0;ca_saves++;return ESP_OK;}
static esp_err_t meshvpn_web_require_auth(httpd_req_t*r){(void)r;return auth?ESP_OK:ESP_FAIL;}
static cJSON *body(httpd_req_t*r,int max){(void)r;assert(max==1024||max==MESHVPN_VPN_CA_MAX*2+128||max==(MESHVPN_CLIENT_CERT_MAX+MESHVPN_CLIENT_KEY_MAX)*2+256);return cJSON_Duplicate(request,true);}
static esp_err_t error(httpd_req_t*r,const char*s,const char*m){(void)r;(void)s;last_error_message=m;return ESP_FAIL;}
static esp_err_t send_json(httpd_req_t*r,cJSON*j){(void)r;if(j->child){cJSON *p=cJSON_GetObjectItem(j,"ca_pem");assert(cJSON_IsString(p));strcpy(exported_ca,p->valuestring);}cJSON_Delete(j);return ESP_OK;}
esp_err_t meshvpn_config_load_vpn(meshvpn_vpn_config_t*c){*c=saved;return load_fail?ESP_FAIL:ESP_OK;}
esp_err_t meshvpn_config_save_vpn(const meshvpn_vpn_config_t*c){if(save_fail)return ESP_FAIL;saved=*c;saves++;return ESP_OK;}
esp_err_t meshvpn_vpn_start(const meshvpn_vpn_config_t*c){assert(c->enabled==saved.enabled);applies++;return apply_fail?ESP_FAIL:ESP_OK;}
esp_err_t meshvpn_vpn_request_internet_check(void){return ESP_OK;}
void meshvpn_vpn_get_status(meshvpn_vpn_status_t*s){memset(s,0,sizeof(*s));s->implemented=true;}
static void meshvpn_dns_clear_cache(void){cache_clears++;}
static void vpn_wipe(void*p,size_t len);
static esp_err_t ok(httpd_req_t*r){return send_json(r,cJSON_CreateObject());}
${handler}
static void replace(const char*k,const char*v){cJSON_DeleteItemFromObject(request,k);cJSON_AddStringToObject(request,k,v);}
int main(void){
httpd_req_t r={.method=HTTP_POST};strcpy(saved.wg_dns,"1.1.1.1");saved.wg_keepalive=25;
request=cJSON_Parse("{\\"enabled\\":true,\\"transport\\":\\"tcp\\",\\"server\\":\\"192.0.2.1:8765\\"}");assert(request);
auth=false;assert(handler_vpn_config(&r)==ESP_FAIL&&!saves);auth=true;
assert(handler_vpn_config(&r)==ESP_FAIL&&!saves);cJSON_AddBoolToObject(request,"allow_plaintext",true);
save_fail=true;assert(handler_vpn_config(&r)==ESP_FAIL&&!applies);save_fail=false;
assert(handler_vpn_config(&r)==ESP_OK&&saves==1&&applies==1);
assert(!strcmp(saved.transport,"tcp"));
replace("transport","udp");replace("server","192.0.2.1:8765");
assert(handler_vpn_config(&r)==ESP_OK&&saves==2&&applies==2);
replace("transport","wireguard");replace("server","192.0.2.1:51820");
replace("wg_address","10.6.0.2");replace("wg_dns","1.1.1.1");
assert(handler_vpn_config(&r)==ESP_FAIL); /* no keys */
unsigned char raw[32];memset(raw,7,sizeof(raw));unsigned char key[45];size_t len;
assert(!mbedtls_base64_encode(key,sizeof(key),&len,raw,sizeof(raw))&&len==44);key[44]=0;
replace("wg_private_key",(char*)key);replace("wg_public_key",(char*)key);replace("wg_preshared_key",(char*)key);
replace("wg_address","10.0.0.7/33");unsigned before_bad_address=saves;
assert(handler_vpn_config(&r)==ESP_FAIL&&saves==before_bad_address&&strstr(last_error_message,"Address:"));
assert(!strstr(last_error_message,(char*)key));
replace("wg_address","10.0.0.7/24,fd42:42:42::7/129");
assert(handler_vpn_config(&r)==ESP_FAIL&&strstr(last_error_message,"Address:"));
replace("wg_address","10.6.0.2");replace("server","vpn.example.com:51820");
assert(handler_vpn_config(&r)==ESP_FAIL&&strstr(last_error_message,"Endpoint/server:"));
replace("server","192.0.2.1:51820");replace("wg_dns","1.1.1.1,8.8.8.8");
assert(handler_vpn_config(&r)==ESP_FAIL&&strstr(last_error_message,"DNS:"));
replace("wg_dns","1.1.1.1");
assert(handler_vpn_config(&r)==ESP_OK&&saves==3);
replace("wg_address","10.0.0.7/24");assert(handler_vpn_config(&r)==ESP_OK);
assert(!strcmp(saved.wg_address,"10.0.0.7")&&!strcmp(saved.wg_address_input,"10.0.0.7/24"));
replace("wg_address","10.0.0.7/24,fd42:42:42::7/64");assert(handler_vpn_config(&r)==ESP_OK);
assert(!strcmp(saved.wg_address,"10.0.0.7")&&!strcmp(saved.wg_address_input,"10.0.0.7/24,fd42:42:42::7/64"));
cJSON_DeleteItemFromObject(request,"wg_address");assert(handler_vpn_config(&r)==ESP_OK);
assert(!strcmp(saved.wg_address_input,"10.0.0.7/24,fd42:42:42::7/64")); /* omitted preserves */
replace("wg_private_key","");replace("wg_preshared_key","");
assert(handler_vpn_config(&r)==ESP_OK&&!strcmp(saved.wg_private_key,(char*)key)&&saved.wg_preshared_key[0]);
/* UI socket saves omit all WG fields. Secrets/profile and per-transport endpoints survive. */
cJSON *wg_request=request;request=cJSON_CreateObject();
cJSON_AddBoolToObject(request,"enabled",true);cJSON_AddBoolToObject(request,"allow_plaintext",true);
cJSON_AddStringToObject(request,"transport","tcp");cJSON_AddStringToObject(request,"server","192.0.2.2:8765");
assert(handler_vpn_config(&r)==ESP_OK);
assert(!strcmp(saved.wg_private_key,(char*)key)&&!strcmp(saved.wg_public_key,(char*)key)&&saved.wg_preshared_key[0]);
assert(!strcmp(saved.wg_address_input,"10.0.0.7/24,fd42:42:42::7/64")&&!strcmp(saved.wg_dns,"1.1.1.1"));
assert(saved.wg_keepalive==25&&!strcmp(saved.server,"192.0.2.2:8765"));
assert(!strcmp(saved.saved_servers[0],"192.0.2.2:8765")&&!strcmp(saved.saved_servers[3],"192.0.2.1:51820"));
cJSON_Delete(request);request=wg_request;
assert(handler_vpn_config(&r)==ESP_OK&&!strcmp(saved.server,"192.0.2.1:51820"));
cJSON_AddBoolToObject(request,"wg_clear_psk",true);assert(handler_vpn_config(&r)==ESP_OK&&!saved.wg_preshared_key[0]);
replace("wg_address","192.168.10.2");assert(handler_vpn_config(&r)==ESP_FAIL);
replace("wg_address","192.168.11.2");assert(handler_vpn_config(&r)==ESP_FAIL);
replace("wg_address","10.6.0.2");replace("wg_public_key","invalid");assert(handler_vpn_config(&r)==ESP_FAIL);
assert(strstr(last_error_message,"PublicKey:"));
replace("wg_public_key",(char*)key);cJSON_AddNumberToObject(request,"wg_keepalive",-1);assert(handler_vpn_config(&r)==ESP_FAIL);
cJSON_DeleteItemFromObject(request,"wg_keepalive");
replace("wg_private_key","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");assert(handler_vpn_config(&r)==ESP_FAIL);
assert(strstr(last_error_message,"PrivateKey:"));
cJSON_Delete(request);assert(cache_clears==applies&&applies==saves);
request=cJSON_Parse("{\\"enabled\\":false,\\"transport\\":\\"socket\\",\\"server\\":\\"192.0.2.2:8765\\"}");
assert(handler_vpn_config(&r)==ESP_OK&&!strcmp(saved.transport,"tcp"));
cJSON_Delete(request);
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
auth=true;cJSON_Delete(request);request=cJSON_CreateObject();
cJSON_AddBoolToObject(request,"enabled",true);replace("transport","tls");replace("server","192.0.2.5:443");
assert(handler_vpn_config(&r)==ESP_FAIL&&strstr(last_error_message,"TLS server name"));
replace("tls_server_name","exit.example");assert(handler_vpn_config(&r)==ESP_FAIL&&strstr(last_error_message,"TLS CA:"));
ca_configured=true;assert(handler_vpn_config(&r)==ESP_OK);replace("tls_server_name","https://exit.example");
assert(handler_vpn_config(&r)==ESP_FAIL);cJSON_Delete(request);
request=cJSON_CreateObject();cJSON_AddStringToObject(request,"ca_pem","ca");
replace("certificate_pem","cert");replace("private_key_pem","key");
auth=false;assert(handler_vpn_client_identity(&r)==ESP_FAIL&&!identity_saves);auth=true;
load_fail=true;assert(handler_vpn_client_identity(&r)==ESP_FAIL&&!identity_saves);load_fail=false;
replace("private_key_pem","bad");assert(handler_vpn_client_identity(&r)==ESP_FAIL&&!identity_saves);
replace("private_key_pem","key");save_fail=true;assert(handler_vpn_client_identity(&r)==ESP_FAIL&&!identity_saves);save_fail=false;
unsigned prior_identity_applies=applies;assert(handler_vpn_client_identity(&r)==ESP_OK&&identity_saves==1&&applies==prior_identity_applies+1);
replace("certificate_pem","");replace("private_key_pem","");
assert(handler_vpn_client_identity(&r)==ESP_OK&&identity_saves==2);
strcpy(saved.transport,"wireguard");prior_identity_applies=applies;
replace("certificate_pem","cert");replace("private_key_pem","key");
assert(handler_vpn_client_identity(&r)==ESP_OK&&identity_saves==3&&applies==prior_identity_applies);
strcpy(saved.transport,"tls");apply_fail=true;
assert(handler_vpn_client_identity(&r)==ESP_FAIL&&identity_saves==4);apply_fail=false;
auth=false;assert(handler_vpn_ca(&r)==ESP_FAIL&&!ca_saves);auth=true;
load_fail=true;assert(handler_vpn_ca(&r)==ESP_FAIL&&!ca_saves);load_fail=false;
replace("ca_pem","bad");assert(handler_vpn_ca(&r)==ESP_FAIL&&!ca_saves);
replace("ca_pem","ca");save_fail=true;assert(handler_vpn_ca(&r)==ESP_FAIL&&!ca_saves);save_fail=false;
unsigned previous_applies=applies;assert(handler_vpn_ca(&r)==ESP_OK&&ca_saves==1&&applies==previous_applies+1);
replace("ca_pem","");assert(handler_vpn_ca(&r)==ESP_OK&&!ca_configured&&applies==previous_applies+2);
strcpy(saved.transport,"wireguard");previous_applies=applies;
replace("ca_pem","ca");assert(handler_vpn_ca(&r)==ESP_OK&&applies==previous_applies);
cJSON_Delete(request);
r.method=HTTP_GET;previous_applies=applies;unsigned previous_ca_saves=ca_saves;
auth=false;assert(handler_vpn_ca(&r)==ESP_FAIL);auth=true;
assert(handler_vpn_ca(&r)==ESP_OK&&!strcmp(exported_ca,"ca"));
ca_load_fail=true;assert(handler_vpn_ca(&r)==ESP_FAIL);ca_load_fail=false;
ca_configured=false;assert(handler_vpn_ca(&r)==ESP_OK&&!exported_ca[0]);
assert(ca_saves==previous_ca_saves&&applies==previous_applies);
puts("VPN HTTP/config: auth, validation, key preservation/clear, storage errors and no reboot passed");
}
`;
const file=path.join(dir,'test.c'),bin=path.join(dir,'test');fs.writeFileSync(file,source);
const idf=process.env.IDF_PATH,json=path.join(idf,'components/json/cJSON');
execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-fsanitize=address,undefined',
  '-I'+new URL('tests/stubs',root).pathname,'-I'+new URL('components/meshvpn_config/include',root).pathname,
  '-I'+new URL('components/meshvpn_vpn/include',root).pathname,'-I'+json,
  '-I'+path.join(idf,'components/mbedtls/mbedtls/include'),file,
  new URL('components/meshvpn_vpn/meshvpn_vpn_frame.c',root).pathname,
  new URL('components/meshvpn_vpn/meshvpn_vpn_profile.c',root).pathname,path.join(json,'cJSON.c'),process.argv[2],'-lm','-o',bin],{stdio:'inherit'});
execFileSync(bin,{stdio:'inherit'});
