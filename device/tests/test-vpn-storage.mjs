// Compile the production NVS loader/saver with an in-memory NVS boundary.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root=new URL('../',import.meta.url);
const text=fs.readFileSync(new URL('components/meshvpn_config/meshvpn_config.c',root),'utf8');
const code=text.slice(text.indexOf('esp_err_t meshvpn_config_load_vpn('),text.indexOf('esp_err_t meshvpn_config_factory_reset('));
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-vpn-storage-'));
const source=`
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "meshvpn_config.h"
static int s_nvs;
static unsigned char record[2048];
static size_t record_size;
static const char *record_key;
static bool commit_fail;
static esp_err_t nvs_get_blob(int n,const char*k,void*out,size_t*len){
 (void)n;if(!record_key||strcmp(k,record_key))return ESP_ERR_NVS_NOT_FOUND;
 if(*len<record_size)return ESP_FAIL;
 memcpy(out,record,record_size);*len=record_size;return ESP_OK;
}
static esp_err_t nvs_set_blob(int n,const char*k,const void*in,size_t len){
 (void)n;record_key=k;assert(len<=sizeof(record));memcpy(record,in,len);record_size=len;return ESP_OK;
}
static esp_err_t nvs_commit(int n){(void)n;return commit_fail?ESP_FAIL:ESP_OK;}
static esp_err_t nvs_get_str(int n,const char*k,char*out,size_t*len){(void)n;(void)k;(void)out;(void)len;return ESP_ERR_NVS_NOT_FOUND;}
static esp_err_t nvs_get_u8(int n,const char*k,uint8_t*out){(void)n;(void)k;(void)out;return ESP_ERR_NVS_NOT_FOUND;}
${code}
int main(void){
 meshvpn_vpn_config_t c,out;
 assert(meshvpn_config_load_vpn(&c)==ESP_OK&&!c.enabled&&!c.allow_direct);
 c.enabled=true;strcpy(c.transport,"wireguard");strcpy(c.server,"192.0.2.1:51820");
 strcpy(c.wg_private_key,"private");strcpy(c.wg_address,"10.0.0.7");
 // Exact old v2 ABI, not just an assumed sizeof of the new structure.
 struct old_v2 {char server[129],sni[129],transport[32];bool enabled;
   char private_key[45],public_key[45],psk[45],address[16],dns[16];uint16_t keepalive;};
 assert(sizeof(struct old_v2)==offsetof(meshvpn_vpn_config_t,allow_direct));
 nvs_set_blob(0,"vpn_cfg2",&c,sizeof(struct old_v2));
 assert(meshvpn_config_load_vpn(&out)==ESP_OK&&out.enabled&&!out.allow_direct);
 assert(!strcmp(out.wg_private_key,"private")&&!strcmp(out.wg_address,"10.0.0.7"));
 struct old_v3 {struct old_v2 v2;bool allow_direct;};
 assert(sizeof(struct old_v3)==offsetof(meshvpn_vpn_config_t,wg_address_input));
 out.allow_direct=true;nvs_set_blob(0,"vpn_cfg3",&out,sizeof(struct old_v3));
 assert(meshvpn_config_load_vpn(&out)==ESP_OK&&out.allow_direct&&out.enabled&&!out.wg_address_input[0]);
 strcpy(out.wg_address_input,"10.0.0.7/24,fd42:42:42::7/64");
 out.allow_direct=true;assert(meshvpn_config_save_vpn(&out)==ESP_OK);
 assert(!strcmp(record_key,"vpn_cfg6"));
 assert(meshvpn_config_load_vpn(&c)==ESP_OK&&c.allow_direct&&c.enabled);
 assert(!strcmp(c.wg_address_input,"10.0.0.7/24,fd42:42:42::7/64"));
 // Exact v5 prefix/padding migration; new credentials must start empty.
 struct old_v4 {struct old_v3 v3;char address_input[160];};
 struct old_v5 {struct old_v4 v4;char endpoints[4][129];};
 const size_t v5_size=(offsetof(meshvpn_vpn_config_t,profiled_server)+1u)&~(size_t)1u;
 assert(v5_size==sizeof(struct old_v5));
 nvs_set_blob(0,"vpn_cfg5",&c,v5_size);
 assert(meshvpn_config_load_vpn(&out)==ESP_OK && !out.profiled_server[0] && !out.tls_psk_hex[0]);
 strcpy(out.tls_psk_hex,"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
 strcpy(out.tls_profile,"chromium156-capture1");strcpy(out.profiled_server,"192.0.2.5:443");
 assert(meshvpn_config_save_vpn(&out)==ESP_OK && meshvpn_config_load_vpn(&c)==ESP_OK);
 assert(!strcmp(c.tls_psk_hex,out.tls_psk_hex)&&!strcmp(c.profiled_server,out.profiled_server));
 // v4 upgrades retain the active endpoint, v5 preserves every transport.
 nvs_set_blob(0,"vpn_cfg4",&c,offsetof(meshvpn_vpn_config_t,saved_servers));
 assert(meshvpn_config_load_vpn(&out)==ESP_OK&&!strcmp(out.saved_servers[3],c.server));
 strcpy(out.saved_servers[0],"192.0.2.2:8765");
 assert(meshvpn_config_save_vpn(&out)==ESP_OK);
 assert(meshvpn_config_load_vpn(&c)==ESP_OK&&!strcmp(c.saved_servers[0],"192.0.2.2:8765"));
 char sni[sizeof(c.tls_server_name)];memcpy(sni,c.tls_server_name,sizeof(sni));
 memset(c.tls_server_name,'x',sizeof(c.tls_server_name));
 assert(meshvpn_config_save_vpn(&c)==ESP_OK&&meshvpn_config_load_vpn(&out)==ESP_FAIL);
 memcpy(c.tls_server_name,sni,sizeof(sni));
 strcpy(c.transport,"socket");assert(meshvpn_config_save_vpn(&c)==ESP_OK);
 assert(meshvpn_config_load_vpn(&out)==ESP_OK&&!strcmp(out.transport,"tcp"));
 c.allow_direct=false;assert(meshvpn_config_save_vpn(&c)==ESP_OK);
 assert(meshvpn_config_load_vpn(&out)==ESP_OK&&!out.allow_direct);
 record_size--;assert(meshvpn_config_load_vpn(&out)==ESP_FAIL); // corrupt v5 must not restore defaults
 commit_fail=true;assert(meshvpn_config_save_vpn(&c)==ESP_FAIL);
 struct {char server[129],sni[129],transport[32];bool enabled;} v1={.transport="socket",.enabled=true};
 nvs_set_blob(0,"vpn_cfg1",&v1,sizeof(v1));
 assert(meshvpn_config_load_vpn(&out)==ESP_OK&&out.enabled&&!out.allow_direct&&!strcmp(out.transport,"tcp"));
 puts("VPN NVS: v1-v5 migration, per-transport v6 roundtrip and corruption handling passed");
}
`;
const file=path.join(dir,'test.c'),bin=path.join(dir,'test');fs.writeFileSync(file,source);
execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
 '-I'+new URL('tests/stubs',root).pathname,'-I'+new URL('components/meshvpn_config/include',root).pathname,file,'-o',bin],{stdio:'inherit'});
execFileSync(bin,{stdio:'inherit'});
