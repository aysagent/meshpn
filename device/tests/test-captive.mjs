import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root=new URL('../',import.meta.url), dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-captive-'));
function section(text,start,end){const a=text.indexOf(start),b=text.indexOf(end,a);if(a<0||b<a)throw Error(start);return text.slice(a,b);}
const proxy=fs.readFileSync(new URL('components/meshvpn_routing/meshvpn_dns_proxy.c',root),'utf8');
const web=fs.readFileSync(new URL('components/meshvpn_web/meshvpn_web.c',root),'utf8');
const source=`
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "meshvpn_hostname.h"
#include "meshvpn_dns_wire.h"
#define DNS_MAX 4096
#define ESP_OK 0
#define ESP_FAIL -1
typedef int esp_err_t;
typedef int httpd_req_t;
static bool setup, local=true, s_https;
static char name[64]="dongle", location[128], status[64];
static unsigned captive_count;
#define COUNT(field) (++captive_count)
static int meshvpn_config_load_hostname(char *out){strcpy(out,name);return 0;}
static bool meshvpn_wifi_needs_setup(void){return setup;}
static int local_answer(const uint8_t *query,size_t len,uint8_t *resp,uint32_t ip){
 meshvpn_dns_question_t q;assert(meshvpn_dns_question(query,len,&q));
 struct {uint32_t local_ip;} job_value={ip},*job=&job_value;
 ${section(proxy,'        char hostname[MESHVPN_HOSTNAME_MAX + 1];','        } else if ((n = cache_get')}
 } else return -1;
 return n;
}
static bool local_socket(httpd_req_t *r){(void)r;return local;}
static int error(httpd_req_t *r,const char *s,const char *message){(void)r;(void)message;strcpy(status,s);return -1;}
static int httpd_req_to_sockfd(httpd_req_t*r){(void)r;return 1;}
static int socket_name(int fd,struct sockaddr *out,socklen_t *len){
 assert(fd==1&&*len>=sizeof(struct sockaddr_in));struct sockaddr_in *s=(void*)out;
 s->sin_family=AF_INET;s->sin_addr.s_addr=inet_addr("192.168.11.1");return 0;
}
#define getsockname socket_name
static void headers(httpd_req_t*r){(void)r;}
static void httpd_resp_set_status(httpd_req_t*r,const char*s){(void)r;strcpy(status,s);}
static void httpd_resp_set_hdr(httpd_req_t*r,const char*k,const char*v){(void)r;assert(!strcmp(k,"Location"));strcpy(location,v);}
static int httpd_resp_sendstr(httpd_req_t*r,const char*s){(void)r;(void)s;return 0;}
${section(web,'static esp_err_t handler_captive(httpd_req_t *req)','esp_err_t meshvpn_web_start(void)')}
static size_t question(uint8_t *out,const char *name,unsigned type){
 memset(out,0,512);out[0]=17;out[2]=1;out[5]=1;size_t n=12;
 while(*name){const char *dot=strchr(name,'.');size_t len=dot?(size_t)(dot-name):strlen(name);
 out[n++]=len;memcpy(out+n,name,len);n+=len;if(!dot)break;name=dot+1;}
 out[n++]=0;out[n++]=0;out[n++]=type;out[n++]=0;out[n++]=1;return n;
}
int main(void){
 uint8_t q[512],r[4096];uint32_t ip=inet_addr("192.168.10.1");
 size_t n=question(q,"dongle.local",1);int got=local_answer(q,n,r,ip);
 assert(got==(int)n+16&&!memcmp(r+got-4,&ip,4)&&r[n+9]==30);
 strcpy(name,"desk-2");assert(local_answer(q,n,r,ip)==-1);
 n=question(q,"desk-2.home.arpa",1);assert(local_answer(q,n,r,ip)>0);
 n=question(q,"desk-2.local.evil",1);assert(local_answer(q,n,r,ip)==-1);
 setup=true;
 for(unsigned i=0;i<2;i++){
  ip=inet_addr(i?"192.168.11.1":"192.168.10.1");
  n=question(q,"captive.apple.com",1);got=local_answer(q,n,r,ip);
  assert(got==(int)n+16&&!memcmp(r+got-4,&ip,4));
  assert(!r[n+6]&&!r[n+7]&&!r[n+8]&&!r[n+9]); /* TTL zero */
 }
 n=question(q,"connectivitycheck.gstatic.com",28);got=local_answer(q,n,r,ip);assert(got==(int)n&&!r[7]);
 assert(captive_count==3);setup=false;assert(local_answer(q,n,r,ip)==-1);
 assert(handler_captive(NULL)==-1&&!strcmp(status,"404 Not Found"));
 setup=true;assert(handler_captive(NULL)==0&&!strcmp(status,"302 Found"));
 assert(!strcmp(location,"http://192.168.11.1/login"));
 s_https=true;assert(handler_captive(NULL)==0&&!strcmp(location,"https://192.168.11.1/login"));
 local=false;assert(handler_captive(NULL)==-1&&!strcmp(status,"403 Forbidden"));
 puts("Captive DNS gateway/zero TTL/AAAA/online bypass and HTTP setup-only redirect passed");
}
`;
try{
 const c=path.join(dir,'test.c'),bin=path.join(dir,'test');fs.writeFileSync(c,source);
 execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
 '-I'+new URL('components/meshvpn_config/include',root).pathname,'-I'+new URL('components/meshvpn_routing/include',root).pathname,
 c,new URL('components/meshvpn_routing/meshvpn_dns_wire.c',root).pathname,'-o',bin],{stdio:'inherit'});
 execFileSync(bin,{stdio:'inherit'});
}finally{fs.rmSync(dir,{recursive:true,force:true});}
