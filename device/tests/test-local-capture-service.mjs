import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const root=new URL('../',import.meta.url).pathname,dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-capture-service-'));
const put=(name,data)=>{fs.mkdirSync(path.dirname(dir+'/'+name),{recursive:true});fs.writeFileSync(dir+'/'+name,data);};
put('esp_err.h',`#pragma once
 typedef int esp_err_t;
 #define ESP_OK 0
 #define ESP_FAIL -1
 #define ESP_ERR_INVALID_ARG 1
 #define ESP_ERR_INVALID_STATE 2
 #define ESP_ERR_NO_MEM 3
 #define ESP_ERR_NOT_SUPPORTED 4
 #define ESP_ERR_NVS_NOT_FOUND 5
`);
put('sdkconfig.h','#define CONFIG_MESHVPN_PROFILED_TLS_ENABLE 1\n');
put('esp_heap_caps.h',`#include <stddef.h>
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
void *heap_caps_malloc(size_t,int);void *heap_caps_calloc(size_t,size_t,int);
`);
put('esp_random.h','#include <stdint.h>\nuint32_t esp_random(void);\n');
put('esp_timer.h','#include <stdint.h>\nint64_t esp_timer_get_time(void);\n');
put('nvs.h','#include "esp_err.h"\n');
put('freertos/FreeRTOS.h',`#include <pthread.h>
#define portMUX_TYPE pthread_mutex_t
#define portMUX_INITIALIZER_UNLOCKED PTHREAD_MUTEX_INITIALIZER
#define portENTER_CRITICAL(p) pthread_mutex_lock(p)
#define portEXIT_CRITICAL(p) pthread_mutex_unlock(p)
#define pdPASS 1
`);
put('freertos/task.h','int xTaskCreate(void (*fn)(void*),const char*,int,void*,int,void*);void vTaskDelete(void*);\n');
put('check.c',`
#include <assert.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <signal.h>
#include "${root}components/meshvpn_web/meshvpn_web_capture.c"
static atomic_llong offset;
static int fail_alloc,fail_task,save_error,preview_error,parse_error,saves,mode;
static pthread_t worker,main_thread;
static void (*worker_fn)(void*);static void*worker_arg;
static meshpn_tls_profile_t stored;
void*heap_caps_malloc(size_t n,int caps){(void)caps;return fail_alloc?NULL:malloc(n);}
void*heap_caps_calloc(size_t n,size_t s,int caps){(void)caps;return fail_alloc?NULL:calloc(n,s);}
uint32_t esp_random(void){static uint32_t n=23817;return ++n;}
int64_t esp_timer_get_time(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000000LL+t.tv_nsec/1000+atomic_load(&offset);}
static void*run_thread(void*arg){(void)arg;worker_fn(worker_arg);return NULL;}
int xTaskCreate(void(*fn)(void*),const char*name,int stack,void*arg,int prio,void*out){(void)name;(void)stack;(void)prio;(void)out;if(fail_task)return 0;worker_fn=fn;worker_arg=arg;return pthread_create(&worker,NULL,run_thread,NULL)?0:1;}
void vTaskDelete(void*arg){(void)arg;pthread_exit(NULL);}
esp_err_t meshvpn_profiled_tls_run(esp_err_t(*fn)(void*),void*arg,uint32_t*spare){assert(!pthread_equal(main_thread,pthread_self()));*spare=1000;return fn(arg);}
bool meshpn_profile_from_hello(const uint8_t*h,size_t n,const char*host,const char*name,meshpn_tls_profile_t*p,const char**why){(void)h;assert(n==42);assert(!strcmp(host,"dongle.local"));assert(!pthread_equal(main_thread,pthread_self()));*p=meshpn_builtin_profile;strcpy(p->id,"c-test");snprintf(p->name,sizeof(p->name),"%s",name);*why=parse_error?"Unsupported browser":NULL;return !parse_error;}
bool meshpn_profile_preview(const meshpn_tls_profile_t*p,meshvpn_profile_check_t*c){(void)p;(void)c;return !preview_error;}
esp_err_t meshvpn_vpn_profile_load(const char*id,meshpn_tls_profile_t*p){(void)id;if(!mode)return ESP_ERR_NVS_NOT_FOUND;*p=stored;if(mode==2)p->http1=!p->http1;return ESP_OK;}
esp_err_t meshvpn_vpn_profile_save(const meshpn_tls_profile_t*p){assert(pthread_equal(main_thread,pthread_self()));saves++;stored=*p;return save_error;}
static uint32_t local;static meshvpn_capture_status_t st;
static void start(uint32_t peer){assert(meshvpn_web_capture_start(local,peer,"dongle.local","Browser",&st)==ESP_OK);assert(st.active&&st.port);assert(meshvpn_web_capture_start(local,peer,"dongle.local","Browser",&st)==ESP_ERR_INVALID_STATE);}
static void hello(void){int fd=socket(AF_INET,SOCK_STREAM,0);assert(fd>=0);struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(st.port),.sin_addr.s_addr=local};assert(!connect(fd,(struct sockaddr*)&a,sizeof(a)));uint8_t wire[47]={22,3,1,0,42,1,0,0,38};(void)send(fd,wire,sizeof(wire),0);close(fd);}
static void join_poll(void){pthread_join(worker,NULL);assert(meshvpn_web_capture_poll(st.ticket,&st)==ESP_OK);assert(!st.active&&!s_job);}
int main(void){signal(SIGPIPE,SIG_IGN);main_thread=pthread_self();local=htonl(0x7f000001);
 assert(meshvpn_web_capture_start(local,local,"bad/host","Browser",&st)==ESP_ERR_INVALID_ARG);
 fail_alloc=1;assert(meshvpn_web_capture_start(local,local,"dongle.local","Browser",&st)==ESP_ERR_NO_MEM);fail_alloc=0;
 fail_task=1;assert(meshvpn_web_capture_start(local,local,"dongle.local","Browser",&st)==ESP_ERR_NO_MEM);assert(!s_job);fail_task=0;
 start(local);assert(meshvpn_web_capture_poll(st.ticket+1,&st)==ESP_ERR_INVALID_ARG);assert(meshvpn_web_capture_cancel(st.ticket+1)==ESP_ERR_INVALID_ARG);hello();join_poll();assert(st.saved&&saves==1&&!st.reused);
 assert(meshvpn_web_capture_cancel(st.ticket)==ESP_OK);assert(meshvpn_web_capture_poll(st.ticket,&st)==ESP_OK&&st.saved);
 mode=1;start(local);hello();join_poll();assert(st.saved&&st.reused&&saves==1);
 mode=2;start(local);hello();join_poll();assert(!st.saved&&!strcmp(st.state,"failed")&&saves==1);mode=0;
 save_error=ESP_FAIL;start(local);hello();join_poll();assert(!st.saved&&saves==2);save_error=0;
 parse_error=1;start(local);hello();join_poll();assert(!st.saved&&!strcmp(st.state,"failed")&&saves==2);parse_error=0;
 preview_error=1;start(local);hello();join_poll();assert(!st.saved&&saves==2);preview_error=0;
 start(local);assert(meshvpn_web_capture_cancel(st.ticket)==ESP_OK);join_poll();assert(!strcmp(st.state,"cancelled")&&saves==2);
 start(local);hello();pthread_join(worker,NULL);assert(s_ready);assert(meshvpn_web_capture_cancel(st.ticket)==ESP_OK);assert(!s_job&&!s_ready&&saves==2);
 start(local);atomic_fetch_add(&offset,26000000);join_poll();assert(!strcmp(st.state,"expired")&&saves==2);
 start(htonl(0x7f000002));for(int i=0;i<8;i++)hello();join_poll();assert(!strcmp(st.state,"expired")&&saves==2);
 start(local);hello();pthread_join(worker,NULL);s_cancel=true;assert(s_ready);assert(meshvpn_web_capture_poll(st.ticket,&st)==ESP_OK);assert(!st.saved&&!s_job&&!strcmp(st.state,"cancelled")&&saves==2);
 // Completed but unpolled capture owns only a bounded model; next start reclaims it.
 start(local);hello();pthread_join(worker,NULL);assert(s_job&&!s_job->wire&&s_ready);start(local);assert(meshvpn_web_capture_cancel(st.ticket)==ESP_OK);join_poll();assert(saves==2);
 puts("Capture lifecycle: peer isolation, limits, timeout, cancel, reuse/conflict, NVS/OOM/task failures and cleanup passed");
}
`);
execFileSync('cc',['-std=c11','-D_POSIX_C_SOURCE=200809L','-DESP_PLATFORM','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-pthread','-I'+dir,'-I'+root+'components/meshvpn_web/include','-I'+root+'components/meshvpn_profiled_tls/include','-I'+root+'components/meshvpn_vpn/include',dir+'/check.c',root+'components/meshvpn_profiled_tls/profile_capture_wire.c','-o',dir+'/check'],{stdio:'inherit'});
execFileSync(dir+'/check',[],{stdio:'inherit',timeout:15000});
put('sdkconfig.h','#define CONFIG_MESHVPN_PROFILED_TLS_ENABLE 0\n');
put('disabled.c',`#include <assert.h>
#include "meshvpn_web_capture.h"
int main(void){meshvpn_capture_status_t s;
assert(meshvpn_web_capture_start(1,1,"dongle.local","Browser",&s)==ESP_ERR_NOT_SUPPORTED);
assert(meshvpn_web_capture_poll(1,&s)==ESP_ERR_NOT_SUPPORTED);
assert(meshvpn_web_capture_cancel(1)==ESP_ERR_NOT_SUPPORTED);}
`);
execFileSync('cc',['-std=c11','-Wall','-Wextra','-Werror','-I'+dir,'-I'+root+'components/meshvpn_web/include',dir+'/disabled.c',root+'components/meshvpn_web/meshvpn_web_capture.c','-o',dir+'/disabled'],{stdio:'inherit'});
execFileSync(dir+'/disabled',[],{stdio:'inherit'});
