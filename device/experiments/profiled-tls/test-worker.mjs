import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-profile-worker-'));
const src=new URL('../../components/meshvpn_profiled_tls/',import.meta.url).pathname;
fs.mkdirSync(path.join(dir,'freertos'));
fs.writeFileSync(path.join(dir,'esp_err.h'),'typedef int esp_err_t;\n#define ESP_OK 0\n#define ESP_FAIL -1\n#define ESP_ERR_NO_MEM 12\n#define ESP_ERR_INVALID_ARG 22\n');
fs.writeFileSync(path.join(dir,'sdkconfig.h'),'#define CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM 1\n#define CONFIG_MESHVPN_PROFILED_TLS_STACK_BYTES 32768\n');
fs.writeFileSync(path.join(dir,'esp_heap_caps.h'),'#include <stddef.h>\n#define MALLOC_CAP_SPIRAM 1\n#define MALLOC_CAP_8BIT 2\nvoid* heap_caps_malloc(size_t,int);\nvoid heap_caps_free(void*);\n');
const api=`#pragma once
#include <stdint.h>
#include <stddef.h>
typedef void* SemaphoreHandle_t;
typedef void* TaskHandle_t;
#define NULL ((void*)0)
#define pdPASS 1
#define portMAX_DELAY 0xffffffff
SemaphoreHandle_t xSemaphoreCreateBinary(void);
int xSemaphoreGive(SemaphoreHandle_t);
int xSemaphoreTake(SemaphoreHandle_t,unsigned);
void vSemaphoreDelete(SemaphoreHandle_t);
int xTaskCreateWithCaps(void(*)(void*),const char*,unsigned,void*,unsigned,TaskHandle_t*,unsigned);
void vTaskDeleteWithCaps(TaskHandle_t);
void vTaskSuspend(TaskHandle_t);
unsigned uxTaskGetStackHighWaterMark(TaskHandle_t);
`;
for(const name of ['FreeRTOS.h','task.h','semphr.h','idf_additions.h'])fs.writeFileSync(path.join(dir,'freertos',name),name==='FreeRTOS.h'?api:'#include "FreeRTOS.h"\n');
fs.writeFileSync(path.join(dir,'worker.c'),`
#include "meshvpn_profiled_tls.h"
#include "freertos/FreeRTOS.h"
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef struct {pthread_mutex_t lock;pthread_cond_t cond;int ready;} sem_t;
typedef struct {pthread_t thread;void(*fn)(void*);void*arg;} task_t;
static int fail_sem,fail_task,live_sem,live_task,jobs;
SemaphoreHandle_t xSemaphoreCreateBinary(void){
 if(fail_sem)return NULL;sem_t*s=calloc(1,sizeof(*s));assert(s);
 pthread_mutex_init(&s->lock,NULL);pthread_cond_init(&s->cond,NULL);live_sem++;return s;
}
int xSemaphoreGive(SemaphoreHandle_t p){sem_t*s=p;pthread_mutex_lock(&s->lock);s->ready=1;pthread_cond_signal(&s->cond);pthread_mutex_unlock(&s->lock);return 1;}
int xSemaphoreTake(SemaphoreHandle_t p,unsigned timeout){assert(timeout==portMAX_DELAY);sem_t*s=p;pthread_mutex_lock(&s->lock);while(!s->ready)pthread_cond_wait(&s->cond,&s->lock);pthread_mutex_unlock(&s->lock);return 1;}
void vSemaphoreDelete(SemaphoreHandle_t p){sem_t*s=p;assert(live_sem);pthread_cond_destroy(&s->cond);pthread_mutex_destroy(&s->lock);free(s);live_sem--;}
static void* entry(void*p){task_t*t=p;t->fn(t->arg);abort();}
int xTaskCreateWithCaps(void(*fn)(void*),const char*name,unsigned stack,void*arg,unsigned priority,TaskHandle_t*out,unsigned caps){
 assert(stack==32768 && caps==3 && priority==4 && !strcmp(name,"tls_profile"));
 if(fail_task)return 0;task_t*t=calloc(1,sizeof(*t));assert(t);t->fn=fn;t->arg=arg;*out=t;live_task++;assert(!pthread_create(&t->thread,NULL,entry,t));return pdPASS;
}
void vTaskDeleteWithCaps(TaskHandle_t p){task_t*t=p;assert(live_task);assert(!pthread_join(t->thread,NULL));free(t);live_task--;}
void vTaskSuspend(TaskHandle_t task){assert(!task);pthread_exit(NULL);}
unsigned uxTaskGetStackHighWaterMark(TaskHandle_t task){assert(!task);return 12345;}
static esp_err_t job(void*p){assert(p);jobs++;return *(int*)p;}
int main(void){
 uint32_t spare=999;int result=-71;
 assert(meshvpn_profiled_tls_run(NULL,NULL,&spare)==ESP_ERR_INVALID_ARG&&spare==0);
 fail_sem=1;assert(meshvpn_profiled_tls_run(job,&result,&spare)==ESP_ERR_NO_MEM&&!jobs&&!live_sem&&!live_task);fail_sem=0;
 fail_task=1;assert(meshvpn_profiled_tls_run(job,&result,&spare)==ESP_ERR_NO_MEM&&!jobs&&!live_sem&&!live_task);fail_task=0;
 for(int i=0;i<100;i++){assert(meshvpn_profiled_tls_run(job,&result,&spare)==result);assert(spare==12345&&!live_sem&&!live_task);}
 assert(jobs==100);puts("PSRAM worker: task/semaphore failures, 100 cycles, result propagation and cleanup passed");
}
`);
execFileSync('cc',['-std=c11','-Wall','-Wextra','-Werror','-Wno-macro-redefined','-fsanitize=address,undefined','-pthread','-DESP_PLATFORM','-I'+dir,'-I'+src+'include',src+'profile_worker.c',path.join(dir,'worker.c'),'-o',path.join(dir,'worker')],{stdio:'inherit'});
execFileSync(path.join(dir,'worker'),[],{stdio:'inherit'});
fs.writeFileSync(path.join(dir,'allocator.cc'),`
#include <cassert>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <unordered_map>
#include "esp_heap_caps.h"
static bool fail=false;
static std::unordered_map<void*,size_t> sizes;
void*heap_caps_malloc(size_t n,int caps){assert(caps==3);if(fail)return nullptr;void*p=malloc(n);if(p)sizes[p]=n;return p;}
void heap_caps_free(void*p){assert(sizes.count(p));sizes.erase(p);free(p);}
extern "C" void*OPENSSL_memory_alloc(size_t);
extern "C" void OPENSSL_memory_free(void*);
extern "C" size_t OPENSSL_memory_get_size(void*);
int main(){
 assert(!OPENSSL_memory_alloc(SIZE_MAX));fail=true;assert(!OPENSSL_memory_alloc(100));fail=false;
 void*a=OPENSSL_memory_alloc(400000),*b=OPENSSL_memory_alloc(400000);assert(a&&b);
 assert(OPENSSL_memory_get_size(a)==400000);assert(!OPENSSL_memory_alloc(400000));
 OPENSSL_memory_free(a);void*c=OPENSSL_memory_alloc(400000);assert(c);
 OPENSSL_memory_free(c);OPENSSL_memory_free(b);OPENSSL_memory_free(nullptr);
 for(int i=0;i<100;i++){void*p=OPENSSL_memory_alloc(1024*1024-64);assert(p);OPENSSL_memory_free(p);}
 assert(sizes.empty());puts("PSRAM allocator: cap/overflow, allocation failure rollback and reuse passed");
}
`);
execFileSync('c++',['-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+dir,src+'profile_allocator.cc',path.join(dir,'allocator.cc'),'-o',path.join(dir,'allocator')],{stdio:'inherit'});
execFileSync(path.join(dir,'allocator'),[],{stdio:'inherit'});
