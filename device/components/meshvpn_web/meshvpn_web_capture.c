#include "meshvpn_web_capture.h"
#include "sdkconfig.h"
#if CONFIG_MESHVPN_PROFILED_TLS_ENABLE
#include "meshvpn_vpn_profiles.h"
#include "profile_capture.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef struct {
 uint32_t local_ip,peer_ip;
 int listener;
 int64_t deadline;
 char host[80],name[65],reason[128];
 meshpn_hello_capture_t *wire;
 meshpn_tls_profile_t profile;
} capture_job_t;
static portMUX_TYPE s_lock=portMUX_INITIALIZER_UNLOCKED;
static capture_job_t *s_job;
static meshvpn_capture_status_t s_status;
static bool s_cancel, s_ready;
#define LOCK() portENTER_CRITICAL(&s_lock)
#define UNLOCK() portEXIT_CRITICAL(&s_lock)
static bool cancelled(void){LOCK();bool v=s_cancel;UNLOCK();return v;}
static void release_wire(capture_job_t*j){if(j->wire){memset(j->wire,0,sizeof(*j->wire));free(j->wire);j->wire=NULL;}}
static void release_job(void){
 if(s_job){release_wire(s_job);
  memset(s_job,0,sizeof(*s_job));free(s_job);s_job=NULL;}
}
static void finish(const char *state,const char *message,bool ready){
 LOCK();s_ready=ready;s_status.active=false;s_status.port=0;
 snprintf(s_status.state,sizeof(s_status.state),"%s",state);
 snprintf(s_status.detail,sizeof(s_status.detail),"%s",message);UNLOCK();
}
static int readable(int fd,int64_t deadline){
 while(!cancelled()&&esp_timer_get_time()<deadline){
  fd_set rd;FD_ZERO(&rd);FD_SET(fd,&rd);struct timeval t={.tv_usec=100000};
  int r=select(fd+1,&rd,NULL,NULL,&t);if(r>0)return 1;if(r<0&&errno!=EINTR)return -1;
 }return 0;
}
static esp_err_t convert(void *arg){
 capture_job_t*j=arg;const char *reason=NULL;
 bool parsed=meshpn_profile_from_hello(j->wire->hello,j->wire->length,j->host,j->name,&j->profile,&reason);
 memset(j->wire,0,sizeof(*j->wire));
 if(!parsed){snprintf(j->reason,sizeof(j->reason),"%s",reason?reason:"Unsupported ClientHello");return ESP_ERR_NOT_SUPPORTED;}
 meshvpn_profile_check_t actual={0};
 if(!meshpn_profile_preview(&j->profile,&actual)){
  snprintf(j->reason,sizeof(j->reason),"Profile cannot be reproduced exactly (JA3/JA4), or TLS memory unavailable");return ESP_ERR_NOT_SUPPORTED;
 }return ESP_OK;
}
static void capture_task(void *arg){
 capture_job_t*j=arg;bool complete=false;unsigned attempts=0;
 while(!cancelled()&&esp_timer_get_time()<j->deadline&&attempts<8){
  int ready=readable(j->listener,j->deadline);if(ready<=0)break;
  struct sockaddr_in peer={0};socklen_t size=sizeof(peer);
  int fd=accept(j->listener,(struct sockaddr*)&peer,&size);if(fd<0)continue;
  attempts++;
  if(peer.sin_family!=AF_INET||peer.sin_addr.s_addr!=j->peer_ip){close(fd);continue;}
  memset(j->wire,0,sizeof(*j->wire));int result=0;
  int64_t until=esp_timer_get_time()+3000000;if(until>j->deadline)until=j->deadline;
  while(readable(fd,until)>0){
   uint8_t data[512];int n=recv(fd,data,sizeof(data),0);if(n<=0)break;
   result=meshpn_hello_capture_feed(j->wire,data,n);if(result)break;
  }
  /* No certificate, HTTP, session tickets or server TLS data are sent. */
  close(fd);
  if(result==1){complete=true;break;}
 }
 close(j->listener);j->listener=-1;
 if(cancelled()){release_wire(j);finish("cancelled","Capture cancelled",false);vTaskDelete(NULL);return;}
 if(!complete){release_wire(j);finish("expired","No ClientHello received. Open the admin by its .local name in a full browser and retry.",false);vTaskDelete(NULL);return;}
 LOCK();strcpy(s_status.state,"checking");s_status.port=0;UNLOCK();
 uint32_t spare=0;esp_err_t e=meshvpn_profiled_tls_run(convert,j,&spare);
 release_wire(j);
 if(cancelled())finish("cancelled","Capture cancelled",false);
 else if(e!=ESP_OK)finish("failed",*j->reason?j->reason:"Cannot start TLS preview worker",false);
 else finish("ready","Profile verified; saving",true);
 /* No job access after publishing active=false; HTTP task may free it. */
 vTaskDelete(NULL);
}
esp_err_t meshvpn_web_capture_start(uint32_t local_ip,uint32_t peer_ip,const char*host,const char*name,meshvpn_capture_status_t*out){
 if(!out||!local_ip||!peer_ip||!host||!name||!strlen(name)||strlen(name)>64||!strlen(host)||strlen(host)>=80)return ESP_ERR_INVALID_ARG;
 for(const char*p=host;*p;p++)if(!strchr("abcdefghijklmnopqrstuvwxyz0123456789-.",*p))return ESP_ERR_INVALID_ARG;
 for(const unsigned char*p=(const unsigned char*)name;*p;p++)if(*p<32||*p==127)return ESP_ERR_INVALID_ARG;
 LOCK();bool active=s_status.active;UNLOCK();if(active)return ESP_ERR_INVALID_STATE;
 release_job();s_ready=false;
 capture_job_t*j=heap_caps_calloc(1,sizeof(*j),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
 if(!j)return ESP_ERR_NO_MEM;
 j->listener=-1;j->wire=heap_caps_calloc(1,sizeof(*j->wire),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
 if(!j->wire){free(j);return ESP_ERR_NO_MEM;}
 j->local_ip=local_ip;j->peer_ip=peer_ip;strcpy(j->host,host);strcpy(j->name,name);
 int fd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
 if(fd<0){free(j->wire);free(j);return ESP_FAIL;}
 struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr.s_addr=local_ip};bool bound=false;
 for(unsigned i=0;i<8;i++){addr.sin_port=htons(49152+(esp_random()%16384));if(!bind(fd,(struct sockaddr*)&addr,sizeof(addr))){bound=true;break;}}
 if(!bound||listen(fd,2)){close(fd);free(j->wire);free(j);return ESP_FAIL;}
 j->listener=fd;j->deadline=esp_timer_get_time()+25000000;s_job=j;
 LOCK();memset(&s_status,0,sizeof(s_status));s_cancel=false;s_ready=false;
 s_status.ticket=esp_random();if(!s_status.ticket)s_status.ticket=1;
 s_status.port=ntohs(addr.sin_port);s_status.active=true;strcpy(s_status.state,"waiting");strcpy(s_status.host,host);UNLOCK();
 if(xTaskCreate(capture_task,"browser_capture",4096,j,3,NULL)!=pdPASS){
  close(fd);release_job();finish("failed","Cannot allocate capture task",false);return ESP_ERR_NO_MEM;
 }
 LOCK();*out=s_status;UNLOCK();return ESP_OK;
}
esp_err_t meshvpn_web_capture_poll(uint32_t ticket,meshvpn_capture_status_t*out){
 if(!out)return ESP_ERR_INVALID_ARG;
 LOCK();bool valid=ticket&&s_status.ticket==ticket,ready=s_ready,cancel=s_cancel;UNLOCK();if(!valid)return ESP_ERR_INVALID_ARG;
 /* Cancellation can race with the worker publishing its completed candidate. */
 if(ready&&cancel){release_job();finish("cancelled","Capture cancelled",false);ready=false;}
 if(ready){
  /* Only this HTTP task writes the catalog. Worker is finished; no concurrent NVS writer. */
  meshpn_tls_profile_t*old=heap_caps_malloc(sizeof(*old),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
  esp_err_t e=old?meshvpn_vpn_profile_load(s_job->profile.id,old):ESP_ERR_NO_MEM;
  if(e==ESP_OK){memcpy(old->name,s_job->profile.name,sizeof(old->name));if(memcmp(old,&s_job->profile,sizeof(*old)))e=ESP_ERR_INVALID_STATE;}
  bool reused=e==ESP_OK;
  if(e==ESP_ERR_NVS_NOT_FOUND)e=meshvpn_vpn_profile_save(&s_job->profile);
  free(old);
  LOCK();s_ready=false;s_status.saved=e==ESP_OK;s_status.reused=reused&&e==ESP_OK;
  if(e==ESP_OK){strcpy(s_status.state,"saved");strcpy(s_status.profile_id,s_job->profile.id);strcpy(s_status.detail,reused?"Profile already saved":"Profile captured and saved");}
  else {strcpy(s_status.state,"failed");strcpy(s_status.detail,"Cannot save profile: catalog full (4 imports), memory or NVS error");}UNLOCK();
 }
 LOCK();*out=s_status;bool done=!s_status.active;UNLOCK();if(done)release_job();
 return ESP_OK;
}
esp_err_t meshvpn_web_capture_cancel(uint32_t ticket){
 LOCK();bool valid=ticket&&s_status.ticket==ticket;if(valid)s_cancel=true;bool active=s_status.active;UNLOCK();
 if(!valid)return ESP_ERR_INVALID_ARG;
 if(!active&&s_ready){s_ready=false;release_job();finish("cancelled","Capture cancelled",false);}return ESP_OK;
}
#else
esp_err_t meshvpn_web_capture_start(uint32_t l,uint32_t p,const char*h,const char*n,meshvpn_capture_status_t*out){(void)l;(void)p;(void)h;(void)n;(void)out;return ESP_ERR_NOT_SUPPORTED;}
esp_err_t meshvpn_web_capture_poll(uint32_t t,meshvpn_capture_status_t*out){(void)t;(void)out;return ESP_ERR_NOT_SUPPORTED;}
esp_err_t meshvpn_web_capture_cancel(uint32_t t){(void)t;return ESP_ERR_NOT_SUPPORTED;}
#endif
