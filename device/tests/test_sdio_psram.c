/* Production generated SDIO RX functions, mocked allocation/queue boundary. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_LOGE(...) ((void)0)
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define H_SDIO_HOST_RX_MODE 1
#define H_SDIO_HOST_STREAMING_MODE 1
#define HOSTED_BLOCK_MAX 999
#define PRIO_Q_OTHERS 2
#define PRIO_Q_SERIAL 0
#define PRIO_Q_BT 1
#define ESP_SERIAL_IF 9
#define ESP_HCI_IF 10
#define le16toh(n) (n)
struct __attribute__((packed)) esp_payload_header {uint8_t if_type,if_num;uint16_t seq_num;uint8_t flags,len,offset,reserved;};
typedef struct {
 void *priv_buffer_handle;void(*free_buf_handle)(void*);uint16_t payload_len;
 uint8_t if_type,if_num,*payload;uint16_t seq_num;uint8_t flag;
} interface_buffer_handle_t;
static interface_buffer_handle_t queued[8];
static unsigned count,allocs,frees,fail_on,drop[4];
static int from_slave_queue[]={0,1,2},sem_from_slave_queue;
static void*heap_caps_malloc(size_t n,unsigned caps){
 assert(caps==(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT));allocs++;if(allocs==fail_on)return NULL;return malloc(n);
}
static void heap_caps_free(void*p){frees++;free(p);}
void meshvpn_hosted_rx_drop(unsigned reason,unsigned bytes){assert(reason<4&&bytes);drop[reason]++;}
static bool is_valid_sdio_rx_packet(const uint8_t*p,uint16_t*len,uint16_t*offset){
 const struct esp_payload_header*h=(const struct esp_payload_header*)p;*len=h->len;*offset=h->offset;return *len&&*offset==sizeof(*h);
}
static int queue_item(int q,const interface_buffer_handle_t*h,unsigned wait){
 assert(q==PRIO_Q_OTHERS&&wait==HOSTED_BLOCK_MAX&&count<8);queued[count++]=*h;return 0;
}
static int post(int s){assert(!s);return 0;}
static struct {struct {int(*_h_queue_item)(int,const interface_buffer_handle_t*,unsigned);int(*_h_post_semaphore)(int);} *funcs;}g_h;
#include "sdio-rx.inc"
static unsigned build(uint8_t*b,unsigned sequence){
 struct esp_payload_header h={.if_type=1,.len=17,.offset=sizeof(h),.seq_num=sequence};
 memcpy(b,&h,sizeof(h));memset(b+sizeof(h),sequence,17);return sizeof(h)+17;
}
static void consume(unsigned expected){
 assert(count==expected);
 for(unsigned i=0;i<count;i++){
  interface_buffer_handle_t*p=&queued[i];assert(p->free_buf_handle==heap_caps_free&&p->payload_len==17);
  for(unsigned j=0;j<p->payload_len;j++)assert(p->payload[j]==p->seq_num);
  p->free_buf_handle(p->priv_buffer_handle);
 }count=0;
}
int main(void){
 typeof(*g_h.funcs) ops={queue_item,post};g_h.funcs=&ops;
 uint8_t stream[100];unsigned n=build(stream,1);n+=build(stream+n,2);
 assert(sdio_push_data_to_queue(stream,n)==ESP_OK&&allocs==2);
 memset(stream,0,sizeof(stream));consume(2);assert(frees==2);
 n=build(stream,3);n+=build(stream+n,4);fail_on=allocs+1;
 assert(sdio_push_data_to_queue(stream,n)==ESP_OK&&drop[0]==1);memset(stream,0,sizeof(stream));consume(1);
 assert(frees==3&&allocs==4);
 n=build(stream,5);assert(sdio_push_data_to_queue(stream,n-1)==ESP_FAIL&&drop[2]==1&&allocs==4);
 /* Use exact-sized allocations so ASan detects a validator reading beyond
  * a short trailing header, rather than hiding it inside a larger array. */
 for(unsigned tail=1;tail<sizeof(struct esp_payload_header);tail++){
  uint8_t*short_stream=malloc(n+tail);build(short_stream,6);memset(short_stream+n,0xff,tail);
  assert(sdio_push_data_to_queue(short_stream,n+tail)==ESP_FAIL);free(short_stream);consume(1);
 }
 uint8_t*short_header=malloc(1);short_header[0]=0;
 assert(sdio_push_data_to_queue(short_header,1)==ESP_FAIL);free(short_header);
 n=build(stream,7);
 stream[offsetof(struct esp_payload_header,offset)]=0; /* Invalid complete header. */
 assert(sdio_push_data_to_queue(stream,n)==ESP_FAIL&&count==0);
 puts("SDIO RX PSRAM: independent packet ownership, matching free callback, OOM recovery and truncated-stream bounds passed");
}
