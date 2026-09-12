#include <stdatomic.h>
#include <stdio.h>
#include <sched.h>
#include "../components/meshvpn_usb/meshvpn_usb_tx_queue.c"

struct test_queue {
    pthread_mutex_t lock;
    unsigned head, tail, count, capacity;
    uint8_t items[MESHVPN_USB_TX_SLOTS];
};
static unsigned alloc_calls, queue_calls, task_calls, live_queues, fail_queue;
static bool fail_pool, fail_task, fail_publish, ready = true, verify_payload;
static atomic_llong clock_us;
static unsigned sends;
static esp_err_t send_result;
static uint8_t expected[1536];
static size_t expected_len;
#if CONFIG_MESHVPN_USB_TX_EVENT_WAIT
static unsigned notification;
static bool wake_during_wait, disconnect_during_wait;
BaseType_t xTaskNotifyGive(TaskHandle_t handle)
{ assert(handle == s_task); notification++; return pdPASS; }
uint32_t ulTaskNotifyTake(BaseType_t clear, TickType_t wait)
{
    assert(clear == pdTRUE);
    if (wait && !notification) {
        if (disconnect_during_wait) { disconnect_during_wait=false; tud_umount_cb(); }
        else if (wake_during_wait) { wake_during_wait=false; meshvpn_usb_tx_capacity_available(); }
        else atomic_fetch_add(&clock_us, (int64_t)wait * 1000);
    }
    unsigned n=notification; notification=0; return n;
}
static void test_capacity_wait(void)
{
    uint32_t epoch=meshvpn_usb_tx_queue_epoch();
    meshvpn_usb_tx_capacity_available(); /* stale event must be cleared */
    meshvpn_usb_tx_prepare_wait(); assert(!notification);
    meshvpn_usb_tx_capacity_available(); /* completion BEFORE entering wait */
    int64_t t=esp_timer_get_time();
    assert(meshvpn_usb_tx_wait_capacity(epoch,t+25000)==ESP_OK);
    assert(esp_timer_get_time()==t); /* no lost wakeup or unnecessary sleep */
    meshvpn_usb_tx_prepare_wait(); wake_during_wait=true;
    assert(meshvpn_usb_tx_wait_capacity(epoch,t+25000)==ESP_OK);
    meshvpn_usb_tx_prepare_wait();
    assert(meshvpn_usb_tx_wait_capacity(epoch,t+25000)==ESP_ERR_TIMEOUT);
    assert(esp_timer_get_time()==t+26000);
    meshvpn_usb_tx_prepare_wait(); meshvpn_usb_tx_capacity_available();
    /* Even a pending event cannot restart an exhausted absolute deadline. */
    assert(meshvpn_usb_tx_wait_capacity(epoch,t+25000)==ESP_ERR_TIMEOUT);
    meshvpn_usb_tx_prepare_wait(); disconnect_during_wait=true;
    assert(meshvpn_usb_tx_wait_capacity(epoch,esp_timer_get_time()+25000)==ESP_ERR_INVALID_STATE);
    meshvpn_usb_tx_prepare_wait(); tud_mount_cb(); /* reconnect already happened */
    assert(meshvpn_usb_tx_wait_capacity(epoch,esp_timer_get_time()+25000)==ESP_ERR_INVALID_STATE);
    assert(s_queue_stats.capacity_waits==6 && s_queue_stats.capacity_wakeups==3);
    assert(s_queue_stats.capacity_timeouts==2 && s_queue_stats.capacity_disconnects==2);
    assert(s_queue_stats.capacity_wait_us==26000 && s_queue_stats.event_wait);
    meshvpn_usb_tx_prepare_wait(); atomic_store(&clock_us,0);
}
#endif

bool tud_ready(void) { return ready; }
int64_t esp_timer_get_time(void) { return atomic_load(&clock_us); }
void *heap_caps_calloc(size_t count, size_t size, uint32_t caps)
{
    alloc_calls++;
    assert(caps == (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    assert(count == 8 && size >= 1536);
    return fail_pool ? NULL : calloc(count, size);
}
QueueHandle_t xQueueCreate(unsigned count, unsigned item_size)
{
    assert(count == 8 && item_size == 1);
    if (++queue_calls == fail_queue) return NULL;
    QueueHandle_t q=calloc(1,sizeof(*q)); assert(q);
    pthread_mutex_init(&q->lock,NULL); q->capacity=count; live_queues++;
    return q;
}
void vQueueDelete(QueueHandle_t q)
{ assert(q && !pthread_mutex_destroy(&q->lock)); free(q); live_queues--; }
BaseType_t xQueueSend(QueueHandle_t q, const void *item, TickType_t wait)
{
    assert(wait == 0);
    pthread_mutex_lock(&q->lock);
    bool ok=q->count<q->capacity && !(fail_publish && q==s_pending);
    if(ok){q->items[q->tail]=*(const uint8_t *)item; q->tail=(q->tail+1)%q->capacity; q->count++;}
    pthread_mutex_unlock(&q->lock); return ok;
}
BaseType_t xQueueReceive(QueueHandle_t q, void *item, TickType_t wait)
{
    assert(wait == 0 || wait == portMAX_DELAY);
    pthread_mutex_lock(&q->lock);
    bool ok=q->count>0;
    if(ok){*(uint8_t *)item=q->items[q->head]; q->head=(q->head+1)%q->capacity; q->count--;}
    pthread_mutex_unlock(&q->lock); return ok;
}
unsigned uxQueueMessagesWaiting(QueueHandle_t q)
{ pthread_mutex_lock(&q->lock); unsigned n=q->count; pthread_mutex_unlock(&q->lock); return n; }
BaseType_t xTaskCreate(void (*fn)(void *), const char *name, unsigned stack, void *arg, unsigned priority, TaskHandle_t *handle)
{
    task_calls++;
    assert(fn==tx_worker && !strcmp(name,"usb_tx") && stack==3072 && !arg && priority==5);
    if(fail_task)return 0;
    *handle=(void *)1; return pdPASS; /* driven by process_one below */
}
static esp_err_t send_owned(void *buffer, size_t len, uint32_t epoch)
{
    assert(epoch == meshvpn_usb_tx_queue_epoch());
    assert(buffer >= (void *)s_pool && (uint8_t *)buffer < (uint8_t *)(s_pool+8));
    if(verify_payload)assert(len == expected_len && !memcmp(buffer,expected,len));
    /* Snapshots during the callback must not deadlock or free the active slot. */
    meshvpn_usb_tx_queue_stats_t s;
    meshvpn_usb_tx_queue_get_stats(&s);
    assert(s.worker_active && s.in_use >= 1);
    sends++;
    atomic_fetch_add(&clock_us,100);
    return send_result;
}
static meshvpn_usb_tx_queue_stats_t stats(void)
{ meshvpn_usb_tx_queue_stats_t s; meshvpn_usb_tx_queue_get_stats(&s); return s; }
static void drain(void) { while(process_one(0)){} }
static void check_idle(void)
{
    meshvpn_usb_tx_queue_stats_t s=stats();
    assert(!s.in_use && !s.pending && !s.worker_active && uxQueueMessagesWaiting(s_free)==8);
    assert(s.enqueued == s.completed);
    assert(s.completed == s.sent+s.send_failed+s.expired+s.stale);
    assert(s.submitted == s.enqueued+s.full+s.no_host+s.invalid_length+s.not_ready+s.enqueue_failed);
}
static atomic_bool stop_worker;
static void *worker(void *arg)
{ (void)arg; while(!atomic_load(&stop_worker)){if(!process_one(0))sched_yield();} drain(); return NULL; }
static void *producer(void *arg)
{
    (void)arg;
    uint8_t packet[128]={0};
    for(unsigned i=0;i<5000;i++){
        esp_err_t err=meshvpn_usb_tx_queue_submit(packet,sizeof(packet));
        assert(err==ESP_OK || err==ESP_ERR_NO_MEM);
        memset(packet,0xa5,sizeof(packet));
    }
    return NULL;
}
int main(void)
{
    assert(!stats().enabled);
    assert(meshvpn_usb_tx_queue_submit("x",1)==ESP_ERR_INVALID_STATE);
    assert(meshvpn_usb_tx_queue_init(NULL)==ESP_ERR_INVALID_ARG);
    fail_pool=true;
    assert(meshvpn_usb_tx_queue_init(send_owned)==ESP_ERR_NO_MEM && !s_pool && !live_queues);
    fail_pool=false; fail_queue=queue_calls+1;
    assert(meshvpn_usb_tx_queue_init(send_owned)==ESP_ERR_NO_MEM && !s_pool && !live_queues);
    fail_queue=queue_calls+2;
    assert(meshvpn_usb_tx_queue_init(send_owned)==ESP_ERR_NO_MEM && !s_pool && !live_queues);
    fail_queue=0; fail_task=true;
    assert(meshvpn_usb_tx_queue_init(send_owned)==ESP_ERR_NO_MEM && !s_pool && !live_queues);
    fail_task=false;
    assert(meshvpn_usb_tx_queue_init(send_owned)==ESP_OK && live_queues==2);
    unsigned allocations=alloc_calls, tasks=task_calls;
    assert(meshvpn_usb_tx_queue_init(send_owned)==ESP_OK && tasks==task_calls && allocations==alloc_calls);
    assert(stats().init_failed==4 && stats().enabled);
#if CONFIG_MESHVPN_USB_TX_EVENT_WAIT
    test_capacity_wait();
#endif
    expected_len=sizeof(expected); memset(expected,0x4b,sizeof(expected)); verify_payload=true;
    uint8_t *packet=malloc(expected_len); memcpy(packet,expected,expected_len);
    for(unsigned i=0;i<8;i++)assert(meshvpn_usb_tx_queue_submit(packet,expected_len)==ESP_OK);
    assert(!sends && stats().in_use==8 && stats().high_water==8);
    assert(meshvpn_usb_tx_queue_submit(packet,expected_len)==ESP_ERR_NO_MEM);
    memset(packet,0xa5,expected_len); free(packet); /* caller lifetime ended */
    atomic_store(&clock_us,1000); drain(); check_idle();
    assert(sends==8 && stats().sent==8 && stats().queue_wait_us>0);
    verify_payload=false;
    assert(meshvpn_usb_tx_queue_submit(NULL,1)==ESP_ERR_INVALID_ARG);
    assert(meshvpn_usb_tx_queue_submit("x",0)==ESP_ERR_INVALID_ARG);
    assert(meshvpn_usb_tx_queue_submit("x",1537)==ESP_ERR_INVALID_ARG);
    ready=false; assert(meshvpn_usb_tx_queue_submit("x",1)==ESP_ERR_INVALID_STATE); ready=true;
    fail_publish=true; assert(meshvpn_usb_tx_queue_submit("x",1)==ESP_FAIL); fail_publish=false;
    check_idle();
    assert(meshvpn_usb_tx_queue_submit("x",1)==ESP_OK);
    atomic_fetch_add(&clock_us,50001); drain(); assert(stats().expired==1); check_idle();
    assert(meshvpn_usb_tx_queue_submit("x",1)==ESP_OK);
    tud_umount_cb(); tud_mount_cb(); /* rapid reconnect: ready stayed true in this model */
    drain(); assert(stats().stale==1); check_idle();
    assert(meshvpn_usb_tx_queue_submit("x",1)==ESP_OK); ready=false; drain(); ready=true;
    assert(stats().stale==2); check_idle();
    const esp_err_t errors[]={ESP_FAIL,ESP_ERR_TIMEOUT,ESP_ERR_INVALID_STATE,ESP_ERR_NO_MEM};
    for(unsigned i=0;i<4;i++){
        send_result=errors[i]; assert(meshvpn_usb_tx_queue_submit("x",1)==ESP_OK); drain(); check_idle();
    }
    assert(stats().send_failed==4);
    send_result=ESP_OK;
    pthread_t w,p1,p2;
    assert(!pthread_create(&w,NULL,worker,NULL));
    assert(!pthread_create(&p1,NULL,producer,NULL));
    assert(!pthread_create(&p2,NULL,producer,NULL));
    assert(!pthread_join(p1,NULL) && !pthread_join(p2,NULL));
    atomic_store(&stop_worker,true); assert(!pthread_join(w,NULL)); check_idle();
    assert(alloc_calls==allocations && task_calls==tasks); /* no per-packet allocation */
    vQueueDelete(s_pending); vQueueDelete(s_free); free(s_pool);
    puts("USB TX queue: ownership, bounds, OOM, stale/expiry, failures, concurrent producer/worker: OK");
}
