#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include "../components/meshvpn_web/meshvpn_cpu.c"

static unsigned alloc_calls, fail_allocation;
static jmp_buf task_deleted;
void *heap_caps_calloc(size_t count, size_t size, uint32_t caps)
{
    assert(caps == (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (++alloc_calls == fail_allocation) return NULL;
    return calloc(count, size);
}
static int64_t now = 7200000000LL;
static unsigned calls, task_count = 4;
static TaskStatus_t fixture[4];
int64_t esp_timer_get_time(void) { return now; }
TaskHandle_t xTaskGetHandle(const char *name) { return !strcmp(name,"wifi") ? (void *)3 : NULL; }
TaskHandle_t xTaskGetIdleTaskHandleForCore(unsigned core) { return (void *)(uintptr_t)(core+1); }
unsigned uxTaskGetSystemState(TaskStatus_t *out, unsigned capacity, uint64_t *total)
{
    calls++;
    assert(capacity >= 4);
    *total = now;
    memcpy(out, fixture, sizeof(fixture));
    return task_count;
}
unsigned xTaskGetTickCount(void) { return 0; }
void vTaskDelayUntil(TickType_t *w, TickType_t t) { (void)w;(void)t;assert(0); }
void vTaskDelete(TaskHandle_t t) { assert(t == NULL);longjmp(task_deleted, 1); }
int xTaskCreate(void (*f)(void *), const char *n, unsigned s, void *a, unsigned p, TaskHandle_t *h)
{ (void)f;(void)n;(void)s;(void)a;(void)p;(void)h;return pdPASS; }
SemaphoreHandle_t xSemaphoreCreateMutex(void) { return (void *)1; }
int xSemaphoreTake(SemaphoreHandle_t m,unsigned w) { (void)m;(void)w;return 1; }
int xSemaphoreGive(SemaphoreHandle_t m) { (void)m;return 1; }
void vSemaphoreDelete(SemaphoreHandle_t m) { (void)m; }
static cJSON *get(cJSON *o, const char *key) { return cJSON_GetObjectItemCaseSensitive(o,key); }

int main(void)
{
    meshvpn_cpu_start();
#if CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
#if CONFIG_SPIRAM
    /* Every sampler allocation must use PSRAM; partial failure releases the
     * others and exits without falling back to scarce internal memory. */
    for (fail_allocation = 1; fail_allocation <= 3; fail_allocation++) {
        alloc_calls = 0;
        if (!setjmp(task_deleted)) { sampler(NULL); assert(0); }
        assert(alloc_calls == 3);
    }
    fail_allocation = 0;
#endif
    TaskStatus_t raw[MAX_TASKS];
    sample_t prev = {0}, next = {0};
    for (unsigned i=0;i<4;i++) fixture[i]=(TaskStatus_t){.xHandle=(void *)(uintptr_t)(i+1),
        .pcTaskName=(const char *)1, /* Deliberately invalid: never dereference. */
        .xTaskNumber=i+10,.ulRunTimeCounter=5000000000ULL,.xCoreID=tskNO_AFFINITY};
    collect(raw,&prev,&next);
    assert(!prev.valid[0] && !prev.valid[1]);
    now+=2000000;
    fixture[0].ulRunTimeCounter+=1000000;
    fixture[1].ulRunTimeCounter+=1980000;
    fixture[2].ulRunTimeCounter+=1000000;
    fixture[3].xTaskNumber=100; /* New task: no delta against deleted ID. */
    collect(raw,&next,&prev);
    assert(next.valid[0] && next.valid[1]);
    assert(next.load[0]==50 && fabs(next.load[1]-1)<.0001);
    assert(next.tasks[2].load_pct==50 && !strcmp(next.tasks[2].name,"wifi"));
    assert(next.tasks[3].name==NULL && !next.tasks[3].valid);
    assert(next.tasks[2].core==-1);
    s_sample=next;
    cJSON *a=cJSON_CreateObject(), *b=cJSON_CreateObject();
    meshvpn_cpu_json(a);now+=1000;meshvpn_cpu_json(b);
    assert(calls==2); /* Readers never collect or reset a measurement. */
    assert(get(get(a,"cpu"),"sampled_us")->valuedouble==get(get(b,"cpu"),"sampled_us")->valuedouble);
    assert(get(get(b,"cpu"),"interval_ms")->valuedouble==2000);
    cJSON_Delete(a);cJSON_Delete(b);
#if CONFIG_SPIRAM
    fail_allocation = alloc_calls + 1;
    a=cJSON_CreateObject();meshvpn_cpu_json(a);
    assert(cJSON_IsFalse(get(get(a,"cpu"),"available")));
    cJSON_Delete(a);fail_allocation=0;
#endif
    now+=11000000;
    a=cJSON_CreateObject();meshvpn_cpu_json(a);
    assert(cJSON_IsFalse(get(get(a,"cpu"),"available")));
    assert(cJSON_IsNull(get(cJSON_GetArrayItem(get(get(a,"cpu"),"cores"),0),"load_pct")));
    cJSON_Delete(a);
    collect(raw,&prev,&next);
    assert(!prev.valid[0]); /* Delayed sampler does not publish a long average. */
    task_count=0;collect(raw,&next,&prev);assert(!next.complete);
#else
    cJSON *a=cJSON_CreateObject();meshvpn_cpu_json(a);
    assert(cJSON_IsFalse(get(get(a,"cpu"),"available")));
    cJSON_Delete(a);
#endif
    puts("CPU snapshot lifetime, reader independence, task identity and availability tests passed");
}
