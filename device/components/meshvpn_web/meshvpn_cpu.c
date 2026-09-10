#include "meshvpn_cpu.h"
#include "meshvpn_cpu_math.h"
#include "sdkconfig.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <stdlib.h>

#if CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
_Static_assert(sizeof(configRUN_TIME_COUNTER_TYPE) == 8, "CPU telemetry requires 64-bit runtime counters");
#define MAX_TASKS 64
typedef struct {
    unsigned id, priority, stack_free;
    int core;
    const char *name; /* Always a static literal, never TaskStatus_t.pcTaskName. */
    uint64_t runtime_us;
    double load_pct;
    bool valid;
} task_sample_t;
typedef struct {
    uint64_t sampled_us, interval_us, collection_us;
    bool complete, valid[CONFIG_FREERTOS_NUMBER_OF_CORES];
    double load[CONFIG_FREERTOS_NUMBER_OF_CORES];
    unsigned count;
    task_sample_t tasks[MAX_TASKS];
} sample_t;
static sample_t s_sample;
static SemaphoreHandle_t s_mutex;
static const char *const s_names[] = {
    "wifi", "tiT", "tcpip_thread", "TinyUSB", "main", "boot_btn", "wifi_profiles",
    "dns_listener", "dns_worker", "mdns", "mdns_recv", "mdns recv task", "httpd",
    "esp_timer", "sys_evt", "Tmr Svc", "ipc0", "ipc1", "IDLE0", "IDLE1", "cpu_stats"
};

static void collect(TaskStatus_t *raw, sample_t *next, const sample_t *prev)
{
    TaskHandle_t known[sizeof(s_names) / sizeof(s_names[0])];
    for (unsigned i = 0; i < sizeof(known) / sizeof(known[0]); i++)
        known[i] = xTaskGetHandle(s_names[i]);
    TaskHandle_t idle[CONFIG_FREERTOS_NUMBER_OF_CORES];
    for (unsigned c = 0; c < CONFIG_FREERTOS_NUMBER_OF_CORES; c++)
        idle[c] = xTaskGetIdleTaskHandleForCore(c);
    uint64_t start = esp_timer_get_time();
    configRUN_TIME_COUNTER_TYPE total = 0;
    next->count = uxTaskGetSystemState(raw, MAX_TASKS, &total);
    next->collection_us = esp_timer_get_time() - start;
    next->sampled_us = total ? total : (uint64_t)esp_timer_get_time();
    next->interval_us = prev->sampled_us ? next->sampled_us - prev->sampled_us : 0;
    next->complete = next->count != 0;
    for (unsigned c = 0; c < CONFIG_FREERTOS_NUMBER_OF_CORES; c++) next->valid[c] = false;
    for (unsigned i = 0; i < next->count; i++) {
        task_sample_t *t = &next->tasks[i];
        *t = (task_sample_t){.id = raw[i].xTaskNumber,
            .runtime_us = raw[i].ulRunTimeCounter, .priority = raw[i].uxCurrentPriority,
            .stack_free = raw[i].usStackHighWaterMark, .core = -1};
#if CONFIG_FREERTOS_VTASKLIST_INCLUDE_COREID
        if (raw[i].xCoreID != tskNO_AFFINITY) t->core = raw[i].xCoreID;
#endif
        /* Only compare opaque handles; task names inside the snapshot may
         * already have been freed. Known names are hints, ID is identity.
         * Unrecognised tasks (including duplicate names) retain name=null. */
        for (unsigned k = 0; k < sizeof(known) / sizeof(known[0]); k++)
            if (known[k] && raw[i].xHandle == known[k]) { t->name = s_names[k]; break; }
        for (unsigned j = 0; j < prev->count; j++) {
            if (t->id != prev->tasks[j].id) continue;
            t->valid = meshvpn_cpu_percent(prev->tasks[j].runtime_us,
                t->runtime_us, next->interval_us, &t->load_pct);
            break;
        }
        for (unsigned c = 0; c < CONFIG_FREERTOS_NUMBER_OF_CORES; c++) {
            if (raw[i].xHandle != idle[c]) continue;
            next->valid[c] = t->valid;
            next->load[c] = 100.0 - t->load_pct;
        }
    }
}

static void sampler(void *arg)
{
    (void)arg;
    /* Allocate once. No unbounded allocation or JSON work under kernel locks. */
    TaskStatus_t *raw = calloc(MAX_TASKS, sizeof(*raw));
    sample_t *next = calloc(1, sizeof(*next)), *prev = calloc(1, sizeof(*prev));
    if (!raw || !next || !prev) {
        free(raw); free(next); free(prev);
        ESP_LOGE("cpu_stats", "Not enough memory for telemetry");
        vTaskDelete(NULL);
        return;
    }
    TickType_t wake = xTaskGetTickCount();
    for (;;) {
        collect(raw, next, prev);
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        s_sample = *next;
        xSemaphoreGive(s_mutex);
        sample_t *swap = prev; prev = next; next = swap;
        vTaskDelayUntil(&wake, pdMS_TO_TICKS(2000));
    }
}
#endif

void meshvpn_cpu_start(void)
{
#if CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
    if (s_mutex) return;
    s_mutex = xSemaphoreCreateMutex();
    if (!s_mutex) return;
    if (xTaskCreate(sampler, "cpu_stats", 4096, NULL, 2, NULL) != pdPASS) {
        vSemaphoreDelete(s_mutex); s_mutex = NULL;
        ESP_LOGE("cpu_stats", "Cannot start sampler");
    }
#endif
}

void meshvpn_cpu_json(cJSON *root)
{
    cJSON *cpu = cJSON_AddObjectToObject(root, "cpu");
#if CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
    sample_t *copy = s_mutex ? malloc(sizeof(*copy)) : NULL;
    if (!copy) { cJSON_AddBoolToObject(cpu, "available", false); return; }
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    *copy = s_sample;
    xSemaphoreGive(s_mutex);
    uint64_t age = copy->sampled_us ? esp_timer_get_time() - copy->sampled_us : 0;
    bool available = copy->complete && age <= 10000000;
    cJSON_AddBoolToObject(cpu, "available", available);
    cJSON_AddNumberToObject(cpu, "sampled_us", copy->sampled_us);
    cJSON_AddNumberToObject(cpu, "sample_age_ms", age / 1000.0);
    cJSON_AddNumberToObject(cpu, "interval_ms", copy->interval_us / 1000.0);
    cJSON_AddNumberToObject(cpu, "collection_us", copy->collection_us);
    cJSON *cores = cJSON_AddArrayToObject(cpu, "cores");
    for (unsigned c = 0; c < CONFIG_FREERTOS_NUMBER_OF_CORES; c++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "id", c);
        if (available && copy->valid[c]) cJSON_AddNumberToObject(item, "load_pct", copy->load[c]);
        else cJSON_AddNullToObject(item, "load_pct");
        cJSON_AddItemToArray(cores, item);
    }
    cJSON *tasks = cJSON_AddArrayToObject(cpu, "tasks");
    for (unsigned i = 0; i < copy->count; i++) {
        const task_sample_t *t = &copy->tasks[i];
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "id", t->id);
        if (t->name) cJSON_AddStringToObject(item, "name", t->name);
        else cJSON_AddNullToObject(item, "name");
        cJSON_AddNumberToObject(item, "runtime_us", t->runtime_us);
        cJSON_AddNumberToObject(item, "priority", t->priority);
        cJSON_AddNumberToObject(item, "stack_free", t->stack_free);
        cJSON_AddNumberToObject(item, "core", t->core);
        if (available && t->valid) cJSON_AddNumberToObject(item, "load_pct", t->load_pct);
        else cJSON_AddNullToObject(item, "load_pct");
        cJSON_AddItemToArray(tasks, item);
    }
    free(copy);
#else
    cJSON_AddBoolToObject(cpu, "available", false);
#endif
}
