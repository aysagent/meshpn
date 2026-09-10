#pragma once
#include <stdint.h>
#include <stddef.h>
typedef uint64_t configRUN_TIME_COUNTER_TYPE;
typedef unsigned TickType_t;
typedef unsigned UBaseType_t;
typedef void *TaskHandle_t;
typedef void *SemaphoreHandle_t;
typedef struct {
    TaskHandle_t xHandle;
    const char *pcTaskName;
    unsigned xTaskNumber, uxCurrentPriority, usStackHighWaterMark;
    int xCoreID;
    uint64_t ulRunTimeCounter;
} TaskStatus_t;
#define tskNO_AFFINITY 0x7fffffff
#define pdPASS 1
#define portMAX_DELAY 0xffffffffu
#define pdMS_TO_TICKS(ms) (ms)
TaskHandle_t xTaskGetHandle(const char *name);
TaskHandle_t xTaskGetIdleTaskHandleForCore(unsigned core);
unsigned uxTaskGetSystemState(TaskStatus_t *out, unsigned capacity, uint64_t *total);
unsigned xTaskGetTickCount(void);
void vTaskDelayUntil(TickType_t *wake, TickType_t ticks);
void vTaskDelete(TaskHandle_t task);
int xTaskCreate(void (*fn)(void *), const char *name, unsigned stack, void *arg, unsigned prio, TaskHandle_t *handle);
SemaphoreHandle_t xSemaphoreCreateMutex(void);
int xSemaphoreTake(SemaphoreHandle_t mutex, unsigned wait);
int xSemaphoreGive(SemaphoreHandle_t mutex);
void vSemaphoreDelete(SemaphoreHandle_t mutex);
