#pragma once
#include "FreeRTOS.h"
BaseType_t xTaskCreate(void (*fn)(void *), const char *, unsigned, void *, unsigned, TaskHandle_t *);
BaseType_t xTaskNotifyGive(TaskHandle_t);
uint32_t ulTaskNotifyTake(BaseType_t, TickType_t);
unsigned uxTaskGetStackHighWaterMark(TaskHandle_t);
