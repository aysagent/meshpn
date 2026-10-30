#pragma once
#include "freertos/FreeRTOS.h"
SemaphoreHandle_t xSemaphoreCreateBinary(void);
int xTaskCreateWithCaps(void (*fn)(void *), const char *name, unsigned stack, void *arg, unsigned prio, TaskHandle_t *task, unsigned caps);
void vTaskDeleteWithCaps(TaskHandle_t task);
void vTaskSuspend(TaskHandle_t task);
