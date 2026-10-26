#pragma once
#include "../../queue_stubs/freertos/queue.h"
BaseType_t xQueueSendToFront(QueueHandle_t, const void *, TickType_t);
