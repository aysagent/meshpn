#pragma once
#include "esp_err.h"
#include <stdint.h>
typedef struct { char exc_task[32]; uint32_t exc_pc; } esp_core_dump_summary_t;
esp_err_t esp_core_dump_image_check(void);
esp_err_t esp_core_dump_get_summary(esp_core_dump_summary_t *summary);
