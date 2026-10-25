#pragma once
#include <stdint.h>
#include "esp_err.h"
typedef struct {uint32_t major1,minor1,patch1;} esp_hosted_coprocessor_fwver_t;
esp_err_t esp_hosted_get_coprocessor_fwversion(esp_hosted_coprocessor_fwver_t *);
