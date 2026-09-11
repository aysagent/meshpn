#pragma once
#include <stdint.h>
#include "esp_err.h"
esp_err_t tinyusb_net_send_sync(void *, uint16_t, void *, unsigned);
