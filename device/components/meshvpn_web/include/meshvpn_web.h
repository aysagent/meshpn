#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t meshvpn_web_start(void);
esp_err_t meshvpn_web_stop(void);

#ifdef __cplusplus
}
#endif
