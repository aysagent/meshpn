#pragma once

#include "esp_err.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t meshvpn_web_start(void);
esp_err_t meshvpn_web_stop(void);
bool meshvpn_web_https_enabled(void);

#ifdef __cplusplus
}
#endif
