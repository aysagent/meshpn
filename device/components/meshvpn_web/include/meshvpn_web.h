#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Once at app_main entry, before any task can create a cJSON object. */
void meshvpn_web_init_allocators(void);
esp_err_t meshvpn_web_start(void);
esp_err_t meshvpn_web_stop(void);
bool meshvpn_web_https_enabled(void);
#if CONFIG_MESHVPN_USB_DIAGNOSTICS
size_t meshvpn_web_diag_snapshot(char *out, size_t capacity);
#endif

#ifdef __cplusplus
}
#endif
