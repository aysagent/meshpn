#pragma once

#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Capture ESP_LOG output into a RAM ring buffer.
 *
 * The NCM firmware takes over the USB peripheral, so the USB-Serial-JTAG
 * console is unavailable at runtime. The buffer is served over the web UI
 * (GET /api/logs) so the device can be diagnosed without a UART adapter.
 */
esp_err_t meshvpn_log_init(void);

/**
 * Log why the previous run ended: reset reason, boot counter and — if the last
 * run panicked — the crashing task, PC and backtrace from the core dump.
 * Panic output bypasses ESP_LOG, so without this a crash leaves no trace.
 */
void meshvpn_log_report_boot(uint32_t boot_count);

/** Copy the buffered log (oldest first) into out. Returns bytes written. */
size_t meshvpn_log_copy(char *out, size_t out_len);

#ifdef __cplusplus
}
#endif
