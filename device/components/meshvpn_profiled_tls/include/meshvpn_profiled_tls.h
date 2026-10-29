#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Frozen chromium-156 capture #1. Cold connections only; not arbitrary profiles.
 * Input includes the four-byte TLS handshake header, but no record header.
 * Every new ClientHello (including HRR) must be checked afresh. */
typedef struct { bool match; char ja3[33]; char ja4[37]; } meshvpn_profile_check_t;
bool meshvpn_profiled_tls_check(const uint8_t *hello, size_t length, meshvpn_profile_check_t *out);
#ifdef ESP_PLATFORM
#include "esp_err.h"
/* Synchronous executor: fn must enforce bounded I/O/cancellation, must not save
 * pointers to the worker's stack. Returns only after worker and stack are freed.
 * PSRAM stack is mandatory. No fallback to the caller's 6 KiB stack. */
typedef esp_err_t (*meshvpn_profiled_tls_job_t)(void *arg);
esp_err_t meshvpn_profiled_tls_run(meshvpn_profiled_tls_job_t fn, void *arg,
                                  uint32_t *stack_spare_bytes);
#endif
#ifdef __cplusplus
}
#endif
