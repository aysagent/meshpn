#pragma once
#include <stdarg.h>
typedef int (*vprintf_like_t)(const char *, va_list);
vprintf_like_t esp_log_set_vprintf(vprintf_like_t fn);
static inline void test_log_warning(const char *tag, const char *fmt, ...)
{ (void)tag; (void)fmt; }
#define ESP_LOGW(...) test_log_warning(__VA_ARGS__)
