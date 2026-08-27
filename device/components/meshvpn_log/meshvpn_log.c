#include "meshvpn_log.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_core_dump.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "meshvpn_log";

#define MESHVPN_LOG_BUF_SIZE 12288
/* Kept small: this buffer lands on the stack of whichever task is logging. */
#define MESHVPN_LOG_LINE_MAX 160

static char s_buf[MESHVPN_LOG_BUF_SIZE];
static size_t s_head;
static bool s_wrapped;
static SemaphoreHandle_t s_lock;
static vprintf_like_t s_prev_vprintf;

static void meshvpn_log_append(const char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        s_buf[s_head++] = data[i];
        if (s_head == MESHVPN_LOG_BUF_SIZE) {
            s_head = 0;
            s_wrapped = true;
        }
    }
}

static int meshvpn_log_vprintf(const char *fmt, va_list args)
{
    char line[MESHVPN_LOG_LINE_MAX];

    va_list copy;
    va_copy(copy, args);
    int n = vsnprintf(line, sizeof(line), fmt, copy);
    va_end(copy);

    if (n > 0) {
        size_t len = (n < (int)sizeof(line)) ? (size_t)n : sizeof(line) - 1;
        /* Never block a logging call: dropping a line beats deadlocking. */
        if (xSemaphoreTake(s_lock, 0) == pdTRUE) {
            meshvpn_log_append(line, len);
            xSemaphoreGive(s_lock);
        }
    }

    return s_prev_vprintf ? s_prev_vprintf(fmt, args) : vprintf(fmt, args);
}

esp_err_t meshvpn_log_init(void)
{
    if (s_lock) {
        return ESP_OK;
    }
    s_lock = xSemaphoreCreateMutex();
    if (!s_lock) {
        return ESP_ERR_NO_MEM;
    }
    s_prev_vprintf = esp_log_set_vprintf(meshvpn_log_vprintf);
    return ESP_OK;
}

static const char *reset_reason_str(esp_reset_reason_t r)
{
    switch (r) {
    case ESP_RST_POWERON:  return "power-on";
    case ESP_RST_EXT:      return "external pin";
    case ESP_RST_SW:       return "software restart";
    case ESP_RST_PANIC:    return "PANIC";
    case ESP_RST_INT_WDT:  return "interrupt watchdog";
    case ESP_RST_TASK_WDT: return "task watchdog";
    case ESP_RST_WDT:      return "other watchdog";
    case ESP_RST_DEEPSLEEP: return "deep sleep wake";
    case ESP_RST_BROWNOUT: return "BROWNOUT (power supply)";
    case ESP_RST_SDIO:     return "sdio";
    default:               return "unknown";
    }
}

const char *meshvpn_log_reset_reason_str(void)
{
    return reset_reason_str(esp_reset_reason());
}

void meshvpn_log_report_boot(uint32_t boot_count)
{
    esp_reset_reason_t reason = esp_reset_reason();
    ESP_LOGW(TAG, "boot #%" PRIu32 ", last reset: %s", boot_count, reset_reason_str(reason));

#if CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH && CONFIG_ESP_COREDUMP_DATA_FORMAT_ELF
    if (esp_core_dump_image_check() != ESP_OK) {
        return;
    }

    esp_core_dump_summary_t *summary = malloc(sizeof(*summary));
    if (!summary) {
        return;
    }

    if (esp_core_dump_get_summary(summary) == ESP_OK) {
        ESP_LOGE(TAG, "last crash in task '%s' pc=0x%08" PRIx32 " cause=%" PRIu32 " vaddr=0x%08" PRIx32,
                 summary->exc_task, summary->exc_pc,
                 summary->ex_info.exc_cause, summary->ex_info.exc_vaddr);

        char bt[16 * 11 + 1];
        size_t pos = 0;
        for (uint32_t i = 0; i < summary->exc_bt_info.depth && pos < sizeof(bt) - 12; i++) {
            pos += snprintf(bt + pos, sizeof(bt) - pos, "0x%08" PRIx32 " ", summary->exc_bt_info.bt[i]);
        }
        bt[pos] = '\0';
        ESP_LOGE(TAG, "backtrace%s: %s", summary->exc_bt_info.corrupted ? " (corrupted)" : "", bt);
    }

    free(summary);
#endif
}

size_t meshvpn_log_copy(char *out, size_t out_len)
{
    if (!out || out_len == 0) {
        return 0;
    }
    if (!s_lock) {
        out[0] = '\0';
        return 0;
    }

    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(500)) != pdTRUE) {
        out[0] = '\0';
        return 0;
    }

    size_t total = s_wrapped ? MESHVPN_LOG_BUF_SIZE : s_head;
    size_t skip = 0;
    if (total > out_len - 1) {
        skip = total - (out_len - 1);
        total = out_len - 1;
    }

    size_t start = s_wrapped ? s_head : 0;
    start = (start + skip) % MESHVPN_LOG_BUF_SIZE;

    size_t first = MESHVPN_LOG_BUF_SIZE - start;
    if (first > total) {
        first = total;
    }
    memcpy(out, s_buf + start, first);
    if (total > first) {
        memcpy(out + first, s_buf, total - first);
    }
    out[total] = '\0';

    xSemaphoreGive(s_lock);
    return total;
}
