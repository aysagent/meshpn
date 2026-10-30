#include <assert.h>
#include "../components/meshvpn_log/meshvpn_log.c"

static bool fail_sem, fail_task, valid_dump, in_worker, signalled;
static unsigned checks, summaries, tasks, deleted_tasks, deleted_sems;
void *heap_caps_malloc(size_t size, uint32_t caps) { (void)caps; return malloc(size); }
SemaphoreHandle_t xSemaphoreCreateMutex(void) { return (void *)1; }
SemaphoreHandle_t xSemaphoreCreateBinary(void) { return fail_sem ? NULL : (void *)2; }
int xSemaphoreTake(SemaphoreHandle_t sem, unsigned wait)
{ assert(sem == (void *)2 && wait == portMAX_DELAY && signalled && !in_worker); return 1; }
int xSemaphoreGive(SemaphoreHandle_t sem)
{ assert(sem == (void *)2 && in_worker); signalled = true; return 1; }
void vSemaphoreDelete(SemaphoreHandle_t sem) { assert(sem == (void *)2 && !in_worker); deleted_sems++; }
int xTaskCreateWithCaps(void (*fn)(void *), const char *name, unsigned stack, void *arg,
                        unsigned prio, TaskHandle_t *task, unsigned caps)
{
    assert(caps == (MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA | MALLOC_CAP_8BIT));
    assert(stack >= 6144 && prio > 0 && name && !in_worker);
    if (fail_task) return 0;
    tasks++; *task = (void *)3;
    in_worker = true; fn(arg); in_worker = false;
    return pdPASS;
}
void vTaskSuspend(TaskHandle_t task) { assert(!task && signalled && in_worker); }
void vTaskDeleteWithCaps(TaskHandle_t task) { assert(task == (void *)3 && !in_worker); deleted_tasks++; }
vprintf_like_t esp_log_set_vprintf(vprintf_like_t fn) { (void)fn; return NULL; }
esp_reset_reason_t esp_reset_reason(void) { return ESP_RST_PANIC; }
esp_err_t esp_core_dump_image_check(void)
{ assert(in_worker); checks++; return valid_dump ? ESP_OK : -1; }
esp_err_t esp_core_dump_get_summary(esp_core_dump_summary_t *summary)
{ assert(in_worker); summaries++; memset(summary, 0, sizeof(*summary)); return ESP_OK; }
int main(void)
{
    fail_sem = true; meshvpn_log_report_boot(1);
    assert(!tasks && !checks && !deleted_sems);
    fail_sem = false; fail_task = true; meshvpn_log_report_boot(2);
    assert(!tasks && !checks && deleted_sems == 1);
    fail_task = false; meshvpn_log_report_boot(3);
    assert(tasks == 1 && checks == 1 && !summaries && deleted_tasks == 1 && deleted_sems == 2);
    signalled = false; valid_dump = true; meshvpn_log_report_boot(4);
    assert(tasks == 2 && checks == 2 && summaries == 1 && deleted_tasks == 2 && deleted_sems == 3);
    puts("P4 crash reader: DRAM worker, empty/valid dump, join and fail-closed allocation paths passed");
}
