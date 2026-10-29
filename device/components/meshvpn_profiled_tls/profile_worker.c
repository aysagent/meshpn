#include "meshvpn_profiled_tls.h"
#include "sdkconfig.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/idf_additions.h"
#if !CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM
#error "Profiled TLS requires explicitly enabled PSRAM task stacks"
#endif
_Static_assert(CONFIG_MESHVPN_PROFILED_TLS_STACK_BYTES >= 32768,
               "Profiled TLS ML-KEM must not run on the 6 KiB VPN RX stack");
typedef struct {
    meshvpn_profiled_tls_job_t fn;
    void *arg;
    SemaphoreHandle_t done;
    esp_err_t result;
    uint32_t spare;
} job_t;
static void run_job(void *arg)
{
    job_t *job = arg;
    job->result = job->fn(job->arg);
    job->spare = uxTaskGetStackHighWaterMark(NULL);
    /* No access to job after publication: caller may delete this task now. */
    xSemaphoreGive(job->done);
    vTaskSuspend(NULL);
}
esp_err_t meshvpn_profiled_tls_run(meshvpn_profiled_tls_job_t fn, void *arg,
                                  uint32_t *stack_spare_bytes)
{
    if (stack_spare_bytes) *stack_spare_bytes = 0;
    if (!fn) return ESP_ERR_INVALID_ARG;
    job_t job = {.fn=fn, .arg=arg, .result=ESP_FAIL};
    job.done = xSemaphoreCreateBinary();
    if (!job.done) return ESP_ERR_NO_MEM;
    TaskHandle_t task = NULL;
    if (xTaskCreateWithCaps(run_job, "tls_profile", CONFIG_MESHVPN_PROFILED_TLS_STACK_BYTES,
                           &job, 4, &task, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) {
        vSemaphoreDelete(job.done);
        return ESP_ERR_NO_MEM; /* Never run on caller/internal fallback. */
    }
    xSemaphoreTake(job.done, portMAX_DELAY);
    vTaskDeleteWithCaps(task);
    vSemaphoreDelete(job.done);
    if (stack_spare_bytes) *stack_spare_bytes = job.spare;
    return job.result;
}
