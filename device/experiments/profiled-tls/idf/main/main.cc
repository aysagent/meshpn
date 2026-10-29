#include "bootloader_random.h"
#include "meshvpn_profiled_tls.h"
#include <stdio.h>
extern int bssl_capture(const char *file, bool configured);
static esp_err_t capture(void*) { return bssl_capture(nullptr,true)==0?ESP_OK:ESP_FAIL; }
extern "C" void app_main() {
    // Standalone image: no radio/ADC consumer is active during this interval.
    bootloader_random_enable();
    uint32_t spare=0;
    esp_err_t result=meshvpn_profiled_tls_run(capture,nullptr,&spare);
    bootloader_random_disable();
    printf("PROFILE_JOB_RESULT=%d stack_spare=%lu\n",result,(unsigned long)spare);
}
