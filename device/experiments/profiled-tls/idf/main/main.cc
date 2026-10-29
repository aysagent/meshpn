#include "bootloader_random.h"
#include <stdio.h>
extern int bssl_capture(const char *file, bool configured);
extern "C" void app_main() {
    // This image has no networking, credentials, USB stack or product services.
    bootloader_random_enable();
    int result=bssl_capture(nullptr,true);
    bootloader_random_disable();
    printf("BSSL_PROBE_CAPTURE_RESULT=%d\n",result);
}
