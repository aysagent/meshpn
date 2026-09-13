#pragma once
#include <stdbool.h>
#include <stdint.h>
typedef struct { uint16_t bm_double_buffered; bool vbus_sensing; } tud_configure_dwc2_t;
typedef union { tud_configure_dwc2_t dwc2; } tud_configure_param_t;
#define CFG_TUD_CONFIGURE_DWC2_DEFAULT {.bm_double_buffered=0, .vbus_sensing=true}
#define TUD_CFGID_DWC2 100
bool tud_inited(void);
bool tud_configure(uint8_t rhport, uint32_t id, const void *cfg);
bool tud_ready(void);
bool tud_network_can_xmit(unsigned size);
