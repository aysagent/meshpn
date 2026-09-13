#pragma once
#include <stdbool.h>
#include <stdint.h>

#define MESHVPN_DWC2_COUNTERS(X) \
    X(submitted) X(resets) X(refill_calls) X(refill_empty) X(refill_bytes) X(txfe_irqs) \
    X(isr_completions) X(zlp_completions) X(service_timed) X(task_timed) \
    X(task_le_100us) X(task_100_1000us) X(task_1_5ms) X(task_gt_5ms) \
    X(unmatched) X(overwritten)
typedef struct {
    bool available, fifo_valid;
    uint8_t endpoint;
    uint32_t tx_fifo_reg, rx_fifo_words, gahbcfg;
    uint64_t sampled_us, service_us, service_max_us, task_us, task_max_us;
#define MESH_DWC_FIELD(n) uint32_t n;
    MESHVPN_DWC2_COUNTERS(MESH_DWC_FIELD)
#undef MESH_DWC_FIELD
} meshvpn_dwc2_stats_t;

/* Hooks only observe the selected NCM IN endpoint. Registers are captured by
 * the DCD while it owns the controller, never by a web/API task. */
void meshvpn_dwc2_bind(uint8_t ep);
void meshvpn_dwc2_reset(void);
void meshvpn_dwc2_submit(uint8_t ep, uint32_t bytes, uint32_t fifo, uint32_t rx, uint32_t ahb);
void meshvpn_dwc2_refill(uint8_t ep, uint16_t bytes);
void meshvpn_dwc2_txfe(uint8_t ep);
void meshvpn_dwc2_complete(uint8_t ep, uint32_t bytes);
void meshvpn_dwc2_task(uint8_t ep, uint32_t bytes);
void meshvpn_dwc2_get_stats(meshvpn_dwc2_stats_t *out);
