#include "meshvpn_dwc2_diag.h"
#include <string.h>
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"

/* ESP32-S3 ISR variants are valid in task context too (unlike the compliance
 * checked task variants in ISR). Lock order: DCD -> observer, never reverse.
 * No allocation, logging, USB calls or notifications under this lock. */
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static meshvpn_dwc2_stats_t s;
static bool active, pending;
static uint32_t active_bytes, pending_bytes;
static uint64_t started, completed;
#define ENTER() portENTER_CRITICAL_ISR(&s_lock)
#define LEAVE() portEXIT_CRITICAL_ISR(&s_lock)
static bool selected(uint8_t ep) { return s.endpoint != 0 && ep == s.endpoint; }

void meshvpn_dwc2_bind(uint8_t ep) {
    ENTER();
    s.available = true;
    s.endpoint = (ep > 0x80 && ep < 0x87) ? ep : 0;
    s.fifo_valid = false;
    active = pending = false;
    LEAVE();
}
void meshvpn_dwc2_reset(void) {
    ENTER();
    s.resets++;
    s.endpoint = 0;
    s.fifo_valid = false;
    active = pending = false;
    LEAVE();
}
void meshvpn_dwc2_submit(uint8_t ep, uint32_t bytes, uint32_t fifo, uint32_t rx, uint32_t ahb) {
    ENTER();
    if (selected(ep)) {
        if (active || pending) s.overwritten++;
        started = (uint64_t)esp_timer_get_time();
        active = true; pending = false; active_bytes = bytes;
        s.submitted++;
        s.fifo_valid = true; s.tx_fifo_reg = fifo; s.rx_fifo_words = rx; s.gahbcfg = ahb;
        s.sampled_us = started;
    }
    LEAVE();
}
void meshvpn_dwc2_refill(uint8_t ep, uint16_t bytes) {
    ENTER();
    if (selected(ep)) { s.refill_calls++; s.refill_bytes += bytes; if (!bytes) s.refill_empty++; }
    LEAVE();
}
void meshvpn_dwc2_txfe(uint8_t ep) {
    ENTER(); if (selected(ep)) s.txfe_irqs++; LEAVE();
}
void meshvpn_dwc2_complete(uint8_t ep, uint32_t bytes) {
    const uint64_t now = (uint64_t)esp_timer_get_time();
    ENTER();
    if (selected(ep)) {
        s.isr_completions++;
        if (!bytes) s.zlp_completions++;
        if (pending) s.overwritten++;
        if (active && active_bytes == bytes) {
            if (bytes) {
                uint64_t elapsed = now - started;
                s.service_timed++; s.service_us += elapsed;
                if (elapsed > s.service_max_us) s.service_max_us = elapsed;
            }
            pending = true; pending_bytes = bytes; completed = now;
        } else { s.unmatched++; pending = false; }
        active = false;
    }
    LEAVE();
}
void meshvpn_dwc2_task(uint8_t ep, uint32_t bytes) {
    const uint64_t now = (uint64_t)esp_timer_get_time();
    ENTER();
    if (selected(ep)) {
        if (pending && bytes == pending_bytes) {
            if (bytes) {
                uint64_t elapsed = now - completed;
                s.task_timed++; s.task_us += elapsed;
                if (elapsed > s.task_max_us) s.task_max_us = elapsed;
                if (elapsed <= 100) s.task_le_100us++;
                else if (elapsed <= 1000) s.task_100_1000us++;
                else if (elapsed <= 5000) s.task_1_5ms++;
                else s.task_gt_5ms++;
            }
        } else s.unmatched++;
        pending = false;
    }
    LEAVE();
}
void meshvpn_dwc2_get_stats(meshvpn_dwc2_stats_t *out) {
    if (!out) return;
    ENTER(); memcpy(out, &s, sizeof(s)); LEAVE();
}
