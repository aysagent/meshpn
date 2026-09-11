#include "meshvpn_ncm_diag.h"
#include <string.h>
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static meshvpn_ncm_stats_t s_diag;
static bool s_active_timed, s_backlog_timed;
static uint64_t s_started_us, s_backlog_us;

void meshvpn_ncm_record(meshvpn_ncm_event_t event, const meshvpn_ncm_state_t *state,
                        uint32_t bytes, uint16_t frames)
{
    uint64_t now = (uint64_t)esp_timer_get_time();
    portENTER_CRITICAL(&s_lock);
    if (!s_diag.available || state->free < s_diag.free_min) s_diag.free_min = state->free;
    if (state->ready > s_diag.ready_max) s_diag.ready_max = state->ready;
    s_diag.available = true;
    s_diag.sampled_us = now;
    s_diag.samples++;
    s_diag.state = *state;
    switch (event) {
    case MESH_NCM_INIT:
        s_diag.initializations++;
        s_active_timed = s_backlog_timed = false;
        break;
    case MESH_NCM_BUSY:
        s_diag.busy++;
        if (!state->free) s_diag.busy_no_free++;
        if (state->active) s_diag.busy_active++;
        break;
    case MESH_NCM_START:
        s_diag.ntb_started++;
        s_diag.bytes_started += bytes;
        s_diag.frames_started += frames;
        s_active_timed = true;
        s_started_us = now;
        if (s_backlog_timed) {
            uint64_t gap = now - s_backlog_us;
            s_diag.backlog_gaps++;
            s_diag.backlog_gap_us += gap;
            if (gap > s_diag.backlog_gap_max_us) s_diag.backlog_gap_max_us = gap;
            s_backlog_timed = false;
        }
        break;
    case MESH_NCM_START_ERROR:
        s_diag.start_errors++;
        break;
    case MESH_NCM_COMPLETE:
    case MESH_NCM_COMPLETE_ERROR:
        if (event == MESH_NCM_COMPLETE) {
            s_diag.ntb_completed++;
            s_diag.bytes_completed += bytes;
        } else {
            s_diag.completion_errors++;
        }
        if (s_active_timed) {
            uint64_t elapsed = now - s_started_us;
            s_diag.completion_timed++;
            s_diag.completion_us += elapsed;
            if (elapsed > s_diag.completion_max_us) s_diag.completion_max_us = elapsed;
            if (elapsed <= 1000) s_diag.completion_le_1ms++;
            else if (elapsed <= 5000) s_diag.completion_1_5ms++;
            else if (elapsed <= 25000) s_diag.completion_5_25ms++;
            else s_diag.completion_gt_25ms++;
        }
        s_active_timed = false;
        s_backlog_timed = state->ready || (state->glue && state->glue_frames);
        s_backlog_us = now;
        break;
    case MESH_NCM_ZLP:
        s_diag.zlp_completed++;
        break;
    case MESH_NCM_ZLP_ERROR:
        s_diag.zlp_errors++;
        break;
    case MESH_NCM_SAMPLE:
        break;
    }
    portEXIT_CRITICAL(&s_lock);
}

void meshvpn_ncm_get_stats(meshvpn_ncm_stats_t *out)
{
    if (!out) return;
    portENTER_CRITICAL(&s_lock);
    memcpy(out, &s_diag, sizeof(*out));
    portEXIT_CRITICAL(&s_lock);
}
