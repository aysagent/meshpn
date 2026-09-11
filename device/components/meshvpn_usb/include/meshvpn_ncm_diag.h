#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Called only from the instrumented NCM driver in TinyUSB task context.
 * No pointers to driver buffers escape into the diagnostic snapshot. */
typedef enum {
    MESH_NCM_SAMPLE, MESH_NCM_INIT, MESH_NCM_BUSY,
    MESH_NCM_START, MESH_NCM_START_ERROR,
    MESH_NCM_COMPLETE, MESH_NCM_COMPLETE_ERROR,
    MESH_NCM_ZLP, MESH_NCM_ZLP_ERROR,
} meshvpn_ncm_event_t;

typedef struct {
    uint16_t pool, free, ready, glue_frames, max_ntb, max_datagrams;
    bool glue, active;
} meshvpn_ncm_state_t;

/* Shared list keeps C JSON serialization consistent with storage. */
#define MESHVPN_NCM_COUNTERS(X) \
    X(samples) X(initializations) X(busy) X(busy_no_free) X(busy_active) \
    X(ntb_started) X(start_errors) X(bytes_started) X(frames_started) \
    X(ntb_completed) X(completion_errors) X(bytes_completed) X(zlp_completed) X(zlp_errors) \
    X(completion_timed) X(completion_le_1ms) X(completion_1_5ms) \
    X(completion_5_25ms) X(completion_gt_25ms) X(backlog_gaps)
typedef struct {
    bool available;
    meshvpn_ncm_state_t state;
    uint16_t free_min, ready_max;
    uint64_t sampled_us, completion_us, completion_max_us, backlog_gap_us, backlog_gap_max_us;
#define MESH_NCM_FIELD(name) uint32_t name;
    MESHVPN_NCM_COUNTERS(MESH_NCM_FIELD)
#undef MESH_NCM_FIELD
} meshvpn_ncm_stats_t;

void meshvpn_ncm_record(meshvpn_ncm_event_t event, const meshvpn_ncm_state_t *state,
                        uint32_t bytes, uint16_t frames);
void meshvpn_ncm_get_stats(meshvpn_ncm_stats_t *out);
