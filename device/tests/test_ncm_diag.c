#include <assert.h>
#include <stdio.h>
#include "../components/meshvpn_usb/meshvpn_ncm_diag.c"
static int64_t now_us;
int64_t esp_timer_get_time(void) { return now_us; }
static meshvpn_ncm_state_t state = {.pool=6, .free=6, .max_ntb=8192, .max_datagrams=6};
static meshvpn_ncm_stats_t snap(void)
{
    meshvpn_ncm_stats_t a, b;
    meshvpn_ncm_get_stats(&a);
    for (unsigned i = 0; i < 100; i++) meshvpn_ncm_get_stats(&b);
    assert(!memcmp(&a, &b, sizeof(a)));
    assert(a.completion_timed == a.completion_le_1ms + a.completion_1_5ms + a.completion_5_25ms + a.completion_gt_25ms);
    return a;
}
int main(void)
{
    assert(!snap().available);
    meshvpn_ncm_get_stats(NULL);
    meshvpn_ncm_record(MESH_NCM_INIT, &state, 0, 0);
    assert(snap().free_min == 6 && snap().initializations == 1);
    state.free=0; state.ready=4; state.glue=true; state.glue_frames=2; state.active=true;
    meshvpn_ncm_record(MESH_NCM_BUSY, &state, 0, 0);
    assert(snap().busy_no_free == 1 && snap().busy_active == 1 && snap().ready_max == 4 && snap().free_min == 0);
    now_us=100;
    meshvpn_ncm_record(MESH_NCM_START, &state, 4096, 3);
    now_us=2100;
    meshvpn_ncm_record(MESH_NCM_COMPLETE, &state, 4096, 0);
    assert(snap().completion_us == 2000 && snap().completion_1_5ms == 1);
    state.active=false;
    now_us=2500;
    meshvpn_ncm_record(MESH_NCM_ZLP, &state, 0, 0);
    assert(snap().completion_timed == 1 && snap().zlp_completed == 1);
    now_us=3100;
    meshvpn_ncm_record(MESH_NCM_START, &state, 2048, 1);
    assert(snap().backlog_gaps == 1 && snap().backlog_gap_us == 1000);
    assert(snap().ntb_started == 2 && snap().frames_started == 4 && snap().bytes_started == 6144);
    now_us=4100; state.ready=0; state.glue=false;
    meshvpn_ncm_record(MESH_NCM_COMPLETE_ERROR, &state, 123, 0);
    assert(snap().completion_errors == 1 && snap().bytes_completed == 4096 && snap().completion_le_1ms == 1);
    now_us=5000;
    meshvpn_ncm_record(MESH_NCM_START_ERROR, &state, 1024, 1);
    assert(snap().start_errors == 1 && snap().ntb_started == 2);
    meshvpn_ncm_record(MESH_NCM_ZLP_ERROR, &state, 0, 0);
    assert(snap().zlp_errors == 1);
    now_us=6000;
    meshvpn_ncm_record(MESH_NCM_START, &state, 1024, 1);
    assert(snap().backlog_gaps == 1); /* no queued data at last completion */
    meshvpn_ncm_record(MESH_NCM_INIT, &state, 0, 0);
    now_us=9000;
    meshvpn_ncm_record(MESH_NCM_COMPLETE, &state, 1024, 0);
    assert(snap().completion_timed == 2); /* reset invalidated active timestamp */
    assert(snap().initializations == 2 && snap().free_min == 0);
    const int64_t durations[] = {1000,1001,5000,5001,25000,25001};
    for (unsigned i=0; i<sizeof(durations)/sizeof(durations[0]); i++) {
        meshvpn_ncm_record(MESH_NCM_START, &state, 64, 1);
        now_us+=durations[i];
        meshvpn_ncm_record(MESH_NCM_COMPLETE, &state, 64, 0);
    }
    meshvpn_ncm_stats_t s=snap();
    assert(s.completion_timed == 8 && s.completion_le_1ms == 2 && s.completion_1_5ms == 3 && s.completion_5_25ms == 2 && s.completion_gt_25ms == 1);
    assert(s.completion_max_us == 25001 && s.sampled_us == (uint64_t)now_us);
    puts("NCM snapshot, busy, NTB/ZLP, timing, error and reset accounting: OK");
}
