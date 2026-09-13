#include <assert.h>
#include <stdio.h>
#include "../components/meshvpn_usb/meshvpn_dwc2_diag.c"
static int64_t now;
int64_t esp_timer_get_time(void) { return now; }
int main(void) {
    meshvpn_dwc2_stats_t a, b;
    meshvpn_dwc2_get_stats(&a); assert(!a.available);
    meshvpn_dwc2_bind(0x84);
    meshvpn_dwc2_submit(0x82, 64, 0, 0, 0);
    meshvpn_dwc2_refill(0x82, 64); meshvpn_dwc2_txfe(0x82);
    assert(!s.submitted && !s.refill_calls && !s.txfe_irqs);
    const int delays[] = {100,101,1000,1001,5000,5001};
    for (unsigned i=0; i<sizeof(delays)/sizeof(delays[0]); i++) {
        now += 100;
        meshvpn_dwc2_submit(0x84, 1200, (32u<<16)|112u, 62, 0x80);
        meshvpn_dwc2_refill(0x84, 128); meshvpn_dwc2_txfe(0x84);
        meshvpn_dwc2_refill(0x84, 0);
        now += 6000; meshvpn_dwc2_complete(0x84, 1200);
        now += delays[i]; meshvpn_dwc2_task(0x84, 1200);
    }
    assert(s.service_timed==6 && s.service_us==36000 && s.service_max_us==6000);
    assert(s.task_timed==6 && s.task_us==12203 && s.task_max_us==5001);
    assert(s.task_le_100us==1 && s.task_100_1000us==2 && s.task_1_5ms==2 && s.task_gt_5ms==1);
    assert(s.refill_calls==12 && s.refill_empty==6 && s.refill_bytes==768 && s.txfe_irqs==6);
    assert(s.fifo_valid && (s.tx_fifo_reg>>16)*4==128 && s.rx_fifo_words==62);
    meshvpn_dwc2_submit(0x84, 0, 0, 0, 0);
    meshvpn_dwc2_complete(0x84, 0); meshvpn_dwc2_task(0x84, 0);
    assert(s.zlp_completions==1 && s.task_timed==6);
    meshvpn_dwc2_task(0x84, 1200); assert(s.unmatched==1);
    meshvpn_dwc2_submit(0x84, 1200, 0, 0, 0);
    meshvpn_dwc2_complete(0x84, 10); assert(s.unmatched==2);
    meshvpn_dwc2_submit(0x84, 1200, 0, 0, 0);
    meshvpn_dwc2_complete(0x84, 1200);
    meshvpn_dwc2_submit(0x84, 1200, 0, 0, 0); assert(s.overwritten==1);
    meshvpn_dwc2_reset();
    meshvpn_dwc2_task(0x84, 1200);
    assert(!s.fifo_valid && !s.endpoint && !pending && !active && s.task_timed==6);
    meshvpn_dwc2_bind(0x82);
    meshvpn_dwc2_submit(0x84, 1200, 0, 0, 0); assert(!active);
    meshvpn_dwc2_get_stats(&a); meshvpn_dwc2_get_stats(&b);
    assert(!memcmp(&a,&b,sizeof(a)));
    meshvpn_dwc2_get_stats(NULL);
    puts("DWC2 observer tests passed");
}
