/* Exercise the real generated driver, replacing only USB core/hardware calls. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include MESHVPN_NCM_SOURCE

static bool endpoint_busy, submit_ok = true;
static unsigned submissions;
static uint16_t last_bytes;
static int64_t now_us;
int64_t esp_timer_get_time(void) { return now_us; }
bool usbd_edpt_busy(uint8_t rhport, uint8_t ep) { (void)rhport; (void)ep; return endpoint_busy; }
bool usbd_edpt_xfer(uint8_t rhport, uint8_t ep, uint8_t *buffer, uint16_t bytes, bool is_isr)
{
    (void)rhport; (void)buffer;
    assert(ep == 0x81 && !is_isr);
    submissions++;
    if (submit_ok) { endpoint_busy = true; last_bytes = bytes; }
    return submit_ok;
}
bool usbd_edpt_open(uint8_t rhport, const tusb_desc_endpoint_t *desc) { (void)rhport; (void)desc; return true; }
void usbd_edpt_close(uint8_t rhport, uint8_t ep) { (void)rhport; (void)ep; }
bool usbd_open_edpt_pair(uint8_t rhport, const uint8_t *desc, uint8_t count, uint8_t type, uint8_t *out, uint8_t *in)
{ (void)rhport; (void)desc; (void)count; (void)type; *out=0x02; *in=0x81; return true; }
tusb_speed_t tud_speed_get(void) { return TUSB_SPEED_FULL; }
bool tud_control_xfer(uint8_t rhport, const tusb_control_request_t *request, void *buffer, uint16_t len)
{ (void)rhport; (void)request; (void)buffer; (void)len; return true; }
bool tud_control_status(uint8_t rhport, const tusb_control_request_t *request)
{ (void)rhport; (void)request; return true; }
uint16_t tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t size) { memcpy(dst, ref, size); return size; }
bool tud_network_recv_cb(const uint8_t *src, uint16_t size) { (void)src; (void)size; return true; }
void tud_network_init_cb(void) {}

static void init(void)
{
    endpoint_busy=false; submit_ok=true;
    netd_reset(0);
    ncm_interface.ep_in=0x81;
    ncm_interface.ep_out=0x02;
    ncm_interface.ep_notif=0x83;
    ncm_interface.ep_size=64;
    ncm_interface.itf_data_alt=1;
}
static meshvpn_ncm_stats_t stats(void)
{
    meshvpn_ncm_stats_t s;
    ncm_interface_t before = ncm_interface;
    unsigned calls=submissions;
    meshvpn_ncm_get_stats(&s);
    assert(!memcmp(&before,&ncm_interface,sizeof(before)) && calls == submissions);
    return s;
}
static void complete(xfer_result_t result)
{
    uint16_t bytes=last_bytes;
    endpoint_busy=false;
    now_us+=2000;
    assert(netd_xfer_cb(0,0x81,result,bytes));
}
int main(void)
{
    init();
    assert(stats().available && stats().state.free == 6);
    uint8_t packet[1514]={0};
    unsigned frames=0;
    while(tud_network_can_xmit(sizeof(packet))) {
        assert(++frames < 100);
        tud_network_xmit(packet,sizeof(packet));
    }
    meshvpn_ncm_stats_t s=stats();
    assert(s.busy == 1 && s.busy_no_free == 1 && s.busy_active == 1);
    assert(s.state.free == 0 && s.state.ready == 5 && s.state.active && !s.state.glue);
    assert(s.free_min == 0 && s.ready_max == 5 && s.ntb_started == 1 && s.frames_started == 1);
    complete(XFER_RESULT_SUCCESS);
    s=stats();
    assert(s.ntb_completed == 1 && s.ntb_started == 2 && s.frames_started == 6);
    assert(s.completion_us == 2000 && s.backlog_gaps == 1);
    unsigned guard=0;
    while(endpoint_busy) { assert(++guard < 20); complete(XFER_RESULT_SUCCESS); }
    s=stats();
    assert(s.state.free == 6 && s.state.ready == 0 && !s.state.active);
    assert(s.frames_started == frames && s.ntb_started == s.ntb_completed);
    init();
    assert(tud_network_can_xmit(16));
    tud_network_xmit(packet,16); /* 48-byte NCM header + 16 payload => ZLP */
    assert(last_bytes == 64);
    uint32_t old_zlp=stats().zlp_completed;
    complete(XFER_RESULT_SUCCESS);
    assert(endpoint_busy && last_bytes == 0);
    uint32_t old_completed=stats().ntb_completed;
    complete(XFER_RESULT_SUCCESS);
    assert(stats().zlp_completed == old_zlp+1 && stats().ntb_completed == old_completed);
    init(); submit_ok=false;
    assert(tud_network_can_xmit(16));
    uint32_t started=stats().ntb_started;
    tud_network_xmit(packet,16);
    assert(stats().start_errors == 1 && stats().ntb_started == started);
    init();
    assert(tud_network_can_xmit(17));
    tud_network_xmit(packet,17);
    complete(XFER_RESULT_FAILED);
    assert(stats().completion_errors == 1);
    puts("Actual generated NCM: pool saturation/drain, aggregation, ZLP and xfer errors: OK");
}
