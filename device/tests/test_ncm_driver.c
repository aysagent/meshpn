/* Exercise the real generated driver, replacing only USB core/hardware calls. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include MESHVPN_NCM_SOURCE

static bool endpoint_busy, submit_ok = true;
static unsigned submissions, rx_submissions, rx_frames;
static uint16_t last_bytes;
static int64_t now_us;
#if CONFIG_MESHVPN_USB_TX_EVENT_WAIT
static unsigned capacity_notifications;
void meshvpn_usb_tx_capacity_available(void)
{
    /* Runs after old NTB was returned to the pool, not the pre-completion
     * telemetry hook. No producer has reclaimed this freed slot yet. */
    unsigned free_count=0;
    for (unsigned i=0;i<XMIT_NTB_N;i++) free_count += ncm_interface.xmit_free_ntb[i]!=NULL;
    assert(free_count > 0);
    capacity_notifications++;
}
#endif
int64_t esp_timer_get_time(void) { return now_us; }
bool usbd_edpt_busy(uint8_t rhport, uint8_t ep) { (void)rhport; (void)ep; return endpoint_busy; }
bool usbd_edpt_xfer(uint8_t rhport, uint8_t ep, uint8_t *buffer, uint16_t bytes, bool is_isr)
{
    (void)rhport; (void)buffer;
    if (ep == 0x02) { assert(!is_isr); rx_submissions++; return true; }
    assert(ep == 0x81 && !is_isr);
    submissions++;
    if (submit_ok) {
        endpoint_busy = true; last_bytes = bytes;
#if CONFIG_MESHVPN_DWC2_TELEMETRY
        meshvpn_dwc2_stats_t s;
        meshvpn_dwc2_get_stats(&s);
        assert(s.unmatched == 0 && s.overwritten == 0);
        meshvpn_dwc2_submit(ep, bytes, 32u<<16, 62, 1);
#endif
    }
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
bool tud_network_recv_cb(const uint8_t *src, uint16_t size) { (void)src; (void)size; rx_frames++; return true; }
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
#if CONFIG_MESHVPN_DWC2_TELEMETRY
    meshvpn_dwc2_reset();
    meshvpn_dwc2_bind(ncm_interface.ep_in);
#endif
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
#if CONFIG_MESHVPN_DWC2_TELEMETRY
    meshvpn_dwc2_complete(0x81,bytes);
#endif
#if CONFIG_MESHVPN_USB_TX_EVENT_WAIT
    unsigned notifications_before=capacity_notifications;
#endif
    assert(netd_xfer_cb(0,0x81,result,bytes));
#if CONFIG_MESHVPN_USB_TX_EVENT_WAIT
    assert(capacity_notifications==notifications_before+1);
#endif
}
/* Allocate only the received bytes: ASan then detects even reads that would
 * ordinarily remain inside the reusable NTB allocation as stale tail data. */
static bool validate_exact(const recv_ntb_t *source, size_t len)
{
    void *bytes=malloc(len ? len : 1);
    assert(bytes);
    memcpy(bytes,source,len);
    bool valid=recv_validate_datagram(bytes,(uint32_t)len);
    free(bytes);
    return valid;
}
static void test_rx_bounds(void)
{
    recv_ntb_t ntb={0};
    ntb.nth.dwSignature=NTH16_SIGNATURE;
    ntb.nth.wHeaderLength=sizeof(nth16_t);
    ntb.nth.wBlockLength=128;
    ntb.nth.wNdpIndex=sizeof(nth16_t);
    ndp16_t *ndp=(ndp16_t *)(ntb.data+ntb.nth.wNdpIndex);
    ndp->dwSignature=NDP16_SIGNATURE_NCM0;
    ndp->wLength=sizeof(ndp16_t)+3*sizeof(ndp16_datagram_t);
    ndp16_datagram_t *entry=(ndp16_datagram_t *)((uint8_t *)ndp+sizeof(*ndp));
    entry[0].wDatagramIndex=64; entry[0].wDatagramLength=32;
    entry[1].wDatagramIndex=96; entry[1].wDatagramLength=32;
    assert(validate_exact(&ntb,128));
    assert(validate_exact(&ntb,160)); /* USB padding after wBlockLength */
    for (unsigned n=0;n<128;n++) assert(!validate_exact(&ntb,n));
    recv_ntb_t good=ntb;
    entry[1].wDatagramLength=33;
    assert(!validate_exact(&ntb,160)); /* padding is not datagram data */
    ntb=good; ndp->wLength=65535;
    assert(!validate_exact(&ntb,128));
    ndp->wLength=120; /* table extends beyond block */
    assert(!validate_exact(&ntb,128));
    ndp->wLength=17; /* fractional entry */
    assert(!validate_exact(&ntb,128));
    ntb=good; ntb.nth.wNdpIndex=127;
    assert(!validate_exact(&ntb,128));
    ntb.nth.wNdpIndex=sizeof(nth16_t)-1;
    assert(!validate_exact(&ntb,128));
    ntb=good; ntb.nth.wBlockLength=0;
    assert(!validate_exact(&ntb,128));
    ntb=good; entry[2].wDatagramIndex=64;
    assert(!validate_exact(&ntb,128)); /* terminator required */
    ntb=good; ndp->wNextNdpIndex=64;
    assert(!validate_exact(&ntb,128)); /* unsupported chain */
    ntb=good; entry[1].wDatagramIndex=0; entry[1].wDatagramLength=0;
    ndp->wLength=sizeof(ndp16_t)+2*sizeof(ndp16_datagram_t);
    assert(validate_exact(&ntb,128)); /* ordinary single frame */
    entry[0].wDatagramIndex=0; entry[0].wDatagramLength=0;
    assert(!validate_exact(&ntb,128)); /* empty NTB must not pin glue buffer */
    entry[0].wDatagramIndex=64;
    assert(!validate_exact(&ntb,128)); /* half-empty first entry */
    assert(!recv_validate_datagram(NULL,0));
    assert(!recv_validate_datagram(&ntb,CFG_TUD_NCM_OUT_NTB_MAX_SIZE+1));

    /* Deterministic malformed-input sweep of lengths, offsets, and tables.
     * Safety is checked by ASan/UBSan, independently of accept/reject policy. */
    uint32_t random=0x4e434d;
    for (unsigned i=0;i<20000;i++) {
        ntb=good;
        random=random*1664525u+1013904223u;
        size_t len=random%257;
        for (unsigned j=0;j<6;j++) {
            random=random*1664525u+1013904223u;
            size_t offset=random%128;
            random=random*1664525u+1013904223u;
            ntb.data[offset]=(uint8_t)(random>>24);
        }
        (void)validate_exact(&ntb,len);
    }
    puts("NCM RX exact-buffer truncation/table bounds and 20000 malformed cases: OK");
}
static void test_rx_recovery(void)
{
    init();
    recv_try_to_start_new_reception(0);
    assert(ncm_interface.recv_tinyusb_ntb);
    unsigned delivered=rx_frames;
    uint32_t rejected=stats().rx_rejected;
    /* More bad/empty blocks than the entire RX pool, then valid traffic. */
    for (unsigned i=0;i<RECV_NTB_N*3;i++) {
        recv_ntb_t *ntb=ncm_interface.recv_tinyusb_ntb;
        assert(ntb);
        memset(ntb,0,sizeof(*ntb));
        ntb->nth.dwSignature=NTH16_SIGNATURE;
        ntb->nth.wHeaderLength=sizeof(nth16_t);
        ntb->nth.wBlockLength=128;
        ntb->nth.wNdpIndex=sizeof(nth16_t);
        ndp16_t *ndp=(ndp16_t *)(ntb->data+sizeof(nth16_t));
        ndp->dwSignature=NDP16_SIGNATURE_NCM0;
        ndp->wLength=sizeof(ndp16_t)+2*sizeof(ndp16_datagram_t);
        unsigned submits=rx_submissions;
        assert(netd_xfer_cb(0,0x02,XFER_RESULT_SUCCESS,128));
        assert(rx_frames==delivered && !ncm_interface.recv_glue_ntb);
        assert(rx_submissions==submits+1 && ncm_interface.recv_tinyusb_ntb);
    }
    assert(stats().rx_rejected-rejected==RECV_NTB_N*3);
    recv_ntb_t *ntb=ncm_interface.recv_tinyusb_ntb;
    ndp16_datagram_t *entry=(ndp16_datagram_t *)(ntb->data+sizeof(nth16_t)+sizeof(ndp16_t));
    entry[0].wDatagramIndex=64;entry[0].wDatagramLength=64;
    assert(netd_xfer_cb(0,0x02,XFER_RESULT_SUCCESS,128));
    assert(rx_frames==delivered+1 && !ncm_interface.recv_glue_ntb);
    /* Failed USB completion must not deliver stale data from an older NTB. */
    *ncm_interface.recv_tinyusb_ntb=*ntb;
    assert(netd_xfer_cb(0,0x02,XFER_RESULT_FAILED,128));
    assert(rx_frames==delivered+1);
    puts("NCM RX: empty/failed blocks recycle pool; following valid packet delivered: OK");
}
int main(void)
{
    test_rx_bounds();
    test_rx_recovery();
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
