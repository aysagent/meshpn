#include "meshvpn_ap_probe.h"
#include "meshvpn_ap_echo.h"
#include <string.h>
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "meshvpn_vpn.h"
#include "meshvpn_vpn_frame.h"
#include "lwip/etharp.h"
#include "lwip/ip4.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

static struct netif *s_ap, *s_sta;
static netif_output_fn s_output;
static struct {
    bool active, received, checksums_ok;
    uint8_t proto, flags, rcode, reply[512];
    uint32_t client, seq, peer_seq;
    uint16_t port, id;
    SemaphoreHandle_t done;
    uint64_t started_us, elapsed_us;
} s_probe;
static meshvpn_ap_flow_t s_flows[8];
static uint64_t s_seen[8];
static unsigned s_next;
static portMUX_TYPE s_flow_lock = portMUX_INITIALIZER_UNLOCKED;
static meshvpn_rx_checksum_t s_checksums[4];
static meshvpn_sta_tcp_trace_t s_tcp, s_ap_tcp;
static uint64_t s_tcp_started, s_ap_tcp_started;
static uint32_t s_tcp_target, s_tcp_generation;
static uint64_t s_tcp_until;
static uint16_t s_tcp_remote_port, s_tcp_local_port;
static esp_err_t tcp_client_arm(void *arg)
{
    uint32_t peer = *(uint32_t *)arg;
    if (peer) {
        const uint8_t *b = (const uint8_t *)&peer;
        bool private = b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
            (b[0] == 192 && b[1] == 168);
        if (!s_sta || !netif_is_up(s_sta) || !netif_is_link_up(s_sta) ||
            meshvpn_vpn_is_enabled() || !private || peer == netif_ip4_addr(s_sta)->addr ||
            !netif_ip4_netmask(s_sta)->addr ||
            ((peer ^ netif_ip4_addr(s_sta)->addr) & netif_ip4_netmask(s_sta)->addr) ||
            !(peer & ~netif_ip4_netmask(s_sta)->addr) ||
            (peer | netif_ip4_netmask(s_sta)->addr) == UINT32_MAX)
            return ESP_ERR_INVALID_STATE;
    }
    uint64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_flow_lock);
    s_tcp_target = peer; s_tcp_until = peer ? now + 120000000 : 0; s_tcp_generation++;
    s_tcp_remote_port = peer ? 80 : 0; s_tcp_local_port = 0;
    memset(&s_tcp, 0, sizeof(s_tcp)); s_tcp_started = 0;
    s_tcp.client = peer != 0;
    portEXIT_CRITICAL(&s_flow_lock);
    return ESP_OK;
}
esp_err_t meshvpn_ap_probe_tcp_client(uint32_t peer)
{ return esp_netif_tcpip_exec(tcp_client_arm, &peer); }
static esp_err_t tcp_vpn_arm(void *arg)
{
    (void)arg; uint32_t peer; uint16_t remote, local;
    if (!s_sta || !netif_is_up(s_sta) || !netif_is_link_up(s_sta) ||
        !meshvpn_vpn_tcp_peer(&peer, &remote, &local)) return ESP_ERR_INVALID_STATE;
    uint64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_flow_lock);
    s_tcp_target=peer; s_tcp_remote_port=remote; s_tcp_local_port=local;
    s_tcp_until=now+30000000; s_tcp_generation++; s_tcp_started=now;
    memset(&s_tcp,0,sizeof(s_tcp)); s_tcp.client=true; s_tcp.vpn=true;
    s_tcp.peer=peer; s_tcp.local=netif_ip4_addr(s_sta)->addr;
    s_tcp.peer_port=remote; s_tcp.local_port=local;
    portEXIT_CRITICAL(&s_flow_lock);
    return ESP_OK;
}
esp_err_t meshvpn_ap_probe_tcp_vpn(void)
{ return esp_netif_tcpip_exec(tcp_vpn_arm, NULL); }
static err_t output(struct netif *, struct pbuf *, const ip4_addr_t *);
/* Default Wi-Fi netifs acquire output during start, after LAN registration. */
static void attach_output(void)
{
    if (s_ap && s_ap->output && s_ap->output != output) {
        s_output = s_ap->output; s_ap->output = output;
    }
}

static uint16_t r16(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }
static uint32_t r32(const uint8_t *p) { return ((uint32_t)r16(p) << 16) | r16(p + 2); }
static void w16(uint8_t *p, uint16_t n) { p[0] = n >> 8; p[1] = n; }
static void w32(uint8_t *p, uint32_t n) { w16(p, n >> 16); w16(p + 2, n); }
/* Local HTTP diagnostic flows only. Retain header metadata, never body bytes,
 * HTTP headers or credentials. Explicitly armed STA client mode also observes
 * forwarded HTTP to one private on-link peer for at most 120 s. RX precedes lwIP;
 * TX means accepted by host SDIO, not confirmed RF delivery. */
static void wifi_tcp(bool ap, bool tx, const uint8_t *h, size_t n, size_t wire_len)
{
    struct netif *local_netif=ap?s_ap:s_sta;
    meshvpn_sta_tcp_trace_t *trace=ap?&s_ap_tcp:&s_tcp;
    uint64_t *started=ap?&s_ap_tcp_started:&s_tcp_started;
    uint32_t target = 0, generation = 0; uint64_t until = 0;
    uint16_t remote_filter=0, local_filter=0;
    if (!ap) {
        portENTER_CRITICAL(&s_flow_lock);
        target=s_tcp_target; generation=s_tcp_generation; until=s_tcp_until;
        remote_filter=s_tcp_remote_port; local_filter=s_tcp_local_port;
        portEXIT_CRITICAL(&s_flow_lock);
        if (target && (uint64_t)esp_timer_get_time() >= until) return;
    }
    if (!local_netif || n < 40 || h[0] >> 4 != 4 || h[9] != 6 || (h[6] & 0x3f) || h[7]) return;
    unsigned ihl = (h[0] & 15) * 4, total = r16(h + 2);
    if (ihl < 20 || n < ihl + 20 || total < ihl + 20 || total > wire_len) return;
    const uint8_t *t = h + ihl; unsigned thl = (t[12] >> 4) * 4;
    if (thl < 20 || n < ihl + thl || total < ihl + thl) return;
    uint32_t local, peer;
    memcpy(&local, h + (tx ? 12 : 16), 4); memcpy(&peer, h + (tx ? 16 : 12), 4);
    uint16_t local_port=r16(t+(tx?0:2)), port=r16(t+(tx?2:0));
    if (local != netif_ip4_addr(local_netif)->addr ||
        (target ? peer != target || port != remote_filter || (local_filter && local_port != local_filter) : local_port != 80)) return;
    meshvpn_sta_tcp_event_t e = {.seq=r32(t+4), .ack=r32(t+8), .flags=t[13],
        .window=r16(t+14), .payload=total-ihl-thl, .tx=tx};
    if (total <= n) {
        struct pbuf l4 = {.payload=(uint8_t *)t, .len=total-ihl, .tot_len=total-ihl};
        ip4_addr_t src, dst; memcpy(&src.addr,h+12,4); memcpy(&dst.addr,h+16,4);
        e.checksum_checked=1; e.bad_ip=inet_chksum(h,ihl)!=0;
        e.bad_tcp=inet_chksum_pseudo(&l4,6,total-ihl,&src,&dst)!=0;
    }
    for (unsigned off = 20; off < thl;) {
        unsigned kind = t[off];
        if (!kind) break;
        if (kind == 1) { off++; continue; }
        if (off + 1 >= thl || t[off+1] < 2 || off + t[off+1] > thl) return;
        unsigned size = t[off+1];
        if (kind == 5) {
            if (size < 10 || (size-2) % 8) return;
            e.sack_blocks = (size-2)/8; e.sack_left = r32(t+off+2); e.sack_right = r32(t+off+6);
        }
        off += size;
    }
    uint64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_flow_lock);
    if (!ap && (generation != s_tcp_generation || (target && now >= s_tcp_until))) {
        portEXIT_CRITICAL(&s_flow_lock); return;
    }
    if (!local_filter && tx == (target != 0) && (e.flags & 0x12) == 2 && (!trace->total_events || trace->peer != peer ||
        trace->local != local || trace->peer_port != port || trace->local_port != local_port || trace->initial_seq != e.seq)) {
        memset(trace, 0, sizeof(*trace)); (*started) = now;
        trace->peer=peer; trace->local=local; trace->peer_port=port; trace->initial_seq=e.seq;
        trace->local_port=local_port; trace->client=target!=0;
    }
    if ((*started) && trace->peer == peer && trace->local == local && trace->peer_port == port && trace->local_port == local_port) {
        e.elapsed_ms = (now-(*started))/1000;
        trace->events[trace->total_events++ % MESHPN_STA_TCP_EVENTS] = e;
        trace->packets[tx]++; trace->data_bytes[tx] += e.payload;
        trace->checked[tx] += e.checksum_checked; trace->bad_ip[tx] += e.bad_ip; trace->bad_tcp[tx] += e.bad_tcp;
    }
    portEXIT_CRITICAL(&s_flow_lock);
}
static void tcp_snapshot(bool ap, meshvpn_sta_tcp_trace_t *out)
{
    meshvpn_sta_tcp_trace_t *trace=ap?&s_ap_tcp:&s_tcp;
    uint64_t *started=ap?&s_ap_tcp_started:&s_tcp_started;
    uint64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_flow_lock);
    *out = *trace;
    out->armed = !ap && s_tcp_target && now < s_tcp_until;
    out->age_ms = (*started) ? (now-(*started))/1000 : 0;
    out->count = trace->total_events < MESHPN_STA_TCP_EVENTS ? trace->total_events : MESHPN_STA_TCP_EVENTS;
    unsigned first = trace->total_events-out->count;
    for (unsigned i=0; i<out->count; i++) out->events[i] = trace->events[(first+i)%MESHPN_STA_TCP_EVENTS];
    portEXIT_CRITICAL(&s_flow_lock);
}
static void sta_tcp(bool tx,const uint8_t *h,size_t n,size_t wire_len)
{wifi_tcp(false,tx,h,n,wire_len);}
void meshvpn_ap_probe_sta_tcp(meshvpn_sta_tcp_trace_t *out){tcp_snapshot(false,out);}
void meshvpn_ap_probe_ap_tcp(meshvpn_sta_tcp_trace_t *out){tcp_snapshot(true,out);}
static void checksum_sample(const struct pbuf *p, unsigned ifx)
{
    portENTER_CRITICAL(&s_flow_lock);
    uint64_t number = ++s_checksums[ifx].seen;
    portEXIT_CRITICAL(&s_flow_lock);
    if ((number & 31) != 1) return;
    bool skip = p->len < 20, bad_ip = false, bad_tcp = false, bad_udp = false;
    if (!skip) {
        const uint8_t *h = p->payload; unsigned ihl = (h[0] & 15) * 4, total = r16(h + 2);
        skip = h[0] >> 4 != 4 || ihl < 20 || total < ihl || total > p->len ||
            (h[6] & 0x3f) || h[7] || (h[9] == 6 && total < ihl + 20) ||
            (h[9] == 17 && total < ihl + 8);
        if (!skip) {
            bad_ip = inet_chksum(h, ihl) != 0;
            if (h[9] == 6 || (h[9] == 17 && r16(h + ihl + 6))) {
                unsigned length = h[9] == 17 ? r16(h + ihl + 4) : total - ihl;
                if (length < (h[9] == 17 ? 8 : 20) || length > total - ihl) {
                    portENTER_CRITICAL(&s_flow_lock); s_checksums[ifx].skipped++; portEXIT_CRITICAL(&s_flow_lock);
                    return;
                }
                struct pbuf l4 = {.payload=(uint8_t *)p->payload+ihl, .len=length, .tot_len=length};
                ip4_addr_t src, dst; memcpy(&src.addr, h + 12, 4); memcpy(&dst.addr, h + 16, 4);
                bool bad = inet_chksum_pseudo(&l4, h[9], length, &src, &dst) != 0;
                bad_tcp = bad && h[9] == 6; bad_udp = bad && h[9] == 17;
            }
        }
    }
    portENTER_CRITICAL(&s_flow_lock);
    meshvpn_rx_checksum_t *s = &s_checksums[ifx];
    s->skipped += skip; s->checked += !skip;
    s->bad_ip += bad_ip; s->bad_tcp += bad_tcp; s->bad_udp += bad_udp;
    portEXIT_CRITICAL(&s_flow_lock);
}
void meshvpn_ap_probe_checksums(meshvpn_rx_checksum_t out[4])
{
    portENTER_CRITICAL(&s_flow_lock); memcpy(out, s_checksums, sizeof(s_checksums)); portEXIT_CRITICAL(&s_flow_lock);
}

/* Only bounded TCP handshake metadata, never TLS/application payload or names.
 * Stages: 1 AP input SYN, 2 STA SDIO accepted SYN, 4 STA input SYN-ACK/RST,
 * 8 AP IPv4 output, 16 AP SDIO accepted. Retransmitted SYNs keep their slot. */
static void flow(unsigned stage, const uint8_t *h, size_t n)
{
    if (n < 40 || h[0] >> 4 != 4 || h[9] != 6 || (h[6] & 0x3f) || h[7]) return;
    unsigned ihl = (h[0] & 15) * 4;
    if (ihl < 20 || n < ihl + 20) return;
    const uint8_t *t = h + ihl; unsigned flags = t[13];
    bool syn = (flags & 0x12) == 2, reply = (flags & 0x12) == 0x12 || (flags & 4);
    if (!syn && !reply) return;
    uint32_t src, dst; memcpy(&src, h + 12, 4); memcpy(&dst, h + 16, 4);
    uint16_t sport = r16(t), dport = r16(t + 2);
    uint32_t seq = r32(t + 4), ack = r32(t + 8);
    uint64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_flow_lock);
    int match = -1;
    for (unsigned i = 0; i < 8; i++) {
        meshvpn_ap_flow_t *f = &s_flows[i];
        if (!f->stages) continue;
        if (syn && f->dst == dst && f->dport == dport && f->seq == seq &&
            ((stage != 1 && stage != 32) || (f->src == src && f->sport == sport))) match = i;
        if (reply && f->dst == src && f->dport == sport && ack == f->seq + 1 &&
            (stage == 4 ? f->mapped_port == dport : f->sport == dport && f->src == dst)) match = i;
    }
    if ((stage == 1 || stage == 32) && syn && match < 0) {
        match = s_next++ % 8;
        s_flows[match] = (meshvpn_ap_flow_t){.src=src, .dst=dst, .seq=seq, .sport=sport, .dport=dport};
        s_flows[match].synthetic = s_probe.active && src == s_probe.client;
    }
    if (match >= 0) {
        s_flows[match].stages |= stage;
        if (stage == 2) s_flows[match].mapped_port = sport;
        if (reply) s_flows[match].reply_flags = flags;
        s_seen[match] = now;
    }
    portEXIT_CRITICAL(&s_flow_lock);
}
/* Bounded ARP headers only. Called before lwIP input / after SDIO acceptance;
 * no packet mutation, payload retention, or access to mutable netif state. */
static meshvpn_arp_event_t s_arp[8];
static uint64_t s_arp_seen[8];
static unsigned s_arp_next, s_arp_count;
void meshvpn_ap_probe_arp(unsigned ifx, unsigned tx, const void *frame, unsigned len)
{
    const uint8_t *p=frame;
    if(ifx>1 || !p || len<42 || r16(p+12)!=0x0806 || r16(p+14)!=1 ||
       r16(p+16)!=0x0800 || p[18]!=6 || p[19]!=4 || (r16(p+20)!=1 && r16(p+20)!=2))return;
    meshvpn_arp_event_t e={.ifx=ifx,.tx=!!tx,.operation=r16(p+20)};
    memcpy(&e.sender,p+28,4);memcpy(&e.target,p+38,4);
    memcpy(e.sender_mac,p+22,6);memcpy(e.target_mac,p+32,6);
    memcpy(e.ethernet_source,p+6,6);memcpy(e.ethernet_target,p,6);
    uint64_t now=esp_timer_get_time();
    portENTER_CRITICAL(&s_flow_lock);
    unsigned i=s_arp_next++%8;s_arp[i]=e;s_arp_seen[i]=now;
    if(s_arp_count<8)s_arp_count++;
    portEXIT_CRITICAL(&s_flow_lock);
}
unsigned meshvpn_ap_probe_arp_snapshot(meshvpn_arp_event_t out[8])
{
    uint64_t now=esp_timer_get_time();
    portENTER_CRITICAL(&s_flow_lock);
    unsigned count=s_arp_count;
    for(unsigned i=0;i<count;i++) {
        unsigned index=(s_arp_next-count+i)%8;
        out[i]=s_arp[index];out[i].age_ms=(now-s_arp_seen[index])/1000;
    }
    portEXIT_CRITICAL(&s_flow_lock);
    return count;
}
void meshvpn_ap_probe_flows(meshvpn_ap_flow_t out[8])
{
    uint64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_flow_lock);
    memcpy(out, s_flows, sizeof(s_flows));
    for (unsigned i = 0; i < 8; i++) out[i].age_ms = (now - s_seen[i]) / 1000;
    portEXIT_CRITICAL(&s_flow_lock);
}
void meshvpn_ap_probe_usb_input(const struct pbuf *p, const struct netif *inp)
{
    uint8_t h[120];size_t n=pbuf_copy_partial(p,h,sizeof(h),0);
    if(n>=20 && memcmp(h+16,&netif_ip4_addr(inp)->addr,4)) flow(32,h,n);
}
void meshvpn_ap_probe_input(const struct pbuf *p, const struct netif *inp)
{
    if (!p || !inp) return;
    attach_output(); /* TCP/IP thread; also handles a restarted netif. */
    if (inp != s_ap && inp != s_sta) return;
    checksum_sample(p, inp == s_ap ? 1 : 0);
    uint8_t h[120]; size_t n = pbuf_copy_partial(p, h, sizeof(h), 0);
    if (inp == s_sta) sta_tcp(false, h, n, p->tot_len);
    if (inp == s_ap) wifi_tcp(true, false, h, n, p->tot_len);
    if (inp == s_ap && n >= 20 && !memcmp(h + 16, &netif_ip4_addr(s_ap)->addr, 4)) return;
    flow(inp == s_ap ? 1 : 4, h, n);
}
void meshvpn_ap_probe_tx(unsigned ifx, const void *frame, size_t len)
{
    meshvpn_ap_probe_arp(ifx,1,frame,len);
    meshvpn_ap_echo_tx(ifx, frame, len);
    const uint8_t *p = frame;
    if (!p || len < 14 || p[12] != 8 || p[13]) return;
    if (ifx < 2 && len - 14 <= UINT16_MAX) {
        struct pbuf packet = {.payload=(uint8_t *)p+14, .len=len-14, .tot_len=len-14};
        checksum_sample(&packet, ifx + 2);
    }
    if (!ifx) sta_tcp(true, p+14, len-14, len-14);
    if (ifx == 1) wifi_tcp(true, true, p+14, len-14, len-14);
    flow(ifx ? 16 : 2, p + 14, len - 14);
}
static err_t output(struct netif *n, struct pbuf *p, const ip4_addr_t *dst)
{
    if (meshvpn_ap_echo_output(p, dst->addr)) return ERR_OK;
    uint8_t h[80]; size_t size = pbuf_copy_partial(p, h, sizeof(h), 0);
    flow(8, h, size);
    if (s_probe.active && dst->addr == s_probe.client && size >= 40 &&
        h[0] >> 4 == 4 && h[9] == s_probe.proto &&
        h[12] == 1 && h[13] == 1 && h[14] == 1 && h[15] == 1) {
        unsigned ihl = (h[0] & 15) * 4;
        if (ihl >= 20 && size >= ihl + 20 && r16(h + ihl + 2) == s_probe.port &&
            r16(h + ihl) == (s_probe.proto == 17 ? 53 : 80) &&
            (s_probe.proto == 17 ? r16(h + ihl + 8) == s_probe.id : r32(h + ihl + 8) == s_probe.seq + 1)) {
            /* Consume only a reply to the active synthetic flow, before ARP.
             * Other packets and all real clients retain the original output. */
            unsigned total = r16(h + 2), cs = s_probe.proto == 17 ? 6 : 16;
            bool complete = total >= ihl + 20 && total <= sizeof(s_probe.reply) &&
                            pbuf_copy_partial(p, s_probe.reply, total, 0) == total;
            if (complete && !s_probe.received) {
                uint16_t ipcs = r16(s_probe.reply + 10), l4cs = r16(s_probe.reply + ihl + cs);
                s_probe.checksums_ok = meshvpn_vpn_repair_checksums(s_probe.reply, total) &&
                    ipcs == r16(s_probe.reply + 10) &&
                    (l4cs == r16(s_probe.reply + ihl + cs) || (s_probe.proto == 17 && !l4cs));
                s_probe.flags = s_probe.proto == 6 ? h[ihl + 13] : 0;
                s_probe.rcode = s_probe.proto == 17 ? h[ihl + 11] & 15 : 0;
                s_probe.peer_seq = s_probe.proto == 6 ? r32(h + ihl + 4) : 0;
                s_probe.received = true; s_probe.elapsed_us = esp_timer_get_time() - s_probe.started_us;
                xSemaphoreGive(s_probe.done);
            }
            return ERR_OK;
        }
    }
    return s_output(n, p, dst);
}
esp_err_t meshvpn_ap_probe_echo(const meshvpn_ap_echo_config_t *c, meshvpn_ap_echo_result_t *r)
{
    return meshvpn_ap_echo_run(s_ap, s_sta, c, r);
}
void meshvpn_ap_probe_attach(struct netif *ap, struct netif *sta)
{
    s_sta = sta; s_ap = ap;
}
static esp_err_t emit(void *arg)
{
    bool rst = arg != NULL;
    if (meshvpn_vpn_is_enabled() || !s_ap || !s_sta || !netif_is_up(s_sta) || !netif_is_link_up(s_sta)) return ESP_ERR_INVALID_STATE;
    uint8_t packet[80] = {0}; unsigned len = s_probe.proto == 17 ? 57 : 40;
    packet[0] = 0x45; w16(packet + 2, len); w16(packet + 4, s_probe.id);
    packet[8] = 64; packet[9] = s_probe.proto; memcpy(packet + 12, &s_probe.client, 4);
    memset(packet + 16, 1, 4); w16(packet + 20, s_probe.port);
    w16(packet + 22, s_probe.proto == 17 ? 53 : 80);
    if (s_probe.proto == 17) {
        w16(packet + 24, 37); w16(packet + 28, s_probe.id);
        packet[30] = 1; packet[33] = 1;
        const uint8_t question[] = {7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
        memcpy(packet + 40, question, sizeof(question));
    } else {
        w32(packet + 24, s_probe.seq + (rst ? 1 : 0));
        if (rst) w32(packet + 28, s_probe.peer_seq + 1);
        packet[32] = 0x50; packet[33] = rst ? 0x14 : 2; w16(packet + 34, 32768);
    }
    if (!meshvpn_vpn_repair_checksums(packet, len)) return ESP_FAIL;
    struct pbuf *p = pbuf_alloc(PBUF_LINK, len, PBUF_RAM);
    if (!p) return ESP_ERR_NO_MEM;
    pbuf_take(p, packet, len);
    return ip4_input(p, s_ap) == ERR_OK ? ESP_OK : ESP_FAIL;
}
typedef struct { unsigned proto; SemaphoreHandle_t done; bool started; uint8_t flags; } start_t;
static esp_err_t begin(void *arg)
{
    attach_output();
    start_t *start = arg;
    start->flags = (s_ap && netif_is_up(s_ap) ? 1 : 0) | (s_ap && netif_is_link_up(s_ap) ? 2 : 0) |
        (s_ap && s_ap->napt ? 4 : 0) | (s_sta && netif_is_up(s_sta) ? 8 : 0) |
        (s_sta && netif_is_link_up(s_sta) ? 16 : 0) | (s_sta && s_sta->napt ? 32 : 0);
    if (s_probe.active || start->flags != 31) return ESP_ERR_INVALID_STATE;
    uint8_t address[4]; memcpy(address, &netif_ip4_addr(s_ap)->addr, 4); address[3] = 254;
    ip4_addr_t client; memcpy(&client.addr, address, 4);
    struct eth_addr *mac; const ip4_addr_t *known;
    if (etharp_find_addr(s_ap, &client, &mac, &known) >= 0) return ESP_ERR_INVALID_STATE;
    memset(&s_probe, 0, sizeof(s_probe)); s_probe.active = true; s_probe.client = client.addr;
    start->started = true;
    s_probe.proto = start->proto; s_probe.done = start->done;
    s_probe.port = 49152 + (esp_random() & 0x3fff); s_probe.id = esp_random(); s_probe.seq = esp_random();
    s_probe.started_us = esp_timer_get_time();
    return emit(NULL);
}
static esp_err_t finish(void *arg)
{
    meshvpn_ap_probe_result_t *out = arg;
    out->received = s_probe.received; out->checksums_ok = s_probe.checksums_ok;
    out->flags = s_probe.flags; out->rcode = s_probe.rcode; out->elapsed_ms = s_probe.elapsed_us / 1000;
    if (s_probe.received && s_probe.proto == 6 && (s_probe.flags & 0x12) == 0x12) emit((void *)1);
    s_probe.active = false; s_probe.done = NULL;
    return ESP_OK;
}
esp_err_t meshvpn_ap_probe_run(meshvpn_ap_probe_result_t out[2])
{
    memset(out, 0, 2 * sizeof(*out));
    for (unsigned i = 0; i < 2; i++) {
        SemaphoreHandle_t done = xSemaphoreCreateBinary();
        if (!done) return ESP_ERR_NO_MEM;
        start_t start = {.proto = i ? 6 : 17, .done = done};
        out[i].error = esp_netif_tcpip_exec(begin, &start);
        out[i].interface_flags = start.flags;
        if (out[i].error == ESP_OK) {
            for (unsigned attempt = 0; attempt < 3; attempt++) {
                if (xSemaphoreTake(done, pdMS_TO_TICKS(1200)) == pdTRUE) break;
                if (attempt == 2) out[i].error = ESP_ERR_TIMEOUT;
                else if ((out[i].error = esp_netif_tcpip_exec(emit, NULL)) != ESP_OK) break;
            }
        }
        if (start.started) esp_netif_tcpip_exec(finish, &out[i]);
        vSemaphoreDelete(done);
    }
    return ESP_OK;
}
