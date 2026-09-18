/* clean-vpn socket client. Hooks never wait on the network; the worker owns
 * the outer socket. All netif/input operations execute on the lwIP thread. */
#include "meshvpn_vpn.h"
#include "meshvpn_vpn_frame.h"
#include "meshvpn_wireguard.h"
#include "sdkconfig.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/netif.h"
#include "lwip/ip4.h"
#include "lwip/ip4_frag.h"
#include "lwip/inet_chksum.h"
#include "lwip/lwip_napt.h"

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static meshvpn_vpn_status_t s;
static meshvpn_vpn_config_t s_config; /* never returned by status; contains keys */
static struct netif s_vpn, *s_usb, *s_ap;
static bool s_ready;
static uint32_t s_probe_epoch;
typedef struct { uint16_t len; int64_t time; uint8_t data[MESHVPN_VPN_MTU]; } packet_t;
static packet_t *s_queue;
static unsigned s_head, s_count;
#define LOCK() portENTER_CRITICAL(&s_lock)
#define UNLOCK() portEXIT_CRITICAL(&s_lock)
#define COUNT(field) do { LOCK(); s.field++; UNLOCK(); } while (0)

void meshvpn_vpn_get_status(meshvpn_vpn_status_t *out) { LOCK(); *out = s; UNLOCK(); }
bool meshvpn_vpn_is_connected(void) { LOCK(); bool v = s.connected; UNLOCK(); return v; }
static bool enabled(void) { LOCK(); bool v = s.enabled; UNLOCK(); return v; }
static bool session(uint32_t g) { LOCK(); bool v = s.enabled && s.generation == g; UNLOCK(); return v; }
static void flush_nat(void)
{
    bool usb = s_usb && s_usb->napt, ap = s_ap && s_ap->napt;
    if (usb) ip_napt_enable_netif(s_usb, 0);
    if (ap) ip_napt_enable_netif(s_ap, 0);
    if (usb) ip_napt_enable_netif(s_usb, 1);
    if (ap) ip_napt_enable_netif(s_ap, 1);
}
static void state_core(uint32_t g, const char *name, bool up, int error)
{
    bool flush = false;
    LOCK();
    if (g == s.generation) {
        flush = s.enabled && !s.kill_switch && s.connected != up;
        if (s.connected != up) { s_probe_epoch++; s.probe_at_us = 0; s.probe_ok = false; }
        strlcpy(s.state, name, sizeof(s.state)); s.connected = up; s.last_error = error;
        if (!up) { s.tx_dropped += s_count; s_head = s_count = s.queue_depth = 0; }
    }
    UNLOCK();
    if (flush) flush_nat(); /* DIRECT and VPN cannot share NAT identities. */
}
typedef struct { uint32_t g; const char *name; bool up; int error; } state_change_t;
static esp_err_t set_state(void *arg)
{ state_change_t *c = arg; state_core(c->g, c->name, c->up, c->error); return ESP_OK; }
static void state(uint32_t g, const char *name, bool up, int error)
{ state_change_t c = {g, name, up, error}; esp_netif_tcpip_exec(set_state, &c); }
esp_err_t meshvpn_vpn_validate_config(const meshvpn_vpn_config_t *c)
{
    const char *error = meshvpn_vpn_config_error(c);
    if (!error) return ESP_OK;
    if (c && c->enabled && strnlen(c->transport, sizeof(c->transport)) < sizeof(c->transport) &&
        strcmp(c->transport, "socket") && strcmp(c->transport, "wireguard")) return ESP_ERR_NOT_SUPPORTED;
    return ESP_ERR_INVALID_ARG;
}
const char *meshvpn_vpn_config_error(const meshvpn_vpn_config_t *c)
{
    if (!c || strnlen(c->server, sizeof(c->server)) == sizeof(c->server) ||
        strnlen(c->transport, sizeof(c->transport)) == sizeof(c->transport)) return "VPN config contains an invalid or overlong field.";
    if (!c->enabled) return NULL;
    uint8_t ip[4]; uint16_t port;
    bool wg = !strcmp(c->transport, "wireguard");
    if (!wg && strcmp(c->transport, "socket")) return "Transport: select socket or WireGuard.";
    if (!meshvpn_vpn_endpoint(c->server, ip, &port)) return "Endpoint/server: enter numeric IPv4:port (port 1-65535); hostnames and IPv6 are not supported.";
    if (wg) return meshvpn_wg_config_error(c);
    if (ip[0] == 10 && ip[1] == 99 && ip[2] == 0) return "Server overlaps the socket tunnel subnet 10.99.0.0/24.";
    return NULL;
}
static esp_err_t apply_config(void *arg)
{
    const meshvpn_vpn_config_t *c = arg;
    esp_err_t err = meshvpn_vpn_validate_config(c);
#if !CONFIG_MESHVPN_VPN_ENABLE
    if (c->enabled) err = ESP_ERR_NOT_SUPPORTED;
#endif
    meshvpn_wg_stop();
    ip4_addr_t address;
    if (strcmp(c->transport, "wireguard") || !ip4addr_aton(c->wg_address, &address)) IP4_ADDR(&address,10,99,0,2);
    netif_set_ipaddr(&s_vpn, &address);
    /* Unsupported saved profiles must never silently enable DIRECT. */
    LOCK(); s_config = *c; s.enabled = c->enabled; s.connected = false; s.generation++;
    s.kill_switch = !c->allow_direct; s_probe_epoch++; s.probe_at_us = 0; s.probe_ok = false; s.probe_error = 0;
    s.tx_dropped += s_count; s_head = s_count = s.queue_depth = 0;
    strlcpy(s.server, c->server, sizeof(s.server)); strlcpy(s.transport, c->transport, sizeof(s.transport));
    strlcpy(s.state, c->enabled ? "waiting" : "disabled", sizeof(s.state));
    s.last_error = err;
    strlcpy(s.wg_address, c->wg_address, sizeof(s.wg_address));
    strlcpy(s.wg_address_input, c->wg_address_input, sizeof(s.wg_address_input));
    strlcpy(s.wg_dns, c->wg_dns, sizeof(s.wg_dns));
    strlcpy(s.wg_public_key, c->wg_public_key, sizeof(s.wg_public_key));
    s.wg_keepalive = c->wg_keepalive;
    s.wg_private_key_set = c->wg_private_key[0] != 0; s.wg_preshared_key_set = c->wg_preshared_key[0] != 0;
    UNLOCK();
    LOCK(); ip4addr_ntoa_r(&address, s.address, sizeof(s.address)); s.wg_handshake_age = UINT32_MAX; UNLOCK();
    /* Existing DIRECT mappings must not survive a change of egress identity. */
    flush_nat();
    return err;
}
esp_err_t meshvpn_vpn_start(const meshvpn_vpn_config_t *c)
{ return c ? esp_netif_tcpip_exec(apply_config, (void *)c) : ESP_ERR_INVALID_ARG; }
esp_err_t meshvpn_vpn_stop(void)
{ meshvpn_vpn_config_t c = { .transport = "socket" }; return meshvpn_vpn_start(&c); }
void meshvpn_vpn_set_lan(struct netif *usb, struct netif *ap) { s_usb = usb; s_ap = ap; }
static bool lan(const ip4_addr_t *ip, struct netif *n)
{ return n && ip && ip4_addr_netcmp(ip, netif_ip4_addr(n), netif_ip4_netmask(n)); }
static bool tunnel_policy(void)
{ LOCK(); bool v = s.enabled && (s.kill_switch || s.connected); UNLOCK(); return v; }
struct netif *meshvpn_vpn_route(const ip4_addr_t *src, const ip4_addr_t *dst)
{
    if (!s_ready || !src || !dst) return NULL;
    /* Previously bound DNS sockets remain blackholed after disabling VPN. */
    if (ip4_addr_cmp(src, netif_ip4_addr(&s_vpn))) return &s_vpn;
    if (!tunnel_policy() || (!lan(src, s_usb) && !lan(src, s_ap))) return NULL;
    if ((s_usb && ip4_addr_cmp(src, netif_ip4_addr(s_usb))) ||
        (s_ap && ip4_addr_cmp(src, netif_ip4_addr(s_ap)))) return NULL;
    if (lan(dst, s_usb) || lan(dst, s_ap) || ip4_addr_ismulticast(dst) || dst->addr == IPADDR_BROADCAST) return NULL;
    return &s_vpn; /* Output drops while disconnected; no STA fallback. */
}
esp_err_t meshvpn_vpn_send_ipv4(const uint8_t *p, uint16_t len)
{
    if (len > MESHVPN_VPN_MTU || !meshvpn_vpn_ipv4_valid(p, len)) return ESP_ERR_INVALID_ARG;
    LOCK();
    if (!s.connected || !s_queue) { s.tx_dropped++; UNLOCK(); return ESP_ERR_INVALID_STATE; }
    if (s_count == MESHVPN_VPN_SLOTS) { s.queue_full++; UNLOCK(); return ESP_ERR_NO_MEM; }
    packet_t *q = &s_queue[(s_head + s_count) % MESHVPN_VPN_SLOTS];
    q->len = len; q->time = esp_timer_get_time(); memcpy(q->data, p, len);
    s.queue_depth = ++s_count;
    if (s_count > s.queue_high_water) s.queue_high_water = s_count;
    UNLOCK(); return ESP_OK;
}
/* RX is injected into lwIP; no second competing consumer. */
esp_err_t meshvpn_vpn_recv_ipv4(uint8_t *p, uint16_t cap, uint16_t *len)
{ (void)p; (void)cap; if (len) *len = 0; return ESP_ERR_NOT_SUPPORTED; }
static err_t output(struct netif *n, struct pbuf *p, const ip4_addr_t *dst)
{
    (void)n; (void)dst;
    uint8_t buf[MESHVPN_VPN_MTU];
    if (p->tot_len > sizeof(buf)) return ERR_BUF;
    pbuf_copy_partial(p, buf, p->tot_len, 0);
    if (!meshvpn_vpn_clamp_mss(buf, p->tot_len)) return ERR_VAL;
    if (!strcmp(s_config.transport, "wireguard")) {
        if (!enabled() || !meshvpn_wg_up()) { COUNT(tx_dropped); return ERR_RTE; }
        struct pbuf *copy = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);
        if (!copy) { COUNT(tx_dropped); return ERR_MEM; }
        pbuf_take(copy, buf, p->tot_len);
        err_t result = meshvpn_wg_output(copy, dst); pbuf_free(copy);
        LOCK(); if (result == ERR_OK) { s.packets_out++; s.bytes_out += p->tot_len; } else s.tx_dropped++; UNLOCK();
        return result;
    }
    return meshvpn_vpn_send_ipv4(buf, p->tot_len) == ESP_OK ? ERR_OK : ERR_RTE;
}
static err_t net_init(struct netif *n)
{ n->name[0] = 'v'; n->name[1] = 'p'; n->mtu = MESHVPN_VPN_MTU; n->output = output; return ERR_OK; }
static esp_err_t add_netif(void *arg)
{
    (void)arg; ip4_addr_t ip, mask, gw;
    IP4_ADDR(&ip, 10,99,0,2); IP4_ADDR(&mask, 255,255,255,255); IP4_ADDR(&gw, 10,99,0,1);
    if (!netif_add(&s_vpn, &ip, &mask, &gw, NULL, net_init, ip4_input)) return ESP_FAIL;
    netif_set_up(&s_vpn); netif_set_link_up(&s_vpn); s_ready = true; return ESP_OK;
}
/* Called before NAPT: reassembly must precede address/port translation. */
int meshvpn_vpn_input(struct pbuf *p, struct netif *inp)
{
    bool from_vpn = inp == &s_vpn || inp == meshvpn_wg_netif();
    if (!enabled() || (inp != s_usb && inp != s_ap && !from_vpn)) return 0;
    uint8_t h[60];
    if (pbuf_copy_partial(p, h, 20, 0) != 20 || (h[0] >> 4) != 4) goto drop;
    unsigned ihl = (h[0] & 15) * 4, len = (h[2] << 8) | h[3];
    if (ihl < 20 || ihl > 60 || len < ihl || len > p->tot_len ||
        pbuf_copy_partial(p, h, ihl, 0) != ihl || inet_chksum(h, ihl)) goto drop;
    ip4_addr_t src, dst; memcpy(&src.addr, h + 12, 4); memcpy(&dst.addr, h + 16, 4);
    if (!from_vpn) {
        if (ip4_addr_isany_val(src)) {
            /* Only DHCP bootstrap may use 0.0.0.0; it is never forwarded. */
            uint8_t ports[4];
            if (dst.addr != IPADDR_BROADCAST || h[9] != 17 || (h[6] & 0x3f) || h[7] ||
                pbuf_copy_partial(p, ports, 4, ihl) != 4 || ports[0] || ports[1] != 68 || ports[2] || ports[3] != 67) goto drop;
        } else if (!lan(&src, inp) || ip4_addr_cmp(&src, netif_ip4_addr(inp))) goto drop;
    }
    if (from_vpn && !ip4_addr_cmp(&dst, netif_ip4_addr(&s_vpn))) goto drop;
    if ((h[6] & 0x3f) || h[7]) {
#if IP_REASSEMBLY
        if (p->len < ihl) goto drop;
        pbuf_realloc(p, len);
        struct pbuf *whole = ip4_reass(p);
        if (whole) {
            struct pbuf *flat = pbuf_clone(PBUF_RAW, PBUF_RAM, whole); pbuf_free(whole);
            if (flat) ip4_input(flat, inp); else COUNT(rx_dropped);
        }
        return 1;
#else
        goto drop;
#endif
    }
    unsigned need = h[9] == 6 ? 20 : 8;
    if (h[9] != 6 && h[9] != 17 && h[9] != 1) goto drop;
    if (len < ihl + need || p->len < ihl + need) goto drop;
    if (inp == meshvpn_wg_netif()) {
        if (p->len < len || !meshvpn_vpn_clamp_mss(p->payload, len)) goto drop;
        LOCK(); s.packets_in++; s.bytes_in += len; UNLOCK();
        /* Local probe/DNS sockets are pinned to the stable vp interface.
         * lwIP TCP/UDP rejects replies arriving on wg when pcb->netif_idx is vp.
         * Re-enter before NAPT so local delivery and forwarded NAT replies share
         * the same logical ingress as socket transport. This hook consumes p;
         * the vp pass must not redirect or count the packet again. */
        ip4_input(p, &s_vpn);
        return 1;
    }
    return 0;
drop:
    COUNT(rx_dropped); pbuf_free(p); return 1;
}
typedef struct { const uint8_t *p; size_t len; uint32_t generation; } rx_t;
static esp_err_t inject(void *arg)
{
    rx_t *rx = arg;
    if (!session(rx->generation)) return ESP_FAIL;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, rx->len, PBUF_RAM);
    if (!p) { COUNT(rx_dropped); return ESP_OK; }
    pbuf_take(p, rx->p, rx->len);
    if (!meshvpn_vpn_clamp_mss(p->payload, p->tot_len)) { pbuf_free(p); COUNT(rx_invalid); return ESP_FAIL; }
    ip4_input(p, &s_vpn);
    LOCK(); s.packets_in++; s.bytes_in += rx->len; UNLOCK(); return ESP_OK;
}
static bool receive_packet(void *arg, const uint8_t *p, size_t len)
{ rx_t rx = { p, len, *(uint32_t *)arg }; return esp_netif_tcpip_exec(inject, &rx) == ESP_OK; }
int meshvpn_vpn_dns_socket(int fd, uint32_t *resolver)
{
    if (!tunnel_policy()) return 0;
    if (!meshvpn_vpn_is_connected()) return -1;
    struct sockaddr_in local = { .sin_family = AF_INET };
    char address[16], resolver_ip[16];
    LOCK(); strlcpy(address, s.address, sizeof(address));
    strlcpy(resolver_ip, !strcmp(s.transport, "wireguard") ? s_config.wg_dns : "1.1.1.1", sizeof(resolver_ip)); UNLOCK();
    inet_aton(address, &local.sin_addr);
    struct in_addr dns; inet_aton(resolver_ip, &dns); *resolver = dns.s_addr;
    struct ifreq iface = {0};
    if (!netif_index_to_name(netif_get_index(&s_vpn), iface.ifr_name) ||
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &iface, sizeof(iface))) return -1;
    return bind(fd, (struct sockaddr *)&local, sizeof(local));
}
esp_err_t meshvpn_vpn_check_internet(void)
{
    meshvpn_vpn_status_t before; uint32_t epoch;
    LOCK(); before = s; epoch = s_probe_epoch; UNLOCK();
    if (!before.enabled || !before.connected) return ESP_ERR_INVALID_STATE;
    /* Never use the DNS helper's optional DIRECT fallback for this probe. */
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), failure = 0;
    if (fd < 0) failure = errno;
    else {
        struct sockaddr_in local = { .sin_family = AF_INET };
        struct sockaddr_in remote = { .sin_family = AF_INET, .sin_port = htons(443) };
        inet_aton(before.address, &local.sin_addr); inet_aton("1.1.1.1", &remote.sin_addr);
        struct ifreq iface = {0};
        if (!netif_index_to_name(netif_get_index(&s_vpn), iface.ifr_name)) failure = ENODEV;
        else if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &iface, sizeof(iface)) ||
                 bind(fd, (struct sockaddr *)&local, sizeof(local)) ||
                 fcntl(fd, F_SETFL, O_NONBLOCK) < 0) failure = errno;
        else if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
            failure = errno;
            if (failure == EINPROGRESS) {
                fd_set wr; FD_ZERO(&wr); FD_SET(fd, &wr);
                struct timeval tv = { .tv_sec = 5 };
                int ready = select(fd + 1, NULL, &wr, NULL, &tv);
                if (ready <= 0) failure = ready == 0 ? ETIMEDOUT : errno;
                else { socklen_t len = sizeof(failure); if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &failure, &len)) failure = errno; }
            }
        }
        close(fd);
    }
    LOCK();
    bool current = s.enabled && s.connected && s.generation == before.generation && s_probe_epoch == epoch;
    if (current) { s.probe_ok = !failure; s.probe_error = failure; s.probe_at_us = esp_timer_get_time(); }
    UNLOCK();
    return current ? ESP_OK : ESP_ERR_INVALID_STATE;
}
static esp_err_t wg_poll(void *arg)
{
    static uint32_t last_uplink;
    uint32_t g = *(uint32_t *)arg;
    if (!session(g) || strcmp(s_config.transport, "wireguard")) return ESP_OK;
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip;
    if (!sta || !esp_netif_is_netif_up(sta) || esp_netif_get_ip_info(sta, &ip) != ESP_OK || !ip.ip.addr) {
        meshvpn_wg_stop(); last_uplink = 0; state_core(g, "wait_uplink", false, ENETDOWN); return ESP_OK;
    }
    if (last_uplink != ip.ip.addr) { meshvpn_wg_stop(); last_uplink = ip.ip.addr; }
    esp_err_t err = meshvpn_wg_start(&s_config);
    bool up = err == ESP_OK && meshvpn_wg_up();
    state_core(g, up ? "up" : err == ESP_OK ? "handshake" : "wg_error", up, err);
    uint32_t age = meshvpn_wg_handshake_age();
    LOCK(); s.wg_handshake_age = age; UNLOCK();
    return ESP_OK;
}
static int connect_exit(const meshvpn_vpn_status_t *cfg)
{
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF"); esp_netif_ip_info_t ip;
    if (!sta || !esp_netif_is_netif_up(sta) || esp_netif_get_ip_info(sta, &ip) != ESP_OK || !ip.ip.addr) { errno = ENETDOWN; return -1; }
    uint8_t addr[4]; uint16_t port;
    if (strcmp(cfg->transport, "socket") || !meshvpn_vpn_endpoint(cfg->server, addr, &port)) { errno = EINVAL; return -1; }
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (fd < 0) return -1;
    struct sockaddr_in local = { .sin_family = AF_INET, .sin_addr.s_addr = ip.ip.addr };
    struct sockaddr_in remote = { .sin_family = AF_INET, .sin_port = htons(port) };
    memcpy(&remote.sin_addr.s_addr, addr, 4);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) goto fail;
    int yes = 1, idle = 15, interval = 5, count = 3;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    fcntl(fd, F_SETFL, O_NONBLOCK); state(cfg->generation, "connecting", false, 0);
    int rc = connect(fd, (struct sockaddr *)&remote, sizeof(remote));
    if (rc < 0 && errno != EINPROGRESS) goto fail;
    for (int i = 0; rc < 0 && i < 50 && session(cfg->generation); i++) {
        fd_set wr; FD_ZERO(&wr); FD_SET(fd, &wr); struct timeval tv = { .tv_usec = 100000 };
        if (select(fd + 1, NULL, &wr, NULL, &tv) > 0) {
            int e = 0; socklen_t n = sizeof(e);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &n) || e) { errno = e; goto fail; } rc = 0;
        }
    }
    if (rc == 0 && session(cfg->generation)) return fd;
    errno = ETIMEDOUT;
fail: { int e = errno; close(fd); errno = e; return -1; }
}
static void __attribute__((unused)) worker(void *arg)
{
    (void)arg;
    meshvpn_vpn_decoder_t *d = heap_caps_calloc(1, sizeof(*d), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    uint8_t *tx = heap_caps_malloc(MESHVPN_VPN_MTU + 4, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    uint8_t *rx = heap_caps_malloc(1024, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!d || !tx || !rx) { free(d); free(tx); free(rx); state(s.generation, "no_memory", false, ENOMEM); vTaskDelete(NULL); return; }
    unsigned backoff = 1;
    for (;;) {
        meshvpn_vpn_status_t cfg; meshvpn_vpn_get_status(&cfg);
        if (!cfg.enabled || cfg.last_error == ESP_ERR_NOT_SUPPORTED || cfg.last_error == ESP_ERR_INVALID_ARG) {
            vTaskDelay(pdMS_TO_TICKS(100)); continue;
        }
        if (!strcmp(cfg.transport, "wireguard")) {
            if (!meshvpn_wg_clock_ready()) state(cfg.generation, "wait_time", false, 0);
            else esp_netif_tcpip_exec(wg_poll, &cfg.generation);
            vTaskDelay(pdMS_TO_TICKS(1000)); continue;
        }
        state(cfg.generation, "wait_uplink", false, 0);
        int fd = connect_exit(&cfg);
        if (fd < 0) { state(cfg.generation, "backoff", false, errno); goto retry; }
        if (!session(cfg.generation)) { close(fd); continue; }
        state(cfg.generation, "up", true, 0); backoff = 1; memset(d, 0, sizeof(*d));
        size_t used = 0, length = 0; int64_t tx_since = 0, partial_since = 0; int error = 0;
        while (session(cfg.generation)) {
            if (!length) {
                LOCK();
                if (s_count) {
                    packet_t *p = &s_queue[s_head];
                    if (esp_timer_get_time() - p->time > 1000000) s.queue_expired++;
                    else { length = p->len + 4; meshvpn_vpn_frame_header(tx, p->len); memcpy(tx + 4, p->data, p->len); }
                    s_head = (s_head + 1) % MESHVPN_VPN_SLOTS; s.queue_depth = --s_count;
                }
                UNLOCK(); used = 0; tx_since = esp_timer_get_time();
            }
            fd_set rd, wr; FD_ZERO(&rd); FD_ZERO(&wr); FD_SET(fd, &rd); if (length) FD_SET(fd, &wr);
            struct timeval tv = { .tv_usec = 10000 };
            if (select(fd + 1, &rd, &wr, NULL, &tv) < 0) { error = errno; break; }
            if (FD_ISSET(fd, &rd)) {
                int n = recv(fd, rx, 1024, 0);
                if (n == 0) { error = ECONNRESET; break; }
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) { error = errno; break; }
                if (n > 0) {
                    if (!meshvpn_vpn_decode(d, rx, n, receive_packet, &cfg.generation)) { COUNT(rx_invalid); error = EPROTO; break; }
                    if (!d->header_used) partial_since = 0;
                    else if (!partial_since) partial_since = esp_timer_get_time();
                }
            }
            if (length && FD_ISSET(fd, &wr)) {
                int n = send(fd, tx + used, length - used, 0);
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) { error = errno; break; }
                if (n > 0) used += n;
                if (used == length) { LOCK(); s.packets_out++; s.bytes_out += length - 4; UNLOCK(); length = 0; }
            }
            int64_t now = esp_timer_get_time();
            if ((length && now - tx_since > 5000000) || (partial_since && now - partial_since > 5000000)) { error = ETIMEDOUT; break; }
        }
        if (length) COUNT(tx_dropped);
        close(fd);
        if (!session(cfg.generation)) continue;
        state(cfg.generation, "backoff", false, error);
retry:
        COUNT(reconnects);
        for (unsigned i = 0; i < backoff * 10 && session(cfg.generation); i++) vTaskDelay(pdMS_TO_TICKS(100));
        if (backoff < 16) backoff *= 2;
    }
}
esp_err_t meshvpn_vpn_init(void)
{
    strlcpy(s.state, "disabled", sizeof(s.state)); strlcpy(s.transport, "socket", sizeof(s.transport));
    strlcpy(s.address, "10.99.0.2", sizeof(s.address)); s.wg_handshake_age = UINT32_MAX;
    /* Keep a blackhole route even in builds without transport workers, so a
     * saved enable flag cannot turn into DIRECT when flashing another build. */
    if (esp_netif_tcpip_exec(add_netif, NULL) != ESP_OK) return ESP_FAIL;
#if CONFIG_MESHVPN_VPN_ENABLE
    s_queue = heap_caps_calloc(MESHVPN_VPN_SLOTS, sizeof(packet_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_queue) return ESP_ERR_NO_MEM;
    if (xTaskCreate(worker, "vpn_socket", 4096, NULL, 5, NULL) != pdPASS) return ESP_ERR_NO_MEM;
    s.implemented = true;
#endif
    return ESP_OK;
}
