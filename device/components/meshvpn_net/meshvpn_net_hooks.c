#include "meshvpn_lwip_hooks.h"

#include <string.h>

#include "lwip/inet_chksum.h"
#include "lwip/ip4.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"
#include "meshvpn_datapath.h"
#include "meshvpn_dns_proxy.h"
#include "meshvpn_routing.h"
#include "meshvpn_vpn.h"
#include "sdkconfig.h"

#define MESHVPN_TRANSPARENT_INTERCEPT_PORT 8443

static uint32_t s_lan_ip4_rx;
static uint32_t s_vpn_routed;
static uint32_t s_blocked;

static bool meshvpn_is_lan_netif(const struct netif *inp)
{
    if (!inp) {
        return false;
    }
    const ip4_addr_t *ip = netif_ip4_addr(inp);
    if (ip4_addr_isany(ip)) {
        return false;
    }
    uint8_t o2 = ip4_addr2(ip);
    return o2 == CONFIG_MESHVPN_USB_SUBNET_OCTET_2 || o2 == 4;
}

uint32_t meshvpn_net_lan_ip4_rx_count(void)
{
    return s_lan_ip4_rx;
}

static uint16_t ip_checksum_fold(uint32_t sum)
{
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static void ip4_fix_checksum(struct ip_hdr *iphdr, uint16_t iphdr_hlen)
{
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, iphdr_hlen));
}

static void tcp_fix_checksum(struct ip_hdr *iphdr, struct tcp_hdr *tcphdr, uint16_t iphdr_hlen, uint16_t tcplen)
{
    uint32_t sum = 0;
    const uint16_t *src = (const uint16_t *)&iphdr->src;
    for (int i = 0; i < 4; i++) {
        sum += lwip_ntohs(src[i]);
    }
    sum += IP_PROTO_TCP;
    sum += tcplen;

    const uint16_t *tcp = (const uint16_t *)tcphdr;
    for (int i = 0; i < (tcplen + 1) / 2; i++) {
        sum += lwip_ntohs(tcp[i]);
    }
    tcphdr->chksum = ip_checksum_fold(sum);
}

static bool meshvpn_try_transparent_redirect(struct pbuf *p, struct netif *inp, struct ip_hdr *iphdr, uint16_t iphdr_hlen)
{
    if (!meshvpn_vpn_is_transparent()) {
        return false;
    }
    if (IPH_PROTO(iphdr) != IP_PROTO_TCP) {
        return false;
    }
    if (p->tot_len < iphdr_hlen + TCP_HLEN) {
        return false;
    }

    struct tcp_hdr *tcphdr = (struct tcp_hdr *)((uint8_t *)p->payload + iphdr_hlen);
    if (lwip_ntohs(tcphdr->dest) != 443) {
        return false;
    }

    const ip4_addr_t *gw = netif_ip4_addr(inp);
    if (!gw) {
        return false;
    }

    ip4_addr_copy(iphdr->dest, *gw);
    tcphdr->dest = lwip_htons(MESHVPN_TRANSPARENT_INTERCEPT_PORT);
    ip4_fix_checksum(iphdr, iphdr_hlen);

    uint16_t tcplen = p->tot_len - iphdr_hlen;
    tcphdr->chksum = 0;
    tcp_fix_checksum(iphdr, tcphdr, iphdr_hlen, tcplen);
    meshvpn_vpn_transparent_note_redirect();
    return true;
}

static bool meshvpn_handle_routing(struct pbuf *p, struct netif *inp, struct ip_hdr *iphdr, uint16_t iphdr_hlen)
{
    const ip4_addr_t *gw = netif_ip4_addr(inp);
    if (gw && ip4_addr_cmp(&iphdr->dest, gw)) {
        return false;
    }

    meshvpn_route_action_t action = meshvpn_routing_classify_ipv4(iphdr->dest.addr, iphdr->src.addr);
    if (action == MESHVPN_ROUTE_DIRECT) {
        return false;
    }
    if (action == MESHVPN_ROUTE_BLOCK) {
        s_blocked++;
        return true;
    }

    if (meshvpn_try_transparent_redirect(p, inp, iphdr, iphdr_hlen)) {
        return false;
    }

    if (p->tot_len > 1500) {
        return false;
    }

    uint8_t buf[1500];
    if (pbuf_copy_partial(p, buf, p->tot_len, 0) != p->tot_len) {
        return false;
    }

    if (meshvpn_datapath_submit_ipv4(buf, (uint16_t)p->tot_len) == ESP_OK) {
        s_vpn_routed++;
        return true;
    }
    return false;
}

/**
 * Redirect LAN client DNS queries (UDP/53) to gateway.
 * Route VPN/block traffic before normal forwarding.
 */
int meshvpn_hook_ip4_input(struct pbuf *p, struct netif *inp)
{
    if (!meshvpn_is_lan_netif(inp) || p == NULL || p->len < sizeof(struct ip_hdr)) {
        return 0;
    }

    s_lan_ip4_rx++;

    struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;
    if (IPH_V(iphdr) != 4) {
        return 0;
    }

    uint16_t iphdr_hlen = IPH_HL_BYTES(iphdr);
    if (iphdr_hlen < IP_HLEN || p->tot_len < iphdr_hlen) {
        return 0;
    }

    if (IPH_PROTO(iphdr) == IP_PROTO_UDP && p->tot_len >= iphdr_hlen + UDP_HLEN) {
        struct udp_hdr *udphdr = (struct udp_hdr *)((uint8_t *)p->payload + iphdr_hlen);
        if (lwip_ntohs(udphdr->dest) == 53) {
            const ip4_addr_t *gw = netif_ip4_addr(inp);
            if (gw && !ip4_addr_cmp(&iphdr->dest, gw)) {
                ip4_addr_copy(iphdr->dest, *gw);
                ip4_fix_checksum(iphdr, iphdr_hlen);
                udphdr->chksum = 0;
                meshvpn_dns_count_hijack();
            }
        }
    }

    if (meshvpn_handle_routing(p, inp, iphdr, iphdr_hlen)) {
        return 1;
    }

    return 0;
}
