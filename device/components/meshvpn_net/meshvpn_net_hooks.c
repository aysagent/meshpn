#include "meshvpn_lwip_hooks.h"

#include "lwip/inet_chksum.h"
#include "lwip/ip4.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/udp.h"
#include "meshvpn_dns_proxy.h"
#include "sdkconfig.h"

static uint32_t s_lan_ip4_rx;

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

/**
 * Redirect LAN client DNS queries (UDP/53 to 8.8.8.8, router, etc.) to the
 * gateway address so the local DNS proxy socket receives them even when iot_bridge
 * overwrites the DHCP DNS option to the uplink resolver.
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
    if (IPH_PROTO(iphdr) != IP_PROTO_UDP || p->tot_len < iphdr_hlen + UDP_HLEN) {
        return 0;
    }

    struct udp_hdr *udphdr = (struct udp_hdr *)((uint8_t *)p->payload + iphdr_hlen);
    if (lwip_ntohs(udphdr->dest) != 53) {
        return 0;
    }

    const ip4_addr_t *gw = netif_ip4_addr(inp);
    if (ip4_addr_cmp(&iphdr->dest, gw)) {
        return 0;
    }

    ip4_addr_copy(iphdr->dest, *gw);
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, iphdr_hlen));
    udphdr->chksum = 0;

    meshvpn_dns_count_hijack();
    return 0;
}
