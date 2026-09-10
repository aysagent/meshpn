#include "meshvpn_lwip_hooks.h"
#include <string.h>

#include "lwip/def.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip4.h"
#include "sdkconfig.h"

static struct netif *s_usb;
static struct netif *s_ap;
static uint32_t s_lan_ip4_rx;
static uint32_t s_ap_ip4_rx;
static uint32_t s_denied;

void meshvpn_net_set_usb_interface(struct netif *netif) { s_usb = netif; }
void meshvpn_net_set_ap_interface(struct netif *netif) { s_ap = netif; }
uint32_t meshvpn_net_lan_ip4_rx_count(void) { return s_lan_ip4_rx; }
uint32_t meshvpn_net_ap_ip4_rx_count(void) { return s_ap_ip4_rx; }
uint32_t meshvpn_net_denied_count(void) { return s_denied; }

static int discard(struct pbuf *p)
{
    s_denied++;
    pbuf_free(p);
    return 1; /* lwIP hook owns consumed pbuf */
}

/* Called before NAPT/reassembly. Never infer trust from an IP address.
 * DNS is advertised by DHCP; no transparent destination rewrite is performed.
 * Outbound requests use ephemeral local ports and are unaffected. */
int meshvpn_hook_ip4_input(struct pbuf *p, struct netif *inp)
{
    if (!p || !inp) return 0;
    if (inp == s_usb) {
        s_lan_ip4_rx++;
        return 0;
    }
    if (inp == s_ap) s_ap_ip4_rx++;
    uint8_t h[60];
    if (pbuf_copy_partial(p, h, 20, 0) != 20 || (h[0] >> 4) != 4) return discard(p);
    unsigned ihl = (h[0] & 15) * 4;
    unsigned total = ((unsigned)h[2] << 8) | h[3];
    if (ihl < 20 || ihl > 60 || total < ihl || total > p->tot_len) return discard(p);

    /* mDNS must also be blocked for multicast destinations on uplink. */
    int local = h[16] == 224 && h[17] == 0 && h[18] == 0 && h[19] == 251;
    ip4_addr_t dest;
    memcpy(&dest.addr, h + 16, 4);
    if (ip4_addr_isbroadcast(&dest, inp)) local = 1;
    struct netif *n;
    NETIF_FOREACH(n) {
        if (!memcmp(h + 16, &netif_ip4_addr(n)->addr, 4)) local = 1;
    }
    if (!local) return 0;
    if (h[9] != 6 && h[9] != 17) return 0;
    /* Only offset-zero fragments contain ports. Denying that fragment prevents
     * delivery of the whole protected datagram; later fragments cannot replace
     * its first four payload bytes. Preserve fragmented NAT return traffic. */
    if ((h[6] & 0x1f) || h[7]) return 0;
    uint8_t ports[4];
    if (total < ihl + 4 || pbuf_copy_partial(p, ports, 4, ihl) != 4) return discard(p);
    unsigned dst = ((unsigned)ports[2] << 8) | ports[3];
    /* AP clients may use the gateway DNS and admin HTTP(S). The STA uplink
     * remains blocked from all local management services. */
    if (inp == s_ap && dst == 53 && dest.addr == netif_ip4_addr(s_ap)->addr) return 0;
    if (inp == s_ap && (dst == 80 || dst == 443) &&
        dest.addr == netif_ip4_addr(s_ap)->addr) return 0;
    if ((h[9] == 6 && (dst == 80 || dst == 443 || dst == 53)) ||
        (h[9] == 17 && (dst == 53 || dst == 5353 || dst == 32768 || dst == 32769)))
        return discard(p);
    return 0;
}

/* The dongle currently routes IPv4 only. Do not expose a second management
 * path if a dependency enables IPv6 in an existing sdkconfig. */
int meshvpn_hook_ip6_input(struct pbuf *p, struct netif *inp)
{
    (void)inp;
    if (!p) return 0;
    return discard(p);
}
