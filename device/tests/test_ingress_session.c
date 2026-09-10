#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "meshvpn_lwip_hooks.h"
#include "meshvpn_session.h"
#include "meshvpn_subnet.h"

struct netif *netif_list;
static int freed;
static uint32_t ip(unsigned a,unsigned b,unsigned c,unsigned d)
{
    uint8_t octets[]={a,b,c,d};uint32_t out;memcpy(&out,octets,4);return out;
}
int ip4_addr_isbroadcast(const ip4_addr_t *addr,const struct netif *n)
{
    (void)n;const uint8_t *b=(const void *)&addr->addr;
    return b[3]==255;
}
uint16_t pbuf_copy_partial(const struct pbuf *p,void *out,uint16_t len,uint16_t offset)
{
    uint16_t copied=0;
    while(p&&offset>=p->len){offset-=p->len;p=p->next;}
    while(p&&copied<len){
        uint16_t n=p->len-offset;if(n>len-copied)n=len-copied;
        memcpy((uint8_t *)out+copied,(uint8_t *)p->payload+offset,n);
        copied+=n;p=p->next;offset=0;
    }
    return copied;
}
void pbuf_free(struct pbuf *p){(void)p;freed++;}
static void check(struct netif *input,uint32_t dest,int proto,int port,int fragment,bool deny)
{
    uint8_t packet[40]={0x45,0,0,40};
    packet[9]=proto;memcpy(packet+16,&dest,4);
    packet[6]=fragment>>8;packet[7]=fragment;
    packet[22]=port>>8;packet[23]=port;
    /* Deliberately split in the middle of the IP header. */
    struct pbuf second={.tot_len=23,.len=23,.payload=packet+17};
    struct pbuf first={.tot_len=40,.len=17,.payload=packet,.next=&second};
    freed=0;
    assert(!!meshvpn_hook_ip4_input(&first,input)==deny);
    assert(freed==(deny?1:0));
}
int main(void)
{
    struct netif usb={.ip={ip(192,168,7,1)}},sta={.ip={ip(192,168,1,80)}},ap={.ip={ip(192,168,4,1)}};
    usb.next=&sta;sta.next=&ap;netif_list=&usb;meshvpn_net_set_usb_interface(&usb);
    meshvpn_net_set_ap_interface(&ap);
    check(&usb,usb.ip.addr,6,443,0,false);
    check(&sta,sta.ip.addr,6,443,0,true);
    check(&sta,usb.ip.addr,6,80,0,true); /* WiFi routing to USB address */
    check(&sta,sta.ip.addr,17,53,0,true);
    check(&sta,ip(192,168,1,255),17,53,0,true);
    check(&sta,ip(224,0,0,251),17,5353,0,true);
    check(&sta,sta.ip.addr,17,32769,0,true);
    check(&sta,sta.ip.addr,17,53123,0,false); /* upstream DNS response */
    check(&sta,sta.ip.addr,6,53000,0,false); /* NAT response */
    check(&sta,sta.ip.addr,17,53,0x2000,true); /* first fragment denied */
    check(&sta,sta.ip.addr,17,0,1,false); /* noninitial can't complete without first */
    check(&sta,ip(192,168,7,2),6,443,0,false); /* forwarded host destination */
    check(&ap,ap.ip.addr,17,53,0,false);
    check(&ap,ap.ip.addr,6,53,0,false);
    check(&ap,ap.ip.addr,6,80,0,false); /* AP clients may open HTTP admin */
    check(&ap,ap.ip.addr,6,443,0,false); /* AP clients may open HTTPS admin */
    check(&ap,ap.ip.addr,17,53,0x2000,false); /* fragmented DNS first packet */
    check(&ap,usb.ip.addr,17,53,0,true); /* AP DNS exception limited to AP gateway */
    check(&sta,ap.ip.addr,17,53,0,true); /* uplink cannot route to AP DNS */
    check(&sta,ap.ip.addr,6,53,0,true);
    check(&sta,ap.ip.addr,6,443,0,true); /* STA uplink remains denied */
    check(&ap,usb.ip.addr,6,80,0,true);
    check(&ap,sta.ip.addr,6,443,0,true);
    check(&ap,ip(224,0,0,251),17,5353,0,true);
    check(&ap,ap.ip.addr,17,32768,0,true);
    check(&ap,ap.ip.addr,17,32769,0,true);
    check(&ap,ip(255,255,255,255),17,67,0,false); /* DHCP discovery */
    check(&ap,ip(1,1,1,1),17,53,0,false); /* NAT with explicit upstream DNS */
    check(&ap,ip(1,1,1,1),6,443,0,false);
    check(&usb,ap.ip.addr,17,53,0,false);
    ap.ip.addr=ip(10,203,7,1);
    check(&ap,ap.ip.addr,17,53,0,false); /* exception follows subnet changes */
    check(&sta,ap.ip.addr,17,53,0,true);
    assert(meshvpn_net_ap_ip4_rx_count()>0);
    uint32_t selected=0;
    assert(meshvpn_subnets_overlap(0xc0a80401,0xffffff00,0xc0a80101,0xffff0000));
    assert(!meshvpn_subnets_overlap(0xc0a80401,0xffffff00,0xc0a80701,0xffffff00));
    assert(meshvpn_pick_lan_ip(0xc0a80401,0xffffff00,0xc0a80701,0xffffff00,&selected));
    assert(selected==0xc0a80801); /* don't collide with USB while moving AP */
    assert(meshvpn_pick_lan_ip(0xc0a80101,0xffff0000,0xc0a80401,0xffffff00,&selected));
    assert(selected==0x0acb0701); /* /16 uplink: move both LANs out of 192.168 */
    uint32_t other=selected;
    assert(meshvpn_pick_lan_ip(0xc0a80101,0xffff0000,other,0xffffff00,&selected));
    assert(selected==0x0acb0801);
    assert(meshvpn_pick_lan_ip(0x0a000001,0xff000000,0xc0a80701,0xffffff00,&selected));
    assert(selected==0xc0a80801); /* /8 uplink */
    assert(!meshvpn_pick_lan_ip(0x01020304,0,0,0,&selected)); /* /0: no free subnet */
    assert(!meshvpn_pick_lan_ip(0,0,0,0,NULL));
    struct pbuf tiny={.len=0,.tot_len=0};freed=0;
    assert(meshvpn_hook_ip4_input(&tiny,&sta)==1&&freed==1);
    assert(meshvpn_hook_ip6_input(&tiny,&usb)==1);
    const char *token="0123456789abcdef0123456789abcdef";
    const char *auth="Bearer 0123456789abcdef0123456789abcdef";
    assert(!meshvpn_session_valid("","Bearer ",0,0,1));
    assert(!meshvpn_session_valid(token,"Bearer ",0,0,1));
    assert(meshvpn_session_valid(token,auth,0,0,1));
    assert(!meshvpn_session_valid(token,"Bearer 0123456789abcdef0123456789abcdee",0,0,1));
    assert(!meshvpn_session_valid(token,auth,0,0,1800000000LL));
    assert(!meshvpn_session_valid(token,auth,0,28800000000LL,28800000000LL));
    assert(!meshvpn_session_valid(token,auth,5,5,4));
    puts("Ingress isolation and session tests passed");
}
