#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include "meshvpn_net_dhcp.h"
#include "dhcpserver/dhcpserver.h"

struct esp_netif_obj {
    esp_netif_dhcp_status_t state;
    uint32_t ip, dns, lease;
    uint8_t router, offer_dns;
    unsigned starts, stops, writes, dns_writes;
    bool client_lease;
    int fail;
};
enum { FAIL_IP=1, FAIL_STATUS, FAIL_GET, FAIL_STOP, FAIL_SET, FAIL_DNS, FAIL_START };
esp_err_t esp_netif_get_ip_info(esp_netif_t *n, esp_netif_ip_info_t *ip)
{ ip->ip.addr=n->ip; return n->fail==FAIL_IP?ESP_FAIL:ESP_OK; }
esp_err_t esp_netif_dhcps_get_status(esp_netif_t *n, esp_netif_dhcp_status_t *state)
{ *state=n->state; return n->fail==FAIL_STATUS?ESP_FAIL:ESP_OK; }
esp_err_t esp_netif_dhcps_stop(esp_netif_t *n)
{
    if(n->fail==FAIL_STOP)return ESP_FAIL;
    assert(n->state==ESP_NETIF_DHCP_STARTED);
    n->stops++;n->state=ESP_NETIF_DHCP_STOPPED;
    n->client_lease=false; /* IDF dhcps_stop frees plist. */
    return ESP_OK;
}
esp_err_t esp_netif_dhcps_start(esp_netif_t *n)
{
    if(n->fail==FAIL_START)return ESP_FAIL;
    assert(n->state!=ESP_NETIF_DHCP_STARTED);
    n->starts++;n->state=ESP_NETIF_DHCP_STARTED;return ESP_OK;
}
esp_err_t esp_netif_dhcps_option(esp_netif_t *n,int op,int id,void *v,uint32_t size)
{
    assert(size==(id==ESP_NETIF_IP_ADDRESS_LEASE_TIME?sizeof(uint32_t):sizeof(uint8_t)));
    if(op==ESP_NETIF_OP_GET) {
        assert(n->state==ESP_NETIF_DHCP_STARTED);
        if(n->fail==FAIL_GET)return ESP_FAIL;
        if(id==ESP_NETIF_IP_ADDRESS_LEASE_TIME)*(uint32_t *)v=n->lease;
        else *(uint8_t *)v=id==ESP_NETIF_DOMAIN_NAME_SERVER?!!(n->offer_dns&OFFER_DNS):!!n->router;
    } else {
        assert(op==ESP_NETIF_OP_SET&&n->state!=ESP_NETIF_DHCP_STARTED);
        if(n->fail==FAIL_SET)return ESP_FAIL;
        n->writes++;
        if(id==ESP_NETIF_IP_ADDRESS_LEASE_TIME)n->lease=*(uint32_t *)v;
        else if(id==ESP_NETIF_DOMAIN_NAME_SERVER)n->offer_dns=*(uint8_t *)v;
        else n->router=*(uint8_t *)v;
    }
    return ESP_OK;
}
esp_err_t esp_netif_set_dns_info(esp_netif_t *n,int type,esp_netif_dns_info_t *dns)
{
    assert(type==ESP_NETIF_DNS_MAIN&&dns->ip.type==IPADDR_TYPE_V4);
    if(n->fail==FAIL_DNS)return ESP_FAIL;
    n->dns=dns->ip.u_addr.ip4.addr;n->dns_writes++;return ESP_OK;
}
static esp_netif_t configured(void)
{
    return (esp_netif_t){.state=ESP_NETIF_DHCP_STARTED,.ip=7,.dns=7,
        .lease=2,.router=1,.offer_dns=OFFER_DNS,.client_lease=true};
}
int main(void)
{
    assert(meshvpn_net_apply_lan_dhcp(NULL)==ESP_ERR_INVALID_ARG);
    /* USB and AP startup, including options that differ from bridge defaults. */
    for(int state=ESP_NETIF_DHCP_INIT;state<=ESP_NETIF_DHCP_STOPPED;state++) {
        esp_netif_t n={.state=state,.ip=7,.lease=120};
        assert(meshvpn_net_apply_lan_dhcp(&n)==ESP_OK);
        assert(n.stops==(state==ESP_NETIF_DHCP_STARTED?1u:0u));
        assert(n.starts==1&&n.writes==3&&n.lease==2&&n.dns==7&&n.offer_dns==OFFER_DNS&&n.router==1);
    }
    /* First IP assignment followed by AP_START, STA_GOT_IP and repeated bridge
     * DNS updates must retain the entry that IDF needs to ACK a renewal. */
    esp_netif_t usb=configured(),ap=configured();ap.ip=4;
    for(int i=0;i<20;i++) {
        usb.dns=ap.dns=123; /* bridge temporarily advertises uplink DNS */
        assert(meshvpn_net_apply_lan_dhcp(&usb)==ESP_OK);
        assert(meshvpn_net_apply_lan_dhcp(&ap)==ESP_OK);
        assert(usb.client_lease&&ap.client_lease);
        assert(usb.dns==7&&ap.dns==4);
    }
    assert(!usb.stops&&!usb.starts&&!usb.writes&&!ap.stops&&!ap.starts&&!ap.writes);
    /* A genuine subnet move already stops DHCP; apply must resume on new IP. */
    assert(esp_netif_dhcps_stop(&usb)==ESP_OK);usb.ip=8;
    assert(meshvpn_net_apply_lan_dhcp(&usb)==ESP_OK);
    assert(usb.stops==1&&usb.starts==1&&usb.dns==8);
    /* Each real option difference still triggers setup, not only lease time. */
    for(int which=0;which<3;which++) {
        esp_netif_t n=configured();
        if(which==0)n.lease=120;else if(which==1)n.router=0;else n.offer_dns=0;
        assert(meshvpn_net_apply_lan_dhcp(&n)==ESP_OK);
        assert(n.stops==1&&n.starts==1&&n.lease==2&&n.router==1&&n.offer_dns==OFFER_DNS);
    }
    for(int failure=FAIL_IP;failure<=FAIL_START;failure++) {
        esp_netif_t n=configured();n.fail=failure;
        if(failure==FAIL_STOP)n.lease=120;
        if(failure==FAIL_SET||failure==FAIL_START)n.state=ESP_NETIF_DHCP_STOPPED;
        assert(meshvpn_net_apply_lan_dhcp(&n)==ESP_FAIL);
        assert(!n.stops&&!n.starts); /* no destructive restart after failed reads */
    }
    puts("LAN DHCP lease-preserving refresh tests passed");
}
