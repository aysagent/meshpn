#include "meshvpn_net_dhcp.h"

#include <stdbool.h>
#include "dhcpserver/dhcpserver.h"

esp_err_t meshvpn_net_apply_lan_dhcp(esp_netif_t *netif)
{
    if (!netif) return ESP_ERR_INVALID_ARG;
    esp_netif_ip_info_t ip;
    esp_netif_dhcp_status_t state;
    esp_err_t err = esp_netif_get_ip_info(netif, &ip);
    if (err != ESP_OK) return err;
    err = esp_netif_dhcps_get_status(netif, &state);
    if (err != ESP_OK) return err;

    bool running = state == ESP_NETIF_DHCP_STARTED;
    if (running) {
        uint8_t router = 0, dns = 0;
        uint32_t lease = 0;
        /* GET returns booleans, not the OFFER_* bit masks accepted by SET.
         * A failed read must not trigger a speculative destructive restart. */
        err = esp_netif_dhcps_option(netif, ESP_NETIF_OP_GET,
                                    ESP_NETIF_ROUTER_SOLICITATION_ADDRESS, &router, sizeof(router));
        if (err != ESP_OK) return err;
        err = esp_netif_dhcps_option(netif, ESP_NETIF_OP_GET,
                                    ESP_NETIF_DOMAIN_NAME_SERVER, &dns, sizeof(dns));
        if (err != ESP_OK) return err;
        err = esp_netif_dhcps_option(netif, ESP_NETIF_OP_GET,
                                    ESP_NETIF_IP_ADDRESS_LEASE_TIME, &lease, sizeof(lease));
        if (err != ESP_OK) return err;
        if (router != 1 || dns != 1 || lease != 2) {
            /* Initial setup or a real DHCP option change requires STOP for SET.
             * Never do this merely because the uplink DNS/address changed. */
            err = esp_netif_dhcps_stop(netif);
            if (err != ESP_OK) return err;
            running = false;
        }
    }

    if (!running) {
        uint8_t router = 1;
        dhcps_offer_t offer_dns = OFFER_DNS;
        uint32_t lease_minutes = 2;
        err = esp_netif_dhcps_option(netif, ESP_NETIF_OP_SET,
                                    ESP_NETIF_ROUTER_SOLICITATION_ADDRESS, &router, sizeof(router));
        if (err == ESP_OK) err = esp_netif_dhcps_option(netif, ESP_NETIF_OP_SET,
                                    ESP_NETIF_DOMAIN_NAME_SERVER, &offer_dns, sizeof(offer_dns));
        if (err == ESP_OK) err = esp_netif_dhcps_option(netif, ESP_NETIF_OP_SET,
                                    ESP_NETIF_IP_ADDRESS_LEASE_TIME, &lease_minutes, sizeof(lease_minutes));
        if (err != ESP_OK) return err;
    }

    esp_netif_dns_info_t dns = {
        .ip = {.type = IPADDR_TYPE_V4, .u_addr = {.ip4 = ip.ip}},
    };
    /* esp_netif_set_dns_info updates the live DHCP resolver without stop/start.
     * dhcps_stop frees the lease table; first renew would otherwise receive NAK. */
    err = esp_netif_set_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns);
    if (err != ESP_OK) return err;
    return running ? ESP_OK : esp_netif_dhcps_start(netif);
}
