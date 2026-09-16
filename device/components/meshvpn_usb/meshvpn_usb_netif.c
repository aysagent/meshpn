/*
 * Project-owned USB Ethernet netif for ESP32-P4.
 *
 * The layout follows the public esp_netif custom-stack contract and the
 * Apache-2.0 iot_bridge USB netif implementation. We keep it here because
 * iot_bridge 1.1.0 intentionally gates its USB Kconfig/source to S2/S3 while
 * esp_tinyusb supports the P4 High-Speed device controller.
 */
#include "meshvpn_usb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif_net_stack.h"
#include "lwip/etharp.h"
#include "lwip/ethip6.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/snmp.h"
#include "sdkconfig.h"
#include "tinyusb.h"
#include "tinyusb_net.h"

static const char *TAG = "meshvpn_usb_netif";
static esp_netif_t *s_usb_netif;

#if CONFIG_TINYUSB_NET_MODE_NCM && CONFIG_TINYUSB_CDC_ENABLED && CONFIG_TINYUSB_CDC_COUNT == 1
/* Keep the NCM identity distinct from the ESP32-S3/default esp_tinyusb
 * identity. macOS keys USB class state by VID/PID/serial; the component's
 * default serial is the literal "123456" on every board. The final string is
 * also installed before the controller can enumerate, avoiding a brief empty
 * NCM MAC descriptor while tinyusb_net_init() catches up. */
static const char s_usb_lang[] = { 0x09, 0x04 };
static char s_usb_serial[13];
static char s_usb_mac[13];
static const char *s_usb_strings[] = {
    s_usb_lang,
    "MeshPN",
    "MeshPN ESP32-P4 HS NCM",
    s_usb_serial,
    "MeshPN CDC",
    "MeshPN NCM",
    s_usb_mac,
};
#endif

/* esp_netif's public custom-stack ABI uses this two-callback layout. */
typedef struct {
    err_t (*init_fn)(struct netif *);
    void (*input_fn)(void *netif, void *buffer, size_t len, void *eb);
} meshvpn_usb_netstack_config_t;

static esp_err_t bootstrap_transmit(void *h, void *buffer, size_t len)
{
    (void)h;
    (void)buffer;
    (void)len;
    return ESP_ERR_INVALID_STATE;
}

static esp_err_t bootstrap_transmit_wrap(void *h, void *buffer, size_t len,
                                         void *netstack_buffer)
{
    (void)netstack_buffer;
    return bootstrap_transmit(h, buffer, len);
}

static void free_rx_buffer(void *h, void *buffer)
{
    (void)h;
    free(buffer);
}

static void low_level_init(struct netif *netif)
{
    netif->hwaddr_len = ETH_HWADDR_LEN;
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
#if LWIP_IGMP
    netif->flags |= NETIF_FLAG_IGMP;
#endif
#if LWIP_IPV6 && LWIP_IPV6_MLD
    netif->flags |= NETIF_FLAG_MLD6;
#endif
}

static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
    esp_netif_t *esp_netif = esp_netif_get_handle_from_netif_impl(netif);
    if (!esp_netif) return ERR_IF;

    struct pbuf *frame = p;
    if (p->next) {
        frame = pbuf_alloc(PBUF_RAW_TX, p->tot_len, PBUF_RAM);
        if (!frame) return ERR_MEM;
        if (pbuf_copy(frame, p) != ERR_OK) {
            pbuf_free(frame);
            return ERR_MEM;
        }
    }

    esp_err_t err = esp_netif_transmit(esp_netif, frame->payload, frame->len);
    if (frame != p) pbuf_free(frame);
    if (err == ESP_OK) return ERR_OK;
    if (err == ESP_ERR_NO_MEM) return ERR_MEM;
    if (err == ESP_ERR_INVALID_ARG) return ERR_ARG;
    return ERR_IF;
}

static void usb_netif_input(void *h, void *buffer, size_t len, void *l2_buffer)
{
    struct netif *netif = h;
    esp_netif_t *esp_netif = esp_netif_get_handle_from_netif_impl(netif);
    if (!buffer || !netif_is_up(netif)) {
        if (l2_buffer && esp_netif) esp_netif_free_rx_buffer(esp_netif, l2_buffer);
        return;
    }

#if CONFIG_LWIP_L2_TO_L3_COPY
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
    if (!p || pbuf_take(p, buffer, len) != ERR_OK) {
        if (p) pbuf_free(p);
        if (l2_buffer && esp_netif) esp_netif_free_rx_buffer(esp_netif, l2_buffer);
        return;
    }
    if (l2_buffer && esp_netif) esp_netif_free_rx_buffer(esp_netif, l2_buffer);
#else
    struct pbuf *p = esp_pbuf_allocate(esp_netif, buffer, len, l2_buffer);
    if (!p) {
        if (l2_buffer && esp_netif) esp_netif_free_rx_buffer(esp_netif, l2_buffer);
        return;
    }
#endif

    if (netif->input(p, netif) != ERR_OK) pbuf_free(p);
}

static err_t usb_netif_init(struct netif *netif)
{
    if (!netif) return ERR_ARG;
#if LWIP_NETIF_HOSTNAME
    if (esp_netif_get_hostname(esp_netif_get_handle_from_netif_impl(netif),
                               &netif->hostname) != ESP_OK) {
        netif->hostname = CONFIG_LWIP_LOCAL_HOSTNAME;
    }
#endif
    NETIF_INIT_SNMP(netif, snmp_ifType_ethernet_csmacd, 100);
    netif->output = etharp_output;
#if LWIP_IPV6
    netif->output_ip6 = ethip6_output;
#endif
    netif->name[0] = 'u';
    netif->name[1] = 's';
    netif->linkoutput = low_level_output;
    low_level_init(netif);
    return ERR_OK;
}

static esp_err_t usb_recv(void *buffer, uint16_t len, void *ctx)
{
    (void)ctx;
    if (!s_usb_netif) return ESP_ERR_INVALID_STATE;
    return esp_netif_receive(s_usb_netif, buffer, len, NULL);
}

esp_netif_t *meshvpn_usb_create_netif(uint32_t ip_addr, uint32_t netmask,
                                     uint32_t gateway, const uint8_t mac[6])
{
    static const esp_netif_driver_ifconfig_t bootstrap_driver = {
        .handle = "USB",
        .transmit = bootstrap_transmit,
        .transmit_wrap = bootstrap_transmit_wrap,
        .driver_free_rx_buffer = free_rx_buffer,
    };
    static const meshvpn_usb_netstack_config_t netstack = {
        .init_fn = usb_netif_init,
        .input_fn = usb_netif_input,
    };
    static const esp_netif_inherent_config_t inherent = {
        .flags = ESP_NETIF_DHCP_SERVER | ESP_NETIF_FLAG_AUTOUP |
                 ESP_NETIF_FLAG_GARP | ESP_NETIF_FLAG_EVENT_IP_MODIFIED,
        .get_ip_event = IP_EVENT_STA_GOT_IP,
        .lost_ip_event = IP_EVENT_STA_LOST_IP,
        .if_key = "USB_DEF",
        .if_desc = "usb",
    };
    const esp_netif_config_t config = {
        .base = &inherent,
        .driver = &bootstrap_driver,
        .stack = (const esp_netif_netstack_config_t *)&netstack,
    };

    esp_netif_t *netif = esp_netif_new(&config);
    if (!netif) return NULL;
    esp_netif_ip_info_t ip_info = {
        .ip.addr = ip_addr,
        .netmask.addr = netmask,
        .gw.addr = gateway,
    };
    esp_netif_dhcps_stop(netif);
    uint8_t writable_mac[6];
    if (mac) memcpy(writable_mac, mac, sizeof(writable_mac));
    if (esp_netif_set_ip_info(netif, &ip_info) != ESP_OK ||
        (mac && esp_netif_set_mac(netif, writable_mac) != ESP_OK)) {
        esp_netif_destroy(netif);
        return NULL;
    }

    /* ESP_NETIF_FLAG_AUTOUP makes this manual start initialize and bring up
     * the lwIP netif. Without it RX is discarded and DHCP/NAPT stay invalid.
     * iot_bridge's private helper instead calls esp_netif_up() explicitly. */
    esp_netif_action_start(netif, NULL, 0, NULL);
    return netif;
}

esp_err_t meshvpn_usb_start_device(esp_netif_t *netif)
{
    if (!netif || s_usb_netif) return ESP_ERR_INVALID_STATE;
    s_usb_netif = netif;

    tinyusb_net_config_t net_cfg = {.on_recv_callback = usb_recv};
    esp_err_t err = esp_read_mac(net_cfg.mac_addr, ESP_MAC_ETH);
    if (err != ESP_OK) {
        s_usb_netif = NULL;
        return err;
    }

    tinyusb_config_t tusb_cfg = {.external_phy = false};
#if CONFIG_TINYUSB_NET_MODE_NCM && CONFIG_TINYUSB_CDC_ENABLED && CONFIG_TINYUSB_CDC_COUNT == 1
    snprintf(s_usb_serial, sizeof(s_usb_serial), "%02X%02X%02X%02X%02X%02X",
             (unsigned)net_cfg.mac_addr[0], (unsigned)net_cfg.mac_addr[1],
             (unsigned)net_cfg.mac_addr[2], (unsigned)net_cfg.mac_addr[3],
             (unsigned)net_cfg.mac_addr[4], (unsigned)net_cfg.mac_addr[5]);
    memcpy(s_usb_mac, s_usb_serial, sizeof(s_usb_mac));
    tusb_cfg.string_descriptor = s_usb_strings;
    tusb_cfg.string_descriptor_count = (int)(sizeof(s_usb_strings) / sizeof(s_usb_strings[0]));
#endif

    err = tinyusb_driver_install(&tusb_cfg);
    bool driver_installed = err == ESP_OK;
    if (err == ESP_OK) {
        err = tinyusb_net_init(TINYUSB_USBDEV_0, &net_cfg);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "USB device start failed: %s", esp_err_to_name(err));
        if (driver_installed) tinyusb_driver_uninstall();
        s_usb_netif = NULL;
        return err;
    }

    ESP_LOGI(TAG, "USB netif started on %s controller; serial=%02X%02X%02X%02X%02X%02X",
#if TUD_OPT_HIGH_SPEED
             "High-Speed",
#else
             "Full-Speed",
#endif
             (unsigned)net_cfg.mac_addr[0], (unsigned)net_cfg.mac_addr[1],
             (unsigned)net_cfg.mac_addr[2], (unsigned)net_cfg.mac_addr[3],
             (unsigned)net_cfg.mac_addr[4], (unsigned)net_cfg.mac_addr[5]
    );
    return ESP_OK;
}
