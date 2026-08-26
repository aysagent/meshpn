#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool host_ready;      /**< USB host has configured the device */
    bool can_xmit;        /**< USB IN endpoint is ready to take a frame right now */
    uint32_t tx_ok;
    uint32_t tx_retried;  /**< frames that needed at least one retry */
    uint32_t tx_dropped;  /**< frames given up on because USB stayed busy */
    uint32_t tx_no_host;  /**< frames dropped because no host is attached */
    uint32_t tx_timeout;
    uint32_t tx_bytes;
    uint16_t tx_max_len;
    uint16_t tx_queue_depth;
} meshvpn_usb_stats_t;

esp_err_t meshvpn_usb_init(void);
const char *meshvpn_usb_profile_name(void);

/**
 * Replace the USB transmit path installed by iot_bridge.
 *
 * The bridge sends every frame with tinyusb_net_send_sync(..., portMAX_DELAY)
 * and drops it outright when the NCM/ECM IN endpoint is still busy with the
 * previous frame. That is fatal for anything bigger than a single packet (the
 * web UI never gets through) and the infinite timeout can wedge the whole
 * TCP/IP thread. Phase 8: bounded async queue + worker retry on CPU1.
 */
esp_err_t meshvpn_usb_attach_netif(esp_netif_t *netif);

void meshvpn_usb_get_stats(meshvpn_usb_stats_t *out);

#ifdef __cplusplus
}
#endif
