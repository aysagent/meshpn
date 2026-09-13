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
    bool ncm_double_buffer_configured; /**< init accepted; not register readback */
    uint8_t ncm_in_ep;    /**< experiment endpoint address, zero when disabled */
    uint32_t tx_ok;
    uint32_t tx_retried;  /**< successfully accepted frames that needed a retry */
    uint32_t tx_dropped;  /**< failed frames, excluding timeout and initial no-host */
    uint32_t tx_no_host;  /**< frames dropped because no host is attached */
    uint32_t tx_timeout;
    uint32_t tx_bytes;
    uint16_t tx_max_len;
    uint32_t tx_calls;    /**< completed sync calls; in queue mode worker only */
    uint32_t tx_attempts; /**< tinyusb_net_send_sync calls, including retries */
    uint32_t tx_busy;     /**< attempts rejected by can_xmit in TinyUSB task */
    /* Disjoint breakdown of tx_dropped; retain historical counter semantics. */
    uint32_t tx_busy_exhausted;
    uint32_t tx_no_mem;
    uint32_t tx_invalid_state;
    uint32_t tx_other_error;
    uint32_t tx_attempts_max; /**< maximum attempts per completed call */
    /* Whole transmit-call elapsed time, not USB bus completion latency.
     * Four disjoint buckets, including failures and initial no-host. */
    uint64_t tx_wait_us;
    uint64_t tx_wait_max_us;
    uint32_t tx_wait_le_1ms;
    uint32_t tx_wait_1_5ms;
    uint32_t tx_wait_5_25ms;
    uint32_t tx_wait_gt_25ms;
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
 * TCP/IP thread. Queue mode copies frames to an owned PSRAM pool and calls the
 * retrying sync transport from one worker. Queue rejections are separate from
 * the sync-send counters above. Startup allocation failure uses sync fallback.
 */
esp_err_t meshvpn_usb_attach_netif(esp_netif_t *netif);

void meshvpn_usb_get_stats(meshvpn_usb_stats_t *out);

#ifdef __cplusplus
}
#endif
