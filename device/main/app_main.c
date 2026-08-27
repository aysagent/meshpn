#include <inttypes.h>
#include <stdio.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "meshvpn_board.h"
#include "meshvpn_config.h"
#include "meshvpn_datapath.h"
#include "meshvpn_dns_proxy.h"
#include "meshvpn_log.h"
#include "meshvpn_net.h"
#include "meshvpn_routing.h"
#include "meshvpn_storage.h"
#include "meshvpn_usb.h"
#include "meshvpn_vpn.h"
#include "meshvpn_wifi.h"
#include "meshvpn_web.h"
#include "sdkconfig.h"

static const char *TAG = "meshvpn";

#define FACTORY_RESET_HOLD_MS 5000
#define FACTORY_RESET_GRACE_MS 20000
#define USB_STABLE_MS 3000

static void meshvpn_wifi_start_saved(void)
{
    meshvpn_wifi_creds_t creds;
    meshvpn_config_load_wifi(&creds);
    if (!meshvpn_config_wifi_is_configured()) {
        return;
    }

    ESP_LOGI(TAG, "WiFi reconnect: %s", creds.ssid);
    meshvpn_wifi_apply_bus_power_limits();
    meshvpn_wifi_start_sta(&creds);
    meshvpn_net_ensure_napt();
}

/* SPIFFS/VPN compete with USB enumeration — defer until NCM is stable. */
static void meshvpn_background_init_task(void *arg)
{
    (void)arg;

    meshvpn_wifi_start_saved();

    int stable_ms = 0;
    while (stable_ms < USB_STABLE_MS) {
        meshvpn_usb_stats_t us;
        meshvpn_usb_get_stats(&us);
        if (us.host_ready) {
            stable_ms += 200;
        } else {
            stable_ms = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    ESP_LOGI(TAG, "USB stable — background init (SPIFFS / VPN)");

    if (meshvpn_storage_init() != ESP_OK) {
        ESP_LOGW(TAG, "SPIFFS unavailable — VPN cert upload disabled until reflash");
    }

    if (meshvpn_vpn_init() != ESP_OK) {
        ESP_LOGW(TAG, "VPN init failed");
        vTaskDelete(NULL);
        return;
    }
    meshvpn_vpn_set_inject(meshvpn_net_inject_ipv4_to_lan);
    if (meshvpn_datapath_init() != ESP_OK) {
        ESP_LOGW(TAG, "VPN datapath init failed");
        vTaskDelete(NULL);
        return;
    }

    meshvpn_vpn_config_t vpn_cfg;
    meshvpn_config_load_vpn(&vpn_cfg);
    meshvpn_datapath_ensure_init();
    meshvpn_vpn_apply_config(&vpn_cfg);

    vTaskDelete(NULL);
}

/* GPIO0 doubles as the download-mode strapping pin, so it cannot be sampled at
 * power-on. Watch it continuously instead: holding BOOT for five seconds while
 * running wipes the config, which is the only recovery path once the device is
 * flashed with the NCM firmware (no serial console, no WiFi credentials). */
static void factory_reset_watch_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(FACTORY_RESET_GRACE_MS));
    ESP_LOGI(TAG, "BOOT button armed (hold %d ms for factory reset)", FACTORY_RESET_HOLD_MS);

    int held_ms = 0;

    while (true) {
        if (meshvpn_board_boot_pressed()) {
            held_ms += 100;
            if (held_ms >= FACTORY_RESET_HOLD_MS) {
                ESP_LOGW(TAG, "BOOT held %d ms — factory reset", held_ms);
                meshvpn_config_factory_reset();
                vTaskDelay(pdMS_TO_TICKS(200));
                esp_restart();
            }
        } else {
            held_ms = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

void app_main(void)
{
    esp_log_level_set("*", ESP_LOG_INFO);
    ESP_ERROR_CHECK(meshvpn_log_init());
    ESP_LOGI(TAG, "MeshVPN device starting");

    ESP_ERROR_CHECK(meshvpn_board_init());
    ESP_ERROR_CHECK(meshvpn_config_init());
    meshvpn_log_report_boot(meshvpn_config_bump_boot_count());

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK(meshvpn_net_init());
    ESP_ERROR_CHECK(meshvpn_usb_init());
    ESP_ERROR_CHECK(meshvpn_routing_init());

    /* Handlers must be in place before the bridge starts the WiFi driver. */
    ESP_ERROR_CHECK(meshvpn_wifi_init());
    meshvpn_wifi_restore_saved();
    ESP_ERROR_CHECK(meshvpn_net_start_bridge());
    /* Deliberately not fatal: DNS proxy must never turn into a boot loop. */
    if (meshvpn_dns_proxy_init() != ESP_OK) {
        ESP_LOGW(TAG, "DNS proxy failed to start — USB clients may have no DNS");
    }

    if (!meshvpn_config_wifi_is_configured()) {
        ESP_LOGW(TAG, "WiFi not configured — open http://192.168.7.1/login over USB");
    }

    ESP_ERROR_CHECK(meshvpn_web_start());

    xTaskCreate(meshvpn_background_init_task, "bg_init", 8192, NULL, 3, NULL);

    xTaskCreate(factory_reset_watch_task, "boot_btn", 3072, NULL, 4, NULL);

    bool led = false;
    int tick = 0;

    while (true) {
        meshvpn_wifi_status_t ws;
        meshvpn_wifi_get_status(&ws);

        /* Solid LED = uplink online, blinking = no uplink yet. */
        if (ws.sta_connected) {
            meshvpn_board_led_set(true);
        } else {
            led = !led;
            meshvpn_board_led_set(led);
        }

        meshvpn_usb_stats_t us;
        meshvpn_usb_get_stats(&us);

        /* NAPT only here — LAN DHCP is refreshed on STA/AP/bridge DNS events. */
        if (us.host_ready || tick % 15 == 0) {
            meshvpn_net_ensure_napt();
        }

        if (tick % 30 == 0) {
            meshvpn_net_log_state();
            meshvpn_net_status_t ns;
            meshvpn_net_get_status(&ns);
            ESP_LOGI(TAG, "uplink %s ssid=%.32s ip=%s reason=%u napt usb=%d ap=%d def=%s",
                     ws.sta_connected ? "up" : "down", ws.ssid, ws.ip, ws.disconnect_reason,
                     ns.usb_napt, ns.ap_napt, ns.default_ifkey);
            meshvpn_dns_stats_t ds;
            meshvpn_dns_get_stats(&ds);
            ESP_LOGI(TAG, "dns q=%" PRIu32 " hij=%" PRIu32 " cap=%" PRIu32 " fwd=%" PRIu32 " fail=%" PRIu32,
                     ds.queries, ds.hijacked, ds.captive, ds.forwarded, ds.forward_fail);
            ESP_LOGI(TAG, "usb host=%d xmit=%d tx=%" PRIu32 " retry=%" PRIu32
                          " drop=%" PRIu32 " nohost=%" PRIu32 " max=%u",
                     us.host_ready, us.can_xmit, us.tx_ok, us.tx_retried,
                     us.tx_dropped, us.tx_no_host, us.tx_max_len);
        }

        tick++;
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
