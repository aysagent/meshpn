#include "meshvpn_wifi.h"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

static const char *TAG = "meshvpn_wifi";
enum { CMD_START, CMD_RELOAD, CMD_SELECT, CMD_PAUSE, CMD_SCAN };
typedef struct { int kind; uint32_t id; } command_t;
static QueueHandle_t s_commands;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static meshvpn_wifi_status_t s_status;
static wifi_ap_record_t s_scan[32];
static uint16_t s_scan_count;
static bool s_scan_done;
static bool s_disconnected;
static bool s_got_ip;

static void state(const char *name)
{
    portENTER_CRITICAL(&s_lock);
    snprintf(s_status.state, sizeof(s_status.state), "%s", name);
    portEXIT_CRITICAL(&s_lock);
}

static esp_err_t command(int kind, uint32_t id)
{
    command_t cmd = {kind, id};
    return s_commands && xQueueSend(s_commands, &cmd, 0) == pdTRUE ? ESP_OK : ESP_ERR_TIMEOUT;
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP &&
        ((ip_event_got_ip_t *)data)->esp_netif != esp_netif_get_handle_from_ifkey("WIFI_STA_DEF")) return;
    portENTER_CRITICAL(&s_lock);
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_status.disconnect_reason = ((wifi_event_sta_disconnected_t *)data)->reason;
        s_status.sta_connected = false;
        s_status.ip[0] = 0;
        s_disconnected = true;
        s_got_ip = false;
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_SCAN_DONE) {
        s_scan_done = true;
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = data;
        snprintf(s_status.ip, sizeof(s_status.ip), IPSTR, IP2STR(&ev->ip_info.ip));
        s_status.sta_connected = true;
        s_status.disconnect_reason = 0;
        s_got_ip = true;
        s_disconnected = false;
    } else if (base == IP_EVENT && id == IP_EVENT_STA_LOST_IP) {
        s_status.sta_connected = false;
        s_status.ip[0] = 0;
        s_disconnected = true;
    }
    portEXIT_CRITICAL(&s_lock);
}

/* One task owns all connect/disconnect/scan operations. iot_bridge reconnect
 * is disabled in sdkconfig; it still owns netif/DHCP lifecycle. */
static void manager(void *arg)
{
    (void)arg;
    meshvpn_wifi_profiles_t *profiles = heap_caps_calloc(1, sizeof(*profiles), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    wifi_ap_record_t *records = heap_caps_calloc(32, sizeof(*records), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!profiles || !records) {
        free(profiles); free(records); state("out_of_memory"); vTaskDelete(NULL); return;
    }
    bool ready = false, paused = false, connecting = false, scanning = false;
    bool automatic_scan = false;
    bool scan_pending = false;
    uint32_t requested = 0, last_success = 0;
    uint32_t tried = 0;
    int64_t deadline = 0, next_attempt = 0;
    unsigned backoff = 2;

    for (;;) {
        command_t cmd;
        if (xQueueReceive(s_commands, &cmd, pdMS_TO_TICKS(100)) == pdTRUE) {
            if (cmd.kind == CMD_START || cmd.kind == CMD_RELOAD) {
                if (meshvpn_config_load_profiles(profiles) != ESP_OK) {
                    memset(profiles, 0, sizeof(*profiles));
                    state("config_error");
                }
                ready = true;
                tried = 0;
                next_attempt = 0;
                portENTER_CRITICAL(&s_lock);
                s_status.setup_mode = profiles->count == 0;
                uint32_t active = s_status.profile_id;
                portEXIT_CRITICAL(&s_lock);
                bool keep = false;
                for (unsigned i = 0; i < profiles->count; i++)
                    if (profiles->items[i].id == active && profiles->items[i].enabled) keep = true;
                if (!keep) {
                    esp_wifi_disconnect();
                    connecting = false;
                }
            } else if (cmd.kind == CMD_SELECT || cmd.kind == CMD_PAUSE) {
                paused = cmd.kind == CMD_PAUSE;
                requested = cmd.id;
                esp_wifi_scan_stop();
                scanning = false;
                esp_wifi_disconnect();
                connecting = false;
                tried = 0;
                next_attempt = esp_timer_get_time() + 500000;
                portENTER_CRITICAL(&s_lock);
                s_status.sta_connected = false;
                s_status.ip[0] = 0;
                s_status.paused = paused;
                s_status.scanning = false;
                portEXIT_CRITICAL(&s_lock);
                state(paused ? "paused" : "selecting");
            } else if (cmd.kind == CMD_SCAN) {
                /* Share an in-progress scan, or wait for association/DHCP. */
                scan_pending = !scanning;
            }
        }
        if (!ready) continue;

        bool disconnected, got_ip, scan_done, online;
        portENTER_CRITICAL(&s_lock);
        disconnected = s_disconnected; s_disconnected = false;
        got_ip = s_got_ip; s_got_ip = false;
        scan_done = s_scan_done; s_scan_done = false;
        online = s_status.sta_connected;
        s_status.scanning = scanning || scan_pending;
        portEXIT_CRITICAL(&s_lock);
        int64_t now = esp_timer_get_time();
        if (got_ip && !paused) {
            connecting = false;
            automatic_scan = false;
            backoff = 2;
            tried = 0;
            portENTER_CRITICAL(&s_lock);
            last_success = s_status.profile_id;
            portEXIT_CRITICAL(&s_lock);
            esp_wifi_set_ps(WIFI_PS_NONE);
            state("online");
        }
        if (disconnected) {
            connecting = false;
            next_attempt = now + 500000;
            if (!paused) state("retrying");
        }
        if (scan_done && scanning) {
            uint16_t count = 32;
            if (esp_wifi_scan_get_ap_records(&count, records) != ESP_OK) count = 0;
            portENTER_CRITICAL(&s_lock);
            memcpy(s_scan, records, count * sizeof(records[0]));
            s_scan_count = count;
            s_status.scanning = false;
            portEXIT_CRITICAL(&s_lock);
            scanning = false;
            if (automatic_scan) next_attempt = 0;
        }
        if ((connecting || scanning) && now >= deadline) {
            if (scanning) esp_wifi_scan_stop();
            if (connecting) esp_wifi_disconnect();
            scanning = connecting = false;
            next_attempt = now + 1000000;
            state("timeout");
        }
        if (scan_pending && !connecting && !scanning) {
            wifi_scan_config_t scan = {.show_hidden = true};
            esp_err_t err = esp_wifi_scan_start(&scan, false);
            if (err == ESP_OK) {
                scanning = true;
                automatic_scan = false;
                deadline = now + 15000000;
            } else ESP_LOGW(TAG, "Requested scan failed: %s", esp_err_to_name(err));
            scan_pending = false;
        }
        if (paused || online || connecting || scanning || now < next_attempt) continue;
        if (!profiles->count) { state("setup"); continue; }

        /* Start a scan at the beginning of an automatic round. */
        if (!tried && !requested && !automatic_scan) {
            wifi_scan_config_t scan = {.show_hidden = true};
            if (esp_wifi_scan_start(&scan, false) == ESP_OK) {
                scanning = automatic_scan = true;
                deadline = now + 15000000;
                state("scanning");
                continue;
            }
        }
        int best = -1, best_rssi = -128;
        for (unsigned i = 0; i < profiles->count; i++) {
            meshvpn_wifi_profile_t *p = &profiles->items[i];
            if (!p->enabled || (tried & (1u << i))) continue;
            int rssi = -128;
            portENTER_CRITICAL(&s_lock);
            for (unsigned j = 0; j < s_scan_count; j++) {
                if (!strcmp(p->ssid, (char *)s_scan[j].ssid) && s_scan[j].rssi > rssi)
                    rssi = s_scan[j].rssi;
            }
            portEXIT_CRITICAL(&s_lock);
            if (requested && p->id == requested) { best = i; break; }
            if (rssi == -128 && !p->hidden) continue;
            if (best < 0 || p->priority > profiles->items[best].priority ||
                (p->priority == profiles->items[best].priority &&
                 (rssi > best_rssi || (rssi == best_rssi && p->id == last_success)))) {
                best = i; best_rssi = rssi;
            }
        }
        requested = 0;
        if (best < 0) {
            tried = 0;
            automatic_scan = false;
            next_attempt = now + (int64_t)backoff * 1000000;
            if (backoff < 60) backoff = backoff * 2 > 60 ? 60 : backoff * 2;
            state("waiting_for_network");
            continue;
        }
        meshvpn_wifi_profile_t *p = &profiles->items[best];
        tried |= 1u << best;
        wifi_config_t cfg = {0};
        memcpy(cfg.sta.ssid, p->ssid, strlen(p->ssid));
        memcpy(cfg.sta.password, p->password, strlen(p->password));
        cfg.sta.threshold.authmode = p->security == 2 ? WIFI_AUTH_WPA3_PSK :
                                     p->security == 1 ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
        cfg.sta.pmf_cfg.capable = true;
        cfg.sta.pmf_cfg.required = p->security == 2;
        cfg.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
        esp_wifi_set_ps(WIFI_PS_NONE);
        esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT40);
        esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &cfg);
        if (err == ESP_OK) err = esp_wifi_connect();
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "profile %" PRIu32 " connect: %s", p->id, esp_err_to_name(err));
            next_attempt = now + 1000000;
            continue;
        }
        portENTER_CRITICAL(&s_lock);
        s_status.profile_id = p->id;
        snprintf(s_status.ssid, sizeof(s_status.ssid), "%s", p->ssid);
        portEXIT_CRITICAL(&s_lock);
        connecting = true;
        deadline = now + 15000000;
        state("connecting");
    }
}

esp_err_t meshvpn_wifi_init(void)
{
    s_commands = xQueueCreate(8, sizeof(command_t));
    if (!s_commands) return ESP_ERR_NO_MEM;
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID, on_event, NULL));
    return xTaskCreate(manager, "wifi_profiles", 4096, NULL, 4, NULL) == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}
esp_err_t meshvpn_wifi_start_manager(void)
{
    /* New connections must not persist a second driver-owned credential copy.
     * Historical driver flash data, if any, is removed by factory reset. */
    esp_err_t err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    return err == ESP_OK ? command(CMD_START, 0) : err;
}
esp_err_t meshvpn_wifi_select(uint32_t id) { return command(CMD_SELECT, id); }
esp_err_t meshvpn_wifi_reload(void) { return command(CMD_RELOAD, 0); }
esp_err_t meshvpn_wifi_connect(void) { return command(CMD_SELECT, 0); }
esp_err_t meshvpn_wifi_disconnect(void) { return command(CMD_PAUSE, 0); }
esp_err_t meshvpn_wifi_scan_start(void)
{
    return command(CMD_SCAN, 0);
}
bool meshvpn_wifi_scan_busy(void)
{
    portENTER_CRITICAL(&s_lock);
    bool busy = s_status.scanning;
    portEXIT_CRITICAL(&s_lock);
    return busy;
}
int meshvpn_wifi_scan_get_count(void)
{
    portENTER_CRITICAL(&s_lock);
    int n = s_scan_count;
    portEXIT_CRITICAL(&s_lock);
    return n;
}
esp_err_t meshvpn_wifi_scan_get_entry(int index, wifi_ap_record_t *rec)
{
    portENTER_CRITICAL(&s_lock);
    if (index < 0 || index >= s_scan_count) {
        portEXIT_CRITICAL(&s_lock);
        return ESP_ERR_INVALID_ARG;
    }
    *rec = s_scan[index];
    portEXIT_CRITICAL(&s_lock);
    return ESP_OK;
}
void meshvpn_wifi_get_status(meshvpn_wifi_status_t *status)
{
    portENTER_CRITICAL(&s_lock);
    *status = s_status;
    portEXIT_CRITICAL(&s_lock);
    wifi_ap_record_t ap;
    if (status->sta_connected && esp_wifi_sta_get_ap_info(&ap) == ESP_OK) status->rssi = ap.rssi;
}
