/*
 * meshvpn_vpn — clean-vpn client (tls / transparent-tls / boring-tls).
 */

#include "meshvpn_vpn.h"
#include "meshvpn_vpn_internal.h"
#include "meshvpn_vpn_protocol.h"
#include "meshvpn_tls_exporter.h"
#include "meshvpn_storage.h"
#include "meshvpn_wifi.h"

#include <string.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdkconfig.h"

static const char *TAG = "meshvpn_vpn";

static meshvpn_vpn_config_t s_cfg;
static meshvpn_vpn_status_t s_status;
static meshvpn_vpn_inject_fn s_inject;
static TaskHandle_t s_worker;
static volatile bool s_worker_run;
static SemaphoreHandle_t s_lock;
static int s_tunnel_fd = -1;
static esp_tls_t *s_tls;

typedef enum {
    MESHVPN_TUNNEL_NONE = 0,
    MESHVPN_TUNNEL_RAW,
    MESHVPN_TUNNEL_HTTP1,
    MESHVPN_TUNNEL_H2,
} meshvpn_tunnel_mode_t;

static meshvpn_tunnel_mode_t s_tunnel_mode = MESHVPN_TUNNEL_NONE;

static void vpn_close_tunnel(void);
static void vpn_worker(void *arg);

static void set_error(const char *msg)
{
    strncpy(s_status.last_error, msg, sizeof(s_status.last_error) - 1);
    s_status.last_error[sizeof(s_status.last_error) - 1] = '\0';
    ESP_LOGW(TAG, "%s", s_status.last_error);
}

static bool vpn_uplink_ready(char *err, size_t err_len)
{
    meshvpn_wifi_status_t ws;
    meshvpn_wifi_get_status(&ws);
    if (!ws.sta_connected || ws.ip[0] == '\0') {
        snprintf(err, err_len, "no WiFi uplink");
        return false;
    }
    if (!meshvpn_wifi_time_ready()) {
        snprintf(err, err_len, "waiting for time sync");
        return false;
    }
    return true;
}

static void vpn_ensure_worker(void)
{
    s_worker_run = true;
    if (s_worker != NULL) {
        eTaskState st = eTaskGetState(s_worker);
        if (st != eDeleted && st != eInvalid) {
            return;
        }
        s_worker = NULL;
    }
    xTaskCreate(vpn_worker, "vpn_worker", 12288, NULL, 5, &s_worker);
}

static void vpn_close_tunnel(void)
{
    meshvpn_vpn_h2_close();
    meshvpn_vpn_http1_close();
    s_tunnel_mode = MESHVPN_TUNNEL_NONE;

    if (s_tls) {
        esp_tls_conn_destroy(s_tls);
        s_tls = NULL;
    }
    if (s_tunnel_fd >= 0) {
        close(s_tunnel_fd);
        s_tunnel_fd = -1;
    }
    s_status.connected = false;
}

static esp_err_t vpn_connect_tls_like(const meshvpn_vpn_config_t *cfg, bool boring)
{
    char err[96] = {0};
    if (!vpn_uplink_ready(err, sizeof(err))) {
        set_error(err);
        return ESP_ERR_INVALID_STATE;
    }
    if (cfg->server[0] == '\0') {
        set_error("server not set");
        return ESP_ERR_INVALID_ARG;
    }

    int fd = -1;
    esp_tls_t *tls = NULL;

    esp_err_t e = boring ? meshvpn_vpn_boring_connect(cfg, &fd, &tls, err, sizeof(err))
                         : meshvpn_vpn_tls_handshake(cfg, &fd, &tls, err, sizeof(err));
    if (e != ESP_OK) {
        set_error(err[0] ? err : "connect failed");
        return e;
    }

    if (!boring && !tls) {
        set_error("tls ctx missing");
        return ESP_FAIL;
    }

    uint8_t exporter[MESHVPN_TLS_EXPORTER_LEN];
    uint8_t psk[64];
    size_t psk_len = 0;
    meshvpn_storage_load_psk(psk, sizeof(psk), &psk_len);
    if (psk_len == 0) {
        set_error("missing HMAC key");
        if (tls) {
            esp_tls_conn_destroy(tls);
        }
        return ESP_ERR_NOT_FOUND;
    }

    if (tls && meshvpn_tls_exporter_from_esp_tls(tls, exporter, sizeof(exporter)) == ESP_OK) {
        int stream_id = 0;
        esp_err_t hop_err = ESP_FAIL;
        for (int64_t woff = -1; woff <= 1 && hop_err != ESP_OK; woff++) {
            char token[33];
            meshvpn_vpn_bearer_compute_window(psk, psk_len, exporter, sizeof(exporter), woff, token,
                                              sizeof(token));
            if (cfg->http_vers == 1) {
                hop_err = meshvpn_vpn_http1_open(tls, cfg, token, err, sizeof(err));
                if (hop_err == ESP_OK) {
                    s_tunnel_mode = MESHVPN_TUNNEL_HTTP1;
                }
            } else {
                hop_err = meshvpn_vpn_h2_open(tls, cfg, token, &stream_id, err, sizeof(err));
                if (hop_err == ESP_OK) {
                    s_tunnel_mode = MESHVPN_TUNNEL_H2;
                }
            }
        }
        if (hop_err != ESP_OK) {
            esp_tls_conn_destroy(tls);
            set_error(err);
            return ESP_FAIL;
        }
    } else {
        set_error("TLS exporter failed");
        if (tls) {
            esp_tls_conn_destroy(tls);
        }
        return ESP_FAIL;
    }

    s_tunnel_fd = fd;
    s_tls = tls;
    s_status.connected = true;
    s_status.last_error[0] = '\0';
    return ESP_OK;
}

static esp_err_t vpn_tunnel_read(uint8_t *pkt, uint16_t maxlen, uint16_t *out_len)
{
    switch (s_tunnel_mode) {
    case MESHVPN_TUNNEL_H2:
        return meshvpn_vpn_h2_read(pkt, maxlen, out_len);
    case MESHVPN_TUNNEL_HTTP1:
        return meshvpn_vpn_http1_read(pkt, maxlen, out_len);
    case MESHVPN_TUNNEL_RAW:
        return meshvpn_vpn_framing_read(s_tunnel_fd, pkt, maxlen, out_len);
    default:
        return ESP_ERR_INVALID_STATE;
    }
}

static esp_err_t vpn_tunnel_write(const uint8_t *pkt, uint16_t len)
{
    switch (s_tunnel_mode) {
    case MESHVPN_TUNNEL_H2:
        return meshvpn_vpn_h2_write(pkt, len);
    case MESHVPN_TUNNEL_HTTP1:
        return meshvpn_vpn_http1_write(pkt, len);
    case MESHVPN_TUNNEL_RAW:
        return meshvpn_vpn_framing_write(s_tunnel_fd, pkt, len);
    default:
        return ESP_ERR_INVALID_STATE;
    }
}

static esp_err_t vpn_connect_transparent(const meshvpn_vpn_config_t *cfg)
{
    char err[96] = {0};
    if (!vpn_uplink_ready(err, sizeof(err))) {
        set_error(err);
        return ESP_ERR_INVALID_STATE;
    }
    if (cfg->tls_public_name[0] == '\0') {
        set_error("tls_public_name required");
        return ESP_ERR_INVALID_ARG;
    }

    meshvpn_vpn_transparent_intercept_start(cfg);

    if (meshvpn_vpn_transparent_mux_connect(cfg, &s_tunnel_fd, err, sizeof(err)) != ESP_OK) {
        set_error(err);
        return ESP_FAIL;
    }

    s_tunnel_mode = MESHVPN_TUNNEL_RAW;
    s_status.connected = true;
    s_status.last_error[0] = '\0';
    return ESP_OK;
}

static void vpn_worker(void *arg)
{
    (void)arg;

    while (s_worker_run) {
        if (!s_cfg.enabled) {
            vpn_close_tunnel();
            meshvpn_vpn_transparent_intercept_stop();
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        if (!s_status.connected) {
            vpn_close_tunnel();
            if (strcmp(s_cfg.transport, "transparent-tls") == 0) {
                vpn_connect_transparent(&s_cfg);
            } else if (strcmp(s_cfg.transport, "boring-tls") == 0) {
                vpn_connect_tls_like(&s_cfg, true);
            } else {
                vpn_connect_tls_like(&s_cfg, false);
            }
            if (!s_status.connected) {
                vTaskDelay(pdMS_TO_TICKS(5000));
            }
            continue;
        }

        if (s_status.connected) {
            if (s_tunnel_mode == MESHVPN_TUNNEL_H2) {
                meshvpn_vpn_h2_poll();
            }

            uint8_t pkt[1500];
            uint16_t len = 0;
            if (vpn_tunnel_read(pkt, sizeof(pkt), &len) == ESP_OK) {
                s_status.bytes_in += len;
                if (s_inject) {
                    s_inject(pkt, len);
                }
            } else {
                vTaskDelay(pdMS_TO_TICKS(10));
            }
            continue;
        }
    }

    vpn_close_tunnel();
    meshvpn_vpn_transparent_intercept_stop();
    s_worker = NULL;
    vTaskDelete(NULL);
}

void meshvpn_vpn_set_inject(meshvpn_vpn_inject_fn fn)
{
    s_inject = fn;
}

esp_err_t meshvpn_vpn_init(void)
{
    if (s_lock) {
        return ESP_OK;
    }
    s_lock = xSemaphoreCreateMutex();
    if (!s_lock) {
        return ESP_ERR_NO_MEM;
    }
    meshvpn_storage_init();
    ESP_LOGI(TAG, "VPN init");
    return ESP_OK;
}

esp_err_t meshvpn_vpn_ensure_init(void)
{
    return meshvpn_vpn_init();
}

esp_err_t meshvpn_vpn_start(const meshvpn_vpn_config_t *cfg)
{
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    memcpy(&s_cfg, cfg, sizeof(s_cfg));
    memcpy(s_status.server, cfg->server, sizeof(s_status.server));
    strncpy(s_status.transport, cfg->transport, sizeof(s_status.transport) - 1);
    strncpy(s_status.profile_name, cfg->profile_name, sizeof(s_status.profile_name) - 1);
    s_status.enabled = cfg->enabled;
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }

    vpn_ensure_worker();
    return ESP_OK;
}

esp_err_t meshvpn_vpn_apply_config(const meshvpn_vpn_config_t *cfg)
{
    if (!cfg) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = meshvpn_vpn_ensure_init();
    if (err != ESP_OK) {
        return err;
    }

    /* Close tunnel and refresh cfg — do not meshvpn_vpn_stop() (kills worker permanently). */
    vpn_close_tunnel();

    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    memcpy(&s_cfg, cfg, sizeof(s_cfg));
    memcpy(s_status.server, cfg->server, sizeof(s_status.server));
    strncpy(s_status.transport, cfg->transport, sizeof(s_status.transport) - 1);
    strncpy(s_status.profile_name, cfg->profile_name, sizeof(s_status.profile_name) - 1);
    s_status.enabled = cfg->enabled;
    s_status.connected = false;
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }

    vpn_ensure_worker();
    return ESP_OK;
}

esp_err_t meshvpn_vpn_stop(void)
{
    s_worker_run = false;
    s_cfg.enabled = false;
    s_status.enabled = false;
    vpn_close_tunnel();
    meshvpn_vpn_transparent_intercept_stop();
    return ESP_OK;
}

bool meshvpn_vpn_is_connected(void)
{
    return s_status.connected;
}

bool meshvpn_vpn_routes_via_tunnel(void)
{
    return s_cfg.enabled && s_status.connected;
}

bool meshvpn_vpn_is_transparent(void)
{
    return s_cfg.enabled && strcmp(s_cfg.transport, "transparent-tls") == 0;
}

void meshvpn_vpn_transparent_note_redirect(void)
{
    ESP_LOGD(TAG, "transparent :443 redirect");
}

esp_err_t meshvpn_vpn_send_ipv4(const uint8_t *pkt, uint16_t len)
{
    if (!s_status.connected) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = vpn_tunnel_write(pkt, len);
    if (err == ESP_OK) {
        s_status.bytes_out += len;
    }
    return err;
}

esp_err_t meshvpn_vpn_recv_ipv4(uint8_t *pkt, uint16_t maxlen, uint16_t *out_len)
{
    return vpn_tunnel_read(pkt, maxlen, out_len);
}

void meshvpn_vpn_get_status(meshvpn_vpn_status_t *status)
{
    memcpy(status, &s_status, sizeof(*status));
}
