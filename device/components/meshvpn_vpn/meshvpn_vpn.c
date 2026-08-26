/*
 * meshvpn_vpn — clean-vpn client (tls / transparent-tls / boring-tls).
 */

#include "meshvpn_vpn.h"
#include "meshvpn_vpn_internal.h"
#include "meshvpn_vpn_protocol.h"
#include "meshvpn_tls_exporter.h"
#include "meshvpn_storage.h"

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

static void set_error(const char *msg)
{
    strncpy(s_status.last_error, msg, sizeof(s_status.last_error) - 1);
    s_status.last_error[sizeof(s_status.last_error) - 1] = '\0';
}

static void vpn_close_tunnel(void)
{
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

    if (tls && meshvpn_tls_exporter_from_esp_tls(tls, exporter, sizeof(exporter)) == ESP_OK) {
        char token[33];
        meshvpn_vpn_bearer_compute(psk, psk_len, exporter, sizeof(exporter), token, sizeof(token));
        int stream_id = 0;
        if (meshvpn_vpn_h2_open(fd, cfg, token, &stream_id, err, sizeof(err)) != ESP_OK) {
            esp_tls_conn_destroy(tls);
            set_error(err);
            return ESP_FAIL;
        }
    } else {
        set_error("exporter/h2 failed");
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

static esp_err_t vpn_connect_transparent(const meshvpn_vpn_config_t *cfg)
{
    char err[96] = {0};
    if (cfg->tls_public_name[0] == '\0') {
        set_error("tls_public_name required");
        return ESP_ERR_INVALID_ARG;
    }

    meshvpn_vpn_transparent_intercept_start(cfg);

    if (meshvpn_vpn_transparent_mux_connect(cfg, &s_tunnel_fd, err, sizeof(err)) != ESP_OK) {
        set_error(err);
        return ESP_FAIL;
    }

    s_status.connected = true;
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

        if (s_tunnel_fd >= 0) {
            uint8_t pkt[1500];
            uint16_t len = 0;
            if (meshvpn_vpn_framing_read(s_tunnel_fd, pkt, sizeof(pkt), &len) == ESP_OK) {
                s_status.bytes_in += len;
                if (s_inject) {
                    s_inject(pkt, len);
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    vpn_close_tunnel();
    meshvpn_vpn_transparent_intercept_stop();
    vTaskDelete(NULL);
}

void meshvpn_vpn_set_inject(meshvpn_vpn_inject_fn fn)
{
    s_inject = fn;
}

esp_err_t meshvpn_vpn_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    meshvpn_storage_init();
    ESP_LOGI(TAG, "VPN init");
    return ESP_OK;
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

    s_worker_run = true;
    if (!s_worker) {
        xTaskCreate(vpn_worker, "vpn_worker", 12288, NULL, 5, &s_worker);
    }
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
    if (!s_status.connected || s_tunnel_fd < 0) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = meshvpn_vpn_framing_write(s_tunnel_fd, pkt, len);
    if (err == ESP_OK) {
        s_status.bytes_out += len;
    }
    return err;
}

esp_err_t meshvpn_vpn_recv_ipv4(uint8_t *pkt, uint16_t maxlen, uint16_t *out_len)
{
    return meshvpn_vpn_framing_read(s_tunnel_fd, pkt, maxlen, out_len);
}

void meshvpn_vpn_get_status(meshvpn_vpn_status_t *status)
{
    memcpy(status, &s_status, sizeof(*status));
}
