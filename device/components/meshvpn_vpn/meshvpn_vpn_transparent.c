#include "meshvpn_vpn_internal.h"
#include "meshvpn_enc_sni.h"
#include "meshvpn_storage.h"
#include "meshvpn_tls_ch_rebuild.h"

#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"

static const char *TAG = "meshvpn_transparent";
static TaskHandle_t s_intercept_task;
static volatile bool s_intercept_run;
static meshvpn_vpn_config_t s_intercept_cfg;

static int tcp_connect_server(const char *server)
{
    char host[128];
    uint16_t port = 443;
    const char *colon = strrchr(server, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - server);
        if (hlen >= sizeof(host)) {
            return -1;
        }
        memcpy(host, server, hlen);
        host[hlen] = '\0';
        port = (uint16_t)atoi(colon + 1);
    } else {
        strncpy(host, server, sizeof(host) - 1);
    }

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        return -1;
    }
    int sock = socket(res->ai_family, res->ai_socktype, 0);
    if (sock < 0) {
        freeaddrinfo(res);
        return -1;
    }
    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        close(sock);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return sock;
}

static void relay_bidirectional(int a, int b)
{
    fd_set rfds;
    uint8_t buf[4096];
    while (true) {
        FD_ZERO(&rfds);
        FD_SET(a, &rfds);
        FD_SET(b, &rfds);
        int maxfd = a > b ? a : b;
        if (select(maxfd + 1, &rfds, NULL, NULL, NULL) <= 0) {
            break;
        }
        if (FD_ISSET(a, &rfds)) {
            ssize_t n = recv(a, buf, sizeof(buf), 0);
            if (n <= 0) {
                break;
            }
            if (send(b, buf, n, 0) != n) {
                break;
            }
        }
        if (FD_ISSET(b, &rfds)) {
            ssize_t n = recv(b, buf, sizeof(buf), 0);
            if (n <= 0) {
                break;
            }
            if (send(a, buf, n, 0) != n) {
                break;
            }
        }
    }
}

static void handle_intercept_client(int client_fd)
{
    uint8_t buf[8192];
    ssize_t n = recv(client_fd, buf, sizeof(buf), MSG_PEEK);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    n = recv(client_fd, buf, n > (ssize_t)sizeof(buf) ? (ssize_t)sizeof(buf) : n, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }

    uint8_t psk[64];
    size_t psk_len = 0;
    if (meshvpn_storage_load_psk(psk, sizeof(psk), &psk_len) != ESP_OK) {
        close(client_fd);
        return;
    }

    char origin[256];
    char relay[512];
    uint8_t *prefix = NULL;
    size_t prefix_len = 0;
    if (meshvpn_tls_ch_replace_sni(buf, (size_t)n, relay, &prefix, &prefix_len, origin, sizeof(origin)) != ESP_OK) {
        /* Build relay hostname from parsed origin if SNI replace setup pending */
        if (buf[0] == 0x16) {
            origin[0] = '\0';
            if (meshvpn_enc_sni_build_relay_hostname(psk, psk_len, "unknown", 443,
                                                     s_intercept_cfg.tls_public_name,
                                                     relay, sizeof(relay)) != ESP_OK) {
                close(client_fd);
                return;
            }
        } else {
            close(client_fd);
            return;
        }
    }

    if (origin[0] == '\0') {
        meshvpn_enc_sni_build_relay_hostname(psk, psk_len, "unknown", 443,
                                             s_intercept_cfg.tls_public_name,
                                             relay, sizeof(relay));
    } else {
        meshvpn_enc_sni_build_relay_hostname(psk, psk_len, origin, 443,
                                             s_intercept_cfg.tls_public_name,
                                             relay, sizeof(relay));
        if (prefix) {
            free(prefix);
        }
        meshvpn_tls_ch_replace_sni(buf, (size_t)n, relay, &prefix, &prefix_len, origin, sizeof(origin));
    }

    int upstream = tcp_connect_server(s_intercept_cfg.server);
    if (upstream < 0) {
        if (prefix) {
            free(prefix);
        }
        close(client_fd);
        return;
    }

    if (prefix) {
        send(upstream, prefix, prefix_len, 0);
        free(prefix);
    } else {
        send(upstream, buf, n, 0);
    }

    ESP_LOGI(TAG, "enc-SNI relay origin=%s -> %s", origin[0] ? origin : "?", relay);
    relay_bidirectional(client_fd, upstream);
    close(client_fd);
    close(upstream);
}

static void intercept_task(void *arg)
{
    (void)arg;
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(8443),
    };
    bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(listen_fd, 4);
    ESP_LOGI(TAG, "intercept listener :8443");

    while (s_intercept_run) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int fd = accept(listen_fd, (struct sockaddr *)&peer, &plen);
        if (fd < 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        handle_intercept_client(fd);
    }
    close(listen_fd);
    vTaskDelete(NULL);
}

esp_err_t meshvpn_vpn_transparent_mux_connect(const meshvpn_vpn_config_t *cfg, int *out_sock,
                                              char *last_error, size_t last_error_len)
{
    int sock = tcp_connect_server(cfg->server);
    if (sock < 0) {
        snprintf(last_error, last_error_len, "TCP mux connect failed");
        return ESP_FAIL;
    }
    *out_sock = sock;
    return ESP_OK;
}

esp_err_t meshvpn_vpn_transparent_intercept_start(const meshvpn_vpn_config_t *cfg)
{
    memcpy(&s_intercept_cfg, cfg, sizeof(s_intercept_cfg));
    s_intercept_run = true;
    if (!s_intercept_task) {
        xTaskCreate(intercept_task, "tls_int", 8192, NULL, 5, &s_intercept_task);
    }
    return ESP_OK;
}

void meshvpn_vpn_transparent_intercept_stop(void)
{
    s_intercept_run = false;
    s_intercept_task = NULL;
}
