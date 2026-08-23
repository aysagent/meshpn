#include "meshvpn_dns_proxy.h"

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include "esp_log.h"
#include "esp_netif_ip_addr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "sdkconfig.h"

static const char *TAG = "meshvpn_dns";

#define DNS_PORT 53
#define DNS_BUF 512
#define DNS_TASK_STACK 4096
#define DNS_UPSTREAM "8.8.8.8"
#define DNS_UPSTREAM_TIMEOUT_MS 2000

static int s_sock = -1;
static int s_upstream = -1;
static meshvpn_dns_stats_t s_stats;

static const char *const s_captive[] = {
    "captive.apple.com",
    "www.apple.com",
    "connectivitycheck.gstatic.com",
    "clients3.google.com",
    "msftconnecttest.com",
    "detectportal.firefox.com",
    NULL,
};

static int dns_skip_name(const uint8_t *pkt, int len, int off)
{
    int hops = 0;

    while (off < len && hops++ < 32) {
        if ((pkt[off] & 0xC0) == 0xC0) {
            return (off + 2 <= len) ? off + 2 : -1;
        }
        if (pkt[off] == 0) {
            return off + 1;
        }
        uint8_t labellen = pkt[off];
        if (labellen > 63 || off + 1 + labellen > len) {
            return -1;
        }
        off += 1 + labellen;
    }
    return -1;
}

static int dns_read_qname(const uint8_t *pkt, int len, int off, char *out, size_t out_len)
{
    size_t pos = 0;
    int hops = 0;

    out[0] = '\0';
    while (off < len && hops++ < 32) {
        if ((pkt[off] & 0xC0) == 0xC0) {
            if (off + 1 >= len) {
                return -1;
            }
            off = ((pkt[off] & 0x3F) << 8) | pkt[off + 1];
            continue;
        }

        uint8_t labellen = pkt[off++];
        if (labellen == 0) {
            if (pos > 0 && pos < out_len) {
                out[pos - 1] = '\0';
            }
            return off;
        }
        if (labellen > 63 || off + labellen > len) {
            return -1;
        }
        if (pos > 0 && pos < out_len) {
            out[pos++] = '.';
        }
        for (int i = 0; i < labellen && pos + 1 < out_len; i++) {
            out[pos++] = (char)pkt[off++];
        }
    }
    return -1;
}

static bool dns_name_equal_ci(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return false;
        }
        a++;
        b++;
    }
    return *a == *b;
}

static bool dns_is_captive(const char *name)
{
    for (int i = 0; s_captive[i]; i++) {
        if (dns_name_equal_ci(name, s_captive[i])) {
            return true;
        }
    }
    return false;
}

static uint32_t dns_gateway_for_client(uint32_t client_ip_be)
{
    const uint8_t *b = (const uint8_t *)&client_ip_be;

    if (b[0] == 192 && b[1] == 168 && b[2] == CONFIG_MESHVPN_USB_SUBNET_OCTET_2) {
        return ESP_IP4TOADDR(192, 168, CONFIG_MESHVPN_USB_SUBNET_OCTET_2, 1);
    }
    if (b[0] == 192 && b[1] == 168 && b[2] == 4) {
        return ESP_IP4TOADDR(192, 168, 4, 1);
    }
    return ESP_IP4TOADDR(192, 168, CONFIG_MESHVPN_USB_SUBNET_OCTET_2, 1);
}

static int dns_build_a_response(const uint8_t *query, int qlen, uint32_t answer_ip, uint8_t *out, int out_max)
{
    if (qlen < 12 || qlen + 16 > out_max) {
        return -1;
    }

    memcpy(out, query, qlen);
    out[2] = 0x81;
    out[3] = 0x80;
    out[7] = 1;

    int qend = dns_skip_name(query, qlen, 12);
    if (qend < 0 || qend + 4 > qlen) {
        return -1;
    }
    qend += 4;

    int pos = qend;
    out[pos++] = 0xC0;
    out[pos++] = 0x0C;
    out[pos++] = 0x00;
    out[pos++] = 0x01;
    out[pos++] = 0x00;
    out[pos++] = 0x01;
    out[pos++] = 0x00;
    out[pos++] = 0x00;
    out[pos++] = 0x00;
    out[pos++] = 60;
    out[pos++] = 0x00;
    out[pos++] = 0x04;
    memcpy(&out[pos], &answer_ip, 4);
    pos += 4;
    return pos;
}

static bool dns_forward_upstream(const uint8_t *query, int qlen, uint8_t *resp, int *resp_len)
{
    struct sockaddr_in up = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
    };
    inet_aton(DNS_UPSTREAM, &up.sin_addr);

    if (sendto(s_upstream, query, qlen, 0, (struct sockaddr *)&up, sizeof(up)) != qlen) {
        return false;
    }

    struct timeval tv = {
        .tv_sec = DNS_UPSTREAM_TIMEOUT_MS / 1000,
        .tv_usec = (DNS_UPSTREAM_TIMEOUT_MS % 1000) * 1000,
    };
    setsockopt(s_upstream, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    socklen_t slen = sizeof(up);
    int n = recvfrom(s_upstream, resp, DNS_BUF, 0, (struct sockaddr *)&up, &slen);
    if (n <= 0) {
        return false;
    }

    *resp_len = n;
    return true;
}

static void dns_task(void *arg)
{
    uint8_t buf[DNS_BUF];
    uint8_t resp[DNS_BUF];

    while (true) {
        struct sockaddr_in src = {0};
        socklen_t slen = sizeof(src);
        int n = recvfrom(s_sock, buf, sizeof(buf), 0, (struct sockaddr *)&src, &slen);
        if (n < 12) {
            if (n < 0) {
                vTaskDelay(pdMS_TO_TICKS(50));
            }
            continue;
        }

        s_stats.queries++;

        char qname[256];
        int qname_end = dns_read_qname(buf, n, 12, qname, sizeof(qname));
        if (qname_end < 0 || qname_end + 4 > n) {
            s_stats.errors++;
            continue;
        }

        uint16_t qtype = (uint16_t)((buf[qname_end] << 8) | buf[qname_end + 1]);
        uint32_t client_ip = src.sin_addr.s_addr;
        uint32_t gateway_ip = dns_gateway_for_client(client_ip);

        if ((qtype == 1 || qtype == 28) && dns_is_captive(qname)) {
            s_stats.captive++;
            if (qtype == 1) {
                int rlen = dns_build_a_response(buf, n, gateway_ip, resp, sizeof(resp));
                if (rlen > 0) {
                    sendto(s_sock, resp, rlen, 0, (struct sockaddr *)&src, slen);
                } else {
                    s_stats.errors++;
                }
            }
            continue;
        }

        int rlen = 0;
        if (dns_forward_upstream(buf, n, resp, &rlen)) {
            sendto(s_sock, resp, rlen, 0, (struct sockaddr *)&src, slen);
            s_stats.forwarded++;
        } else {
            s_stats.forward_fail++;
        }
    }
}

esp_err_t meshvpn_dns_proxy_init(void)
{
    if (s_sock >= 0) {
        return ESP_OK;
    }

    s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s_sock < 0) {
        ESP_LOGE(TAG, "DNS socket failed: errno %d", errno);
        return ESP_FAIL;
    }

    int reuse = 1;
    setsockopt(s_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    if (bind(s_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
        ESP_LOGE(TAG, "DNS bind :53 failed: errno %d", errno);
        close(s_sock);
        s_sock = -1;
        return ESP_FAIL;
    }

    s_upstream = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s_upstream < 0) {
        ESP_LOGE(TAG, "upstream DNS socket failed: errno %d", errno);
        close(s_sock);
        s_sock = -1;
        return ESP_FAIL;
    }

    BaseType_t ok = xTaskCreate(dns_task, "dns_proxy", DNS_TASK_STACK, NULL, 5, NULL);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "DNS task create failed");
        close(s_upstream);
        close(s_sock);
        s_upstream = -1;
        s_sock = -1;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "DNS proxy on :53 (captive hijack + %s forward)", DNS_UPSTREAM);
    return ESP_OK;
}

void meshvpn_dns_get_stats(meshvpn_dns_stats_t *out)
{
    memcpy(out, &s_stats, sizeof(*out));
}

void meshvpn_dns_count_hijack(void)
{
    s_stats.hijacked++;
}

esp_err_t meshvpn_dns_proxy_handle_query(const uint8_t *pkt, uint16_t len)
{
    (void)pkt;
    (void)len;
    return ESP_OK;
}
