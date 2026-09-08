#include "meshvpn_dns_proxy.h"
#include "meshvpn_dns_wire.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#define DNS_MAX 4096
#define DNS_UDP_MAX 1232
#define DNS_WORKERS 3
static const char *TAG = "meshvpn_dns";
static int s_udp = -1, s_tcp = -1;
static QueueHandle_t s_queue;
static meshvpn_dns_stats_t s_stats;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
#define COUNT(field) do { portENTER_CRITICAL(&s_lock); s_stats.field++; portEXIT_CRITICAL(&s_lock); } while (0)

typedef struct {
    int fd; /* -1 for UDP */
    struct sockaddr_in peer;
    size_t len;
    uint8_t query[DNS_UDP_MAX + 1];
} job_t;
typedef struct { uint8_t *query, *resp; TaskHandle_t task; } worker_t;
static worker_t s_workers[DNS_WORKERS];
#define CACHE_SLOTS 8
typedef struct {
    uint16_t qlen, rlen;
    int64_t stored_us;
    uint32_t ttl;
    uint8_t query[DNS_UDP_MAX], response[DNS_UDP_MAX];
} cache_entry_t;
static cache_entry_t *s_cache;
static SemaphoreHandle_t s_cache_lock;
static unsigned s_cache_next;
static uint32_t s_cache_generation;

void meshvpn_dns_clear_cache(void)
{
    if (!s_cache || !s_cache_lock) return;
    xSemaphoreTake(s_cache_lock, portMAX_DELAY);
    s_cache_generation++;
    memset(s_cache, 0, CACHE_SLOTS * sizeof(*s_cache));
    xSemaphoreGive(s_cache_lock);
}
static int cache_get(const uint8_t *query, size_t len, uint8_t *response)
{
    if (!s_cache || len > DNS_UDP_MAX) return 0;
    int n = 0;
    uint32_t age = 0;
    xSemaphoreTake(s_cache_lock, portMAX_DELAY);
    for (unsigned i = 0; i < CACHE_SLOTS; i++) {
        cache_entry_t *e = &s_cache[i];
        age = (esp_timer_get_time() - e->stored_us) / 1000000;
        if (e->qlen != len || age >= e->ttl || memcmp(query + 2, e->query + 2, len - 2)) continue;
        n = e->rlen; memcpy(response, e->response, n); break;
    }
    xSemaphoreGive(s_cache_lock);
    if (n) {
        response[0] = query[0]; response[1] = query[1];
        if (!meshvpn_dns_age_ttls(response, n, age)) return 0;
        COUNT(cache_hits);
    }
    return n;
}
static uint32_t cache_generation(void)
{
    if (!s_cache_lock) return 0;
    xSemaphoreTake(s_cache_lock, portMAX_DELAY);
    uint32_t generation = s_cache_generation;
    xSemaphoreGive(s_cache_lock);
    return generation;
}
static void cache_put(const uint8_t *query, size_t qlen, uint8_t *response, size_t rlen, uint32_t generation)
{
    if (!s_cache || qlen > DNS_UDP_MAX || rlen > DNS_UDP_MAX) return;
    uint32_t ttl = meshvpn_dns_age_ttls(response, rlen, 0);
    if (!ttl) return;
    xSemaphoreTake(s_cache_lock, portMAX_DELAY);
    if (generation != s_cache_generation) {
        xSemaphoreGive(s_cache_lock);
        return;
    }
    cache_entry_t *e = &s_cache[s_cache_next++ % CACHE_SLOTS];
    e->qlen = qlen; e->rlen = rlen; e->stored_us = esp_timer_get_time();
    e->ttl = ttl < 300 ? ttl : 300;
    memcpy(e->query, query, qlen); memcpy(e->response, response, rlen);
    xSemaphoreGive(s_cache_lock);
}

static void timeout(int fd)
{
    struct timeval tv = {.tv_sec = 2};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}
static bool transfer(int fd, uint8_t *buf, size_t len, bool write)
{
    int64_t deadline = esp_timer_get_time() + 5000000;
    while (len) {
        if (esp_timer_get_time() >= deadline) return false;
        int n = write ? send(fd, buf, len, 0) : recv(fd, buf, len, 0);
        if (n <= 0) return false;
        buf += n; len -= n;
    }
    return true;
}

static bool upstream_address(struct sockaddr_in *up)
{
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_dns_info_t dns;
    esp_netif_ip_info_t ip;
    if (!sta || esp_netif_get_ip_info(sta, &ip) != ESP_OK || !ip.ip.addr) return false;
    memset(up, 0, sizeof(*up));
    up->sin_family = AF_INET;
    up->sin_port = htons(53);
    if (esp_netif_get_dns_info(sta, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK &&
        dns.ip.type == ESP_IPADDR_TYPE_V4 && dns.ip.u_addr.ip4.addr)
        up->sin_addr.s_addr = dns.ip.u_addr.ip4.addr;
    else inet_aton("1.1.1.1", &up->sin_addr);
    return true;
}

/* Connected UDP socket checks source IP+port; fresh random ID and full
 * question comparison reject unrelated or late replies. One socket per job. */
static int upstream(uint8_t *query, size_t len, uint8_t *resp, bool tcp)
{
    struct sockaddr_in up;
    if (!upstream_address(&up)) return -1;
    int fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    timeout(fd);
    /* Nonblocking connect with a deadline, including TCP fallback. */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int rc = connect(fd, (struct sockaddr *)&up, sizeof(up));
    if (rc < 0 && errno == EINPROGRESS) {
        fd_set wr; FD_ZERO(&wr); FD_SET(fd, &wr);
        struct timeval tv = {.tv_sec = 2};
        rc = select(fd + 1, NULL, &wr, NULL, &tv);
        int error = 0; socklen_t elen = sizeof(error);
        if (rc > 0 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &elen) == 0 && !error) rc = 0;
        else rc = -1;
    }
    fcntl(fd, F_SETFL, flags);
    int n = -1;
    if (rc == 0) {
        if (tcp) {
            uint8_t prefix[2] = {len >> 8, len};
            if (transfer(fd, prefix, 2, true) && transfer(fd, query, len, true) &&
                transfer(fd, prefix, 2, false)) {
                n = (prefix[0] << 8) | prefix[1];
                if (n < 12 || n > DNS_MAX || !transfer(fd, resp, n, false)) n = -1;
            }
        } else if (send(fd, query, len, 0) == len) {
            /* Extra byte detects datagrams exceeding our bounded response. */
            n = recv(fd, resp, DNS_MAX + 1, 0);
            if (n > DNS_MAX) n = -1;
        }
    }
    close(fd);
    meshvpn_dns_question_t q, a;
    if (n < 12 || !(resp[2] & 0x80) || resp[0] != query[0] || resp[1] != query[1] ||
        !meshvpn_dns_question(query, len, &q) || !meshvpn_dns_question(resp, n, &a) ||
        strcmp(q.name, a.name) || q.type != a.type || q.klass != a.klass) return -1;
    if (!tcp && (resp[2] & 2)) return upstream(query, len, resp, true);
    return n;
}

static unsigned udp_limit(const uint8_t *query, size_t len, const meshvpn_dns_question_t *q)
{
    /* Accept a single standard root-name OPT record. Unsupported extra
     * records conservatively use the classic 512-byte UDP limit. */
    size_t off = q->end;
    if (!query[10] && query[11] == 1 && off + 11 <= len &&
        query[off] == 0 && query[off + 1] == 0 && query[off + 2] == 41) {
        unsigned cap = (query[off + 3] << 8) | query[off + 4];
        return cap < 512 ? 512 : cap > DNS_UDP_MAX ? DNS_UDP_MAX : cap;
    }
    return 512;
}

static void worker(void *arg)
{
    worker_t *ctx = arg;
    uint8_t *query = ctx->query, *resp = ctx->resp;
    job_t *job;
    while (xQueueReceive(s_queue, &job, portMAX_DELAY) == pdTRUE) {
        size_t len = job->len;
        if (job->fd >= 0) {
            timeout(job->fd);
            uint8_t prefix[2];
            if (!transfer(job->fd, prefix, 2, false)) goto done;
            len = (prefix[0] << 8) | prefix[1];
            if (len < 12 || len > DNS_MAX || !transfer(job->fd, query, len, false)) goto done;
        } else memcpy(query, job->query, len);
        meshvpn_dns_question_t q;
        if ((query[2] & 0x80) || !meshvpn_dns_question(query, len, &q)) {
            COUNT(errors); goto done;
        }
        COUNT(queries);
        int n;
        if (!strcmp(q.name, "meshpn.home.arpa") || !strcmp(q.name, "meshpn.local")) {
            esp_netif_t *usb = esp_netif_get_handle_from_ifkey("USB_DEF");
            esp_netif_ip_info_t ip = {0};
            if (usb) esp_netif_get_ip_info(usb, &ip);
            n = meshvpn_dns_reply(query, len, resp, DNS_MAX, 0, false, ip.ip.addr);
        } else if ((n = cache_get(query, len, resp)) == 0) {
            uint32_t generation = cache_generation();
            uint8_t id[2] = {query[0], query[1]};
            uint16_t random_id = esp_random();
            query[0] = random_id >> 8; query[1] = random_id;
            n = upstream(query, len, resp, job->fd >= 0);
            query[0] = id[0]; query[1] = id[1];
            if (n < 0) {
                COUNT(forward_fail);
                n = meshvpn_dns_reply(query, len, resp, DNS_MAX, 2, false, 0);
            } else {
                resp[0] = id[0]; resp[1] = id[1];
                COUNT(forwarded);
                cache_put(query, len, resp, n, generation);
            }
        }
        if (job->fd < 0 && n > udp_limit(query, len, &q))
            n = meshvpn_dns_reply(query, len, resp, DNS_MAX, 0, true, 0);
        if (n > 0) {
            if (job->fd >= 0) {
                uint8_t prefix[2] = {n >> 8, n};
                if (transfer(job->fd, prefix, 2, true)) transfer(job->fd, resp, n, true);
            } else sendto(s_udp, resp, n, 0, (struct sockaddr *)&job->peer, sizeof(job->peer));
        }
done:
        if (job->fd >= 0) close(job->fd);
        free(job);
    }
}

static void listener(void *arg)
{
    (void)arg;
    for (;;) {
        fd_set rd; FD_ZERO(&rd); FD_SET(s_udp, &rd); FD_SET(s_tcp, &rd);
        if (select((s_udp > s_tcp ? s_udp : s_tcp) + 1, &rd, NULL, NULL, NULL) <= 0) continue;
        job_t *job = calloc(1, sizeof(*job));
        if (!job) { vTaskDelay(pdMS_TO_TICKS(50)); continue; }
        socklen_t sl = sizeof(job->peer);
        if (FD_ISSET(s_udp, &rd)) {
            job->fd = -1;
            int n = recvfrom(s_udp, job->query, sizeof(job->query), 0, (struct sockaddr *)&job->peer, &sl);
            if (n < 12 || n > DNS_UDP_MAX) { free(job); COUNT(errors); continue; }
            job->len = n;
        } else {
            job->fd = accept(s_tcp, (struct sockaddr *)&job->peer, &sl);
            if (job->fd < 0) { free(job); continue; }
        }
        if (xQueueSend(s_queue, &job, 0) != pdTRUE) {
            if (job->fd >= 0) close(job->fd);
            free(job);
            COUNT(errors);
        }
    }
}

esp_err_t meshvpn_dns_proxy_init(void)
{
    if (s_udp >= 0) return ESP_ERR_INVALID_STATE;
    s_queue = xQueueCreate(4, sizeof(job_t *));
    if (!s_queue) return ESP_ERR_NO_MEM;
    s_cache_lock = xSemaphoreCreateMutex();
    if (s_cache_lock) s_cache = heap_caps_calloc(CACHE_SLOTS, sizeof(*s_cache), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    s_udp = socket(AF_INET, SOCK_DGRAM, 0);
    s_tcp = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(53),
                               .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (s_udp < 0 || s_tcp < 0 || bind(s_udp, (struct sockaddr *)&addr, sizeof(addr)) ||
        bind(s_tcp, (struct sockaddr *)&addr, sizeof(addr)) || listen(s_tcp, 3)) {
        if (s_udp >= 0) close(s_udp);
        if (s_tcp >= 0) close(s_tcp);
        s_udp = s_tcp = -1;
        vQueueDelete(s_queue);
        free(s_cache); s_cache = NULL;
        if (s_cache_lock) vSemaphoreDelete(s_cache_lock);
        s_cache_lock = NULL;
        return ESP_FAIL;
    }
    for (unsigned i = 0; i < DNS_WORKERS; i++) {
        s_workers[i].query = heap_caps_malloc(DNS_MAX + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        s_workers[i].resp = heap_caps_malloc(DNS_MAX + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_workers[i].query || !s_workers[i].resp ||
            xTaskCreate(worker, "dns_worker", 4096, &s_workers[i], 5, &s_workers[i].task) != pdPASS)
            goto failed;
    }
    if (xTaskCreate(listener, "dns_listener", 3072, NULL, 5, NULL) != pdPASS) goto failed;
    ESP_LOGI(TAG, "USB DNS: bounded UDP/TCP proxy, DHCP uplink resolver");
    return ESP_OK;
failed:
    for (unsigned i = 0; i < DNS_WORKERS; i++) {
        if (s_workers[i].task) vTaskDelete(s_workers[i].task);
        free(s_workers[i].query); free(s_workers[i].resp);
        memset(&s_workers[i], 0, sizeof(s_workers[i]));
    }
    close(s_udp); close(s_tcp); s_udp = s_tcp = -1;
    vQueueDelete(s_queue); s_queue = NULL;
    free(s_cache); s_cache = NULL;
    if (s_cache_lock) vSemaphoreDelete(s_cache_lock);
    s_cache_lock = NULL;
    return ESP_ERR_NO_MEM;
}
void meshvpn_dns_get_stats(meshvpn_dns_stats_t *out)
{
    portENTER_CRITICAL(&s_lock);
    *out = s_stats;
    portEXIT_CRITICAL(&s_lock);
}
void meshvpn_dns_count_hijack(void) { }
esp_err_t meshvpn_dns_proxy_handle_query(const uint8_t *pkt, uint16_t len)
{
    (void)pkt; (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}
