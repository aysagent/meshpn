#include "meshvpn_web.h"
#include "meshvpn_web_tls.h"
#include "meshvpn_session.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "cJSON.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_psram.h"
#include "esp_flash.h"
#include "esp_app_desc.h"
#include "lwip/sockets.h"
#include "meshvpn_board.h"
#include "meshvpn_config.h"
#include "meshvpn_dns_proxy.h"
#include "meshvpn_log.h"
#include "meshvpn_net.h"
#include "meshvpn_lwip_hooks.h"
#include "meshvpn_routing.h"
#include "meshvpn_ip_ranges.h"
#include "meshvpn_usb.h"
#include "meshvpn_vpn.h"
#include "meshvpn_wifi.h"
#include "web_ui.h"
#include "sdkconfig.h"

static const char *TAG = "meshvpn_web";
static httpd_handle_t s_server, s_redirect;
static bool s_https, s_https_configured;
bool meshvpn_web_https_enabled(void) { return s_https; }
static char s_session_token[33];
static int64_t s_session_created, s_session_used, s_login_after;
static unsigned s_login_failures;
static const char *meshvpn_web_build_id(void) { return esp_app_get_description()->version; }

static esp_err_t error(httpd_req_t *req, const char *status, const char *message)
{
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req, message);
    return ESP_FAIL;
}
static void headers(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");
}
/* Defense in depth; the lwIP ingress hook enforces interface identity even
 * when a WiFi peer routes to the USB destination IP. */
static bool local_socket(httpd_req_t *req)
{
    struct sockaddr_in local; socklen_t len = sizeof(local);
    esp_netif_ip_info_t usb;
    return meshvpn_net_usb() && esp_netif_get_ip_info(meshvpn_net_usb(), &usb) == ESP_OK &&
        getsockname(httpd_req_to_sockfd(req), (struct sockaddr *)&local, &len) == 0 &&
        local.sin_family == AF_INET && local.sin_addr.s_addr == usb.ip.addr;
}
static bool password_change_required(void)
{
#if CONFIG_MESHVPN_WEB_REQUIRE_PASSWORD_CHANGE
    char password[MESHVPN_ADMIN_PASS_MAX + 1];
    return meshvpn_config_load_admin_password(password, sizeof(password)) == ESP_OK &&
           !strcmp(password, CONFIG_MESHVPN_WEB_ADMIN_PASSWORD_DEFAULT);
#else
    return false;
#endif
}
static esp_err_t meshvpn_web_require_auth(httpd_req_t *req)
{
    headers(req);
    if (!local_socket(req)) return error(req, "403 Forbidden", "USB management only");
    char auth[64];
    int64_t now = esp_timer_get_time();
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth, sizeof(auth)) != ESP_OK ||
        !meshvpn_session_valid(s_session_token, auth, s_session_created, s_session_used, now))
        return error(req, "401 Unauthorized", "Login required");
    s_session_used = now;
    if (password_change_required() && req->method != HTTP_GET &&
        strcmp(req->uri, "/api/admin/password") && strcmp(req->uri, "/api/logout") &&
        strcmp(req->uri, "/api/wifi/scan"))
        return error(req, "403 Forbidden", "Change the default admin password first");
    return ESP_OK;
}
static cJSON *body(httpd_req_t *req, size_t limit)
{
    char type[48];
    if (httpd_req_get_hdr_value_str(req, "Content-Type", type, sizeof(type)) != ESP_OK ||
        (strcmp(type, "application/json") && strcmp(type, "application/json; charset=utf-8"))) {
        error(req, "415 Unsupported Media Type", "Use application/json");
        return NULL;
    }
    if (!req->content_len || req->content_len > limit) {
        error(req, "413 Content Too Large", "Request body exceeds limit"); return NULL;
    }
    char *buf = malloc(req->content_len + 1);
    if (!buf) { error(req, "503 Service Unavailable", "Out of memory"); return NULL; }
    size_t done = 0;
    int64_t deadline = esp_timer_get_time() + 5000000;
    while (done < req->content_len && esp_timer_get_time() < deadline) {
        int n = httpd_req_recv(req, buf + done, req->content_len - done);
        if (n <= 0) break;
        done += n;
    }
    if (done != req->content_len) {
        free(buf); error(req, "408 Request Timeout", "Incomplete request"); return NULL;
    }
    buf[done] = 0;
    cJSON *in = cJSON_ParseWithLengthOpts(buf, done + 1, NULL, true);
    memset(buf, 0, done); free(buf);
    if (!cJSON_IsObject(in)) {
        cJSON_Delete(in); error(req, "400 Bad Request", "Expected JSON object"); return NULL;
    }
    return in;
}
static esp_err_t send_json(httpd_req_t *req, cJSON *root)
{
    if (!root) return error(req, "503 Service Unavailable", "Out of memory");
    char *str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!str) return error(req, "503 Service Unavailable", "Out of memory");
    headers(req);
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, str);
    cJSON_free(str);
    return err;
}
static esp_err_t ok(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}
static esp_err_t handler_index(httpd_req_t *req)
{
    if (!local_socket(req)) return error(req, "403 Forbidden", "USB management only");
    headers(req);
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, MESHVPN_WEB_INDEX_HTML, HTTPD_RESP_USE_STRLEN);
}
static esp_err_t handler_login_page(httpd_req_t *req)
{
    if (!local_socket(req)) return error(req, "403 Forbidden", "USB management only");
    headers(req);
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, MESHVPN_WEB_LOGIN_HTML, HTTPD_RESP_USE_STRLEN);
}
static esp_err_t handler_api_login(httpd_req_t *req)
{
    headers(req);
    if (!local_socket(req)) return error(req, "403 Forbidden", "USB management only");
    int64_t now = esp_timer_get_time();
    if (now < s_login_after) return error(req, "429 Too Many Requests", "Wait before retrying");
    cJSON *in = body(req, 1024);
    if (!in) return ESP_FAIL;
    const cJSON *pw = cJSON_GetObjectItemCaseSensitive(in, "password");
    char expected[MESHVPN_ADMIN_PASS_MAX + 1] = {0};
    bool valid = meshvpn_config_load_admin_password(expected, sizeof(expected)) == ESP_OK &&
                 cJSON_IsString(pw) && !strcmp(pw->valuestring, expected);
    memset(expected, 0, sizeof(expected));
    cJSON_Delete(in);
    if (!valid) {
        s_login_failures++;
        s_login_after = now + (s_login_failures >= 5 ? 30000000 : 1000000);
        return error(req, "401 Unauthorized", "Invalid password");
    }
    s_login_failures = 0;
    s_login_after = now + 1000000;
    uint8_t raw[16]; esp_fill_random(raw, sizeof(raw));
    for (unsigned i = 0; i < 16; i++) snprintf(s_session_token + i * 2, 3, "%02x", raw[i]);
    s_session_created = s_session_used = now;
    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "token", s_session_token);
    cJSON_AddBoolToObject(out, "must_change_password", password_change_required());
    return send_json(req, out);
}
static void heap_json(cJSON *parent, const char *name, uint32_t caps)
{
    multi_heap_info_t info;
    heap_caps_get_info(&info, caps);
    cJSON *h = cJSON_AddObjectToObject(parent, name);
    cJSON_AddNumberToObject(h, "total", info.total_free_bytes + info.total_allocated_bytes);
    cJSON_AddNumberToObject(h, "free", info.total_free_bytes);
    cJSON_AddNumberToObject(h, "minimum_free", info.minimum_free_bytes);
    cJSON_AddNumberToObject(h, "largest_block", info.largest_free_block);
}
static void add_https_status(cJSON *root)
{
    cJSON_AddBoolToObject(root, "https_enabled", s_https);
    cJSON_AddBoolToObject(root, "https_configured", s_https_configured);
    cJSON_AddBoolToObject(root, "https_restart_required", s_https != s_https_configured);
    cJSON_AddStringToObject(root, "admin_next_url", s_https_configured ? "https://meshpn.local/" : "http://meshpn.local/");
}
static void add_telemetry(cJSON *root)
{
    float temp;
    if (meshvpn_board_temperature(&temp) && isfinite(temp)) cJSON_AddNumberToObject(root, "temperature_c", temp);
    else cJSON_AddNullToObject(root, "temperature_c");
    cJSON *memory = cJSON_AddObjectToObject(root, "memory");
    heap_json(memory, "internal", MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    heap_json(memory, "psram", MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    heap_json(memory, "dma", MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    cJSON_AddNumberToObject(memory, "psram_detected", esp_psram_get_size());
    uint32_t flash = 0; esp_flash_get_size(NULL, &flash);
    cJSON_AddNumberToObject(memory, "flash_detected", flash);
    cJSON_AddNumberToObject(memory, "web_stack_free", uxTaskGetStackHighWaterMark(NULL));
    cJSON_AddStringToObject(root, "build", meshvpn_web_build_id());
    cJSON_AddStringToObject(root, "idf", esp_get_idf_version());
    cJSON_AddStringToObject(root, "hostname", "meshpn.local");
    add_https_status(root);
    if (s_https) cJSON_AddStringToObject(root, "certificate_sha256", meshvpn_web_tls_fingerprint());
    else cJSON_AddNullToObject(root, "certificate_sha256");
    cJSON_AddNumberToObject(root, "ingress_denied", meshvpn_net_denied_count());
}
static esp_err_t handler_api_status(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }

    meshvpn_wifi_status_t ws;
    meshvpn_wifi_get_status(&ws);
    meshvpn_net_status_t ns;
    meshvpn_net_get_status(&ns);
    meshvpn_vpn_status_t vs;
    meshvpn_vpn_get_status(&vs);

    const meshvpn_board_config_t *board = meshvpn_board_get_config();

    cJSON *root = cJSON_CreateObject();
    add_telemetry(root);
    cJSON_AddBoolToObject(root, "must_change_password", password_change_required());
    cJSON_AddStringToObject(root, "board", board->name);
    cJSON_AddNumberToObject(root, "uptime_sec", (double)(esp_timer_get_time() / 1000000));

    cJSON *wifi = cJSON_AddObjectToObject(root, "wifi");
    cJSON_AddStringToObject(wifi, "state", ws.state);
    cJSON_AddNumberToObject(wifi, "profile_id", ws.profile_id);
    cJSON_AddBoolToObject(wifi, "scanning", ws.scanning);
    cJSON_AddBoolToObject(wifi, "paused", ws.paused);
    cJSON_AddBoolToObject(wifi, "connected", ws.sta_connected);
    cJSON_AddBoolToObject(wifi, "setup_mode", ws.setup_mode);
    cJSON_AddBoolToObject(wifi, "ap_active", ws.ap_active);
    cJSON_AddNumberToObject(wifi, "rssi", ws.rssi);
    cJSON_AddStringToObject(wifi, "ssid", ws.ssid);
    cJSON_AddStringToObject(wifi, "ip", ws.ip);
    cJSON_AddNumberToObject(wifi, "disconnect_reason", ws.disconnect_reason);

    cJSON *net = cJSON_AddObjectToObject(root, "net");
    cJSON_AddBoolToObject(net, "bridge", ns.bridge_running);
    cJSON_AddStringToObject(net, "usb_ip", ns.usb_ip);
    cJSON_AddStringToObject(net, "ap_ip", ns.ap_ip);
    cJSON_AddBoolToObject(net, "usb_napt", ns.usb_napt);
    cJSON_AddBoolToObject(net, "ap_napt", ns.ap_napt);
    cJSON_AddStringToObject(net, "default_ifkey", ns.default_ifkey);
    cJSON_AddStringToObject(net, "usb_dhcps_dns", ns.usb_dhcps_dns);
    cJSON_AddNumberToObject(net, "lan_ip4_rx", ns.lan_ip4_rx);

    meshvpn_dns_stats_t ds;
    meshvpn_dns_get_stats(&ds);
    cJSON *dns = cJSON_AddObjectToObject(root, "dns");
    cJSON_AddNumberToObject(dns, "queries", ds.queries);
    cJSON_AddNumberToObject(dns, "cache_hits", ds.cache_hits);
    cJSON_AddNumberToObject(dns, "captive", ds.captive);
    cJSON_AddNumberToObject(dns, "forwarded", ds.forwarded);
    cJSON_AddNumberToObject(dns, "forward_fail", ds.forward_fail);
    cJSON_AddNumberToObject(dns, "errors", ds.errors);
    cJSON_AddNumberToObject(dns, "hijacked", ds.hijacked);

    meshvpn_usb_stats_t us;
    meshvpn_usb_get_stats(&us);
    cJSON *usb = cJSON_AddObjectToObject(root, "usb");
    cJSON_AddStringToObject(usb, "profile", meshvpn_usb_profile_name());
    cJSON_AddBoolToObject(usb, "host_ready", us.host_ready);
    cJSON_AddBoolToObject(usb, "can_xmit", us.can_xmit);
    cJSON_AddNumberToObject(usb, "tx_ok", us.tx_ok);
    cJSON_AddNumberToObject(usb, "tx_retried", us.tx_retried);
    cJSON_AddNumberToObject(usb, "tx_dropped", us.tx_dropped);
    cJSON_AddNumberToObject(usb, "tx_no_host", us.tx_no_host);
    cJSON_AddNumberToObject(usb, "tx_timeout", us.tx_timeout);
    cJSON_AddNumberToObject(usb, "tx_bytes", us.tx_bytes);
    cJSON_AddNumberToObject(usb, "tx_max_len", us.tx_max_len);
    cJSON_AddNumberToObject(usb, "tx_queue_depth", us.tx_queue_depth);

    cJSON *vpn = cJSON_AddObjectToObject(root, "vpn");
    cJSON_AddBoolToObject(vpn, "implemented", false);
    cJSON_AddBoolToObject(vpn, "enabled", false);
    cJSON_AddBoolToObject(vpn, "connected", vs.connected);
    cJSON_AddStringToObject(vpn, "server", vs.server);

    cJSON *routing = cJSON_AddObjectToObject(root, "routing");
    const char *def = "direct";
    meshvpn_route_action_t da = meshvpn_routing_default_action();
    if (da == MESHVPN_ROUTE_VPN) {
        def = "vpn";
    } else if (da == MESHVPN_ROUTE_BLOCK) {
        def = "block";
    }
    (void)def;
    cJSON_AddBoolToObject(routing, "implemented", false);
    cJSON_AddStringToObject(routing, "default", "direct");

    return send_json(req, root);
}

static esp_err_t handler_logs(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }

    const size_t cap = 12288;
    char *buf = malloc(cap);
    if (!buf) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_send(req, NULL, 0);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "text/plain");

    /* A snapshot header makes every copied log self-describing: without it a
     * pasted log cannot be told apart from one captured seconds after boot,
     * and the USB counters are the only way to see whether the host ever
     * configured the network interface. */
    meshvpn_wifi_status_t ws;
    meshvpn_wifi_get_status(&ws);
    meshvpn_net_status_t ns;
    meshvpn_net_get_status(&ns);
    meshvpn_usb_stats_t us;
    meshvpn_usb_get_stats(&us);

    char header[512];
    int n = snprintf(header, sizeof(header),
                     "=== meshvpn: uptime %llus, boot #%" PRIu32 ", built %s ===\n"
                     "usb:  %s host_ready=%d can_xmit=%d q=%u tx_ok=%" PRIu32 " retry=%" PRIu32
                     " drop=%" PRIu32 " nohost=%" PRIu32 " timeout=%" PRIu32 " maxlen=%u\n"
                     "wifi: connected=%d ssid=%.32s ip=%s rssi=%d reason=%u ap=%d\n"
                     "net:  usb_ip=%s ap_ip=%s usb_napt=%d ap_napt=%d\n"
                     "--- log ---\n",
                     esp_timer_get_time() / 1000000, meshvpn_config_get_boot_count(),
                     meshvpn_web_build_id(),
                     meshvpn_usb_profile_name(), us.host_ready, us.can_xmit, us.tx_queue_depth, us.tx_ok,
                     us.tx_retried, us.tx_dropped, us.tx_no_host, us.tx_timeout, us.tx_max_len,
                     ws.sta_connected, ws.ssid, ws.ip, ws.rssi, ws.disconnect_reason, ws.ap_active,
                     ns.usb_ip, ns.ap_ip, ns.usb_napt, ns.ap_napt);

    esp_err_t err = httpd_resp_send_chunk(req, header, n);
    if (err == ESP_OK) {
        size_t len = meshvpn_log_copy(buf, cap);
        err = httpd_resp_send_chunk(req, buf, len);
    }
    httpd_resp_send_chunk(req, NULL, 0);

    free(buf);
    return err;
}


static esp_err_t handler_scan(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) return ESP_FAIL;
    if (req->method == HTTP_POST) {
        if (meshvpn_wifi_scan_start() != ESP_OK) return error(req, "503 Service Unavailable", "WiFi busy");
        httpd_resp_set_status(req, "202 Accepted");
        return ok(req);
    }
    cJSON *out = cJSON_CreateObject(), *arr = cJSON_AddArrayToObject(out, "networks");
    cJSON_AddBoolToObject(out, "scanning", meshvpn_wifi_scan_busy());
    for (int i = 0; i < meshvpn_wifi_scan_get_count(); i++) {
        wifi_ap_record_t ap;
        if (meshvpn_wifi_scan_get_entry(i, &ap) != ESP_OK) continue;
        cJSON *p = cJSON_CreateObject();
        cJSON_AddStringToObject(p, "ssid", (char *)ap.ssid);
        cJSON_AddNumberToObject(p, "rssi", ap.rssi);
        cJSON_AddNumberToObject(p, "authmode", ap.authmode);
        cJSON_AddItemToArray(arr, p);
    }
    return send_json(req, out);
}
static esp_err_t handler_profiles(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) return ESP_FAIL;
    meshvpn_wifi_profiles_t profiles;
    if (meshvpn_config_load_profiles(&profiles) != ESP_OK)
        return error(req, "500 Internal Server Error", "Cannot load WiFi profiles");
    if (req->method == HTTP_GET) {
        cJSON *out = cJSON_CreateObject(), *arr = cJSON_AddArrayToObject(out, "profiles");
        for (unsigned i = 0; i < profiles.count; i++) {
            meshvpn_wifi_profile_t *p = &profiles.items[i];
            cJSON *item = cJSON_CreateObject();
            cJSON_AddNumberToObject(item, "id", p->id);
            cJSON_AddStringToObject(item, "ssid", p->ssid);
            cJSON_AddNumberToObject(item, "priority", p->priority);
            cJSON_AddNumberToObject(item, "security", p->security);
            cJSON_AddBoolToObject(item, "enabled", p->enabled);
            cJSON_AddBoolToObject(item, "hidden", p->hidden);
            cJSON_AddItemToArray(arr, item);
        }
        return send_json(req, out);
    }
    cJSON *in = body(req, 2048);
    if (!in) return ESP_FAIL;
    cJSON *id = cJSON_GetObjectItemCaseSensitive(in, "id");
    cJSON *remove = cJSON_GetObjectItemCaseSensitive(in, "delete");
    cJSON *connect = cJSON_GetObjectItemCaseSensitive(in, "connect");
    unsigned index = profiles.count;
    bool invalid = id && (!cJSON_IsNumber(id) || id->valuedouble < 1 ||
                           id->valuedouble > UINT32_MAX || floor(id->valuedouble) != id->valuedouble);
    if (id && !invalid) {
        for (unsigned i = 0; i < profiles.count; i++)
            if (profiles.items[i].id == (uint32_t)id->valuedouble) index = i;
        if (index == profiles.count) invalid = true;
    }
    uint32_t selected = 0;
    if (invalid || (!id && profiles.count == MESHVPN_WIFI_PROFILES_MAX)) goto bad;
    if (cJSON_IsTrue(remove)) {
        if (!id) goto bad;
        memmove(&profiles.items[index], &profiles.items[index + 1],
                (profiles.count - index - 1) * sizeof(profiles.items[0]));
        memset(&profiles.items[--profiles.count], 0, sizeof(profiles.items[0]));
    } else {
        meshvpn_wifi_profile_t *p = &profiles.items[index];
        if (!id) {
            if (profiles.next_id == UINT32_MAX) goto bad;
            memset(p, 0, sizeof(*p));
            p->id = profiles.next_id++;
            p->enabled = 1; p->security = 1;
            profiles.count++;
        }
        cJSON *ssid = cJSON_GetObjectItemCaseSensitive(in, "ssid");
        cJSON *pw = cJSON_GetObjectItemCaseSensitive(in, "password");
        cJSON *prio = cJSON_GetObjectItemCaseSensitive(in, "priority");
        cJSON *security = cJSON_GetObjectItemCaseSensitive(in, "security");
        cJSON *enabled = cJSON_GetObjectItemCaseSensitive(in, "enabled");
        cJSON *hidden = cJSON_GetObjectItemCaseSensitive(in, "hidden");
        if (!cJSON_IsString(ssid) || !ssid->valuestring[0] || strlen(ssid->valuestring) > 32 ||
            !cJSON_IsNumber(prio) || prio->valuedouble < -1000 || prio->valuedouble > 1000 ||
            floor(prio->valuedouble) != prio->valuedouble ||
            !cJSON_IsNumber(security) || security->valuedouble < 0 || security->valuedouble > 2 ||
            floor(security->valuedouble) != security->valuedouble ||
            !cJSON_IsBool(enabled) || !cJSON_IsBool(hidden)) goto bad;
        strcpy(p->ssid, ssid->valuestring); p->priority = prio->valueint;
        p->security = security->valueint; p->enabled = cJSON_IsTrue(enabled); p->hidden = cJSON_IsTrue(hidden);
        if (pw) {
            if (!cJSON_IsString(pw) || strlen(pw->valuestring) > 63) goto bad;
            strcpy(p->password, pw->valuestring);
        }
        if (!p->security) memset(p->password, 0, sizeof(p->password));
        if (p->security && strlen(p->password) < 8) goto bad;
        selected = p->id;
    }
    bool do_connect = cJSON_IsTrue(connect) && selected;
    cJSON_Delete(in);
    esp_err_t err = meshvpn_config_save_profiles(&profiles);
    memset(&profiles, 0, sizeof(profiles));
    if (err != ESP_OK) return error(req, "500 Internal Server Error", "Cannot save profiles");
    err = meshvpn_wifi_reload();
    if (err == ESP_OK && do_connect) err = meshvpn_wifi_select(selected);
    if (err != ESP_OK) return error(req, "503 Service Unavailable", "Saved; WiFi queue busy, retry selection");
    return ok(req);
bad:
    cJSON_Delete(in);
    memset(&profiles, 0, sizeof(profiles));
    return error(req, "400 Bad Request", "Invalid profile: SSID 1-32 bytes, WPA password 8-63 bytes");
}
static esp_err_t handler_select(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) return ESP_FAIL;
    cJSON *in = body(req, 128);
    if (!in) return ESP_FAIL;
    cJSON *id = cJSON_GetObjectItemCaseSensitive(in, "id");
    cJSON *pause = cJSON_GetObjectItemCaseSensitive(in, "pause");
    bool paused = cJSON_IsTrue(pause);
    uint32_t selected = 0;
    if (!paused) {
        if (!cJSON_IsNumber(id) || id->valuedouble < 0 || id->valuedouble > UINT32_MAX ||
            floor(id->valuedouble) != id->valuedouble) {
            cJSON_Delete(in); return error(req, "400 Bad Request", "Invalid profile id");
        }
        selected = id->valuedouble;
        if (selected) {
            meshvpn_wifi_profiles_t profiles;
            bool found = false;
            if (meshvpn_config_load_profiles(&profiles) == ESP_OK)
                for (unsigned i = 0; i < profiles.count; i++)
                    if (profiles.items[i].id == selected && profiles.items[i].enabled) found = true;
            if (!found) { cJSON_Delete(in); return error(req, "400 Bad Request", "Profile disabled or missing"); }
        }
    }
    cJSON_Delete(in);
    esp_err_t err = paused ? meshvpn_wifi_disconnect() : meshvpn_wifi_select(selected);
    return err == ESP_OK ? ok(req) : error(req, "503 Service Unavailable", "WiFi busy");
}
static esp_err_t handler_password(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) return ESP_FAIL;
    cJSON *in = body(req, 1024);
    if (!in) return ESP_FAIL;
    cJSON *pw = cJSON_GetObjectItemCaseSensitive(in, "password");
    esp_err_t err = cJSON_IsString(pw) ? meshvpn_config_save_admin_password(pw->valuestring) : ESP_ERR_INVALID_ARG;
    cJSON_Delete(in);
    if (err != ESP_OK) return error(req, "400 Bad Request", "Password must be 8-64 bytes and save successfully");
    memset(s_session_token, 0, sizeof(s_session_token));
    return ok(req);
}
static esp_err_t handler_logout(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) return ESP_FAIL;
    memset(s_session_token, 0, sizeof(s_session_token));
    return ok(req);
}
static esp_err_t handler_system(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) return ESP_FAIL;
    if (!strcmp(req->uri, "/api/system/factory-reset") && meshvpn_config_factory_reset() != ESP_OK)
        return error(req, "500 Internal Server Error", "Reset failed");
    ok(req);
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;
}
static esp_err_t handler_https(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) return ESP_FAIL;
    cJSON *in = body(req, 128);
    if (!in) return ESP_FAIL;
    cJSON *enabled = cJSON_GetObjectItemCaseSensitive(in, "enabled");
    if (!cJSON_IsBool(enabled)) {
        cJSON_Delete(in);
        return error(req, "400 Bad Request", "enabled must be a boolean");
    }
    bool next = cJSON_IsTrue(enabled);
    cJSON_Delete(in);
    /* Prepare/validate the identity before committing a transition from HTTP.
     * Failure leaves both the current listener and saved mode unchanged. */
    if (next && !s_https && meshvpn_web_tls_init() != ESP_OK)
        return error(req, "503 Service Unavailable", "Cannot prepare HTTPS identity; settings unchanged");
    if (meshvpn_config_save_https(next) != ESP_OK)
        return error(req, "500 Internal Server Error", "Cannot save HTTPS mode");
    s_https_configured = next;
    cJSON *out = cJSON_CreateObject();
    add_https_status(out);
    return send_json(req, out);
}
static esp_err_t handler_certificate(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) return ESP_FAIL;
    if (!s_https) return error(req, "403 Forbidden", "Certificate API requires HTTPS");
    if (req->method == HTTP_GET) {
        httpd_resp_set_type(req, "application/x-pem-file");
        httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=meshpn-device.pem");
        return httpd_resp_sendstr(req, meshvpn_web_tls_cert());
    }
    cJSON *in = body(req, 12288);
    if (!in) return ESP_FAIL;
    cJSON *crt = cJSON_GetObjectItemCaseSensitive(in, "certificate");
    cJSON *key = cJSON_GetObjectItemCaseSensitive(in, "private_key");
    esp_err_t err = cJSON_IsString(crt) && cJSON_IsString(key) ?
        meshvpn_web_tls_import(crt->valuestring, key->valuestring) : ESP_ERR_INVALID_ARG;
    if (cJSON_IsString(key)) memset(key->valuestring, 0, strlen(key->valuestring));
    cJSON_Delete(in);
    return err == ESP_OK ? ok(req) : error(req, "400 Bad Request", "Invalid certificate/key or storage error");
}
static esp_err_t handler_unimplemented(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) return ESP_FAIL;
    return error(req, "501 Not Implemented", "VPN and policy routing are not active in this firmware");
}

static esp_err_t handler_ranges_benchmark(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) return ESP_FAIL;
    cJSON *in = body(req, 128);
    if (!in) return ESP_FAIL;
    cJSON *count = cJSON_GetObjectItemCaseSensitive(in, "count");
    bool valid = cJSON_IsNumber(count) && count->valuedouble >= 1000 &&
        count->valuedouble <= 500000 && floor(count->valuedouble) == count->valuedouble;
    size_t n = valid ? count->valueint : 0;
    cJSON_Delete(in);
    if (!valid) return error(req, "400 Bad Request", "Count must be 1000..500000");
    size_t bytes = n * sizeof(meshvpn_ip_range_t);
    uint32_t caps = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
    if (heap_caps_get_free_size(caps) < bytes + 2 * 1024 * 1024)
        return error(req, "409 Conflict", "Benchmark would leave less than 2 MiB PSRAM");
    meshvpn_ip_range_t *ranges = heap_caps_malloc(bytes, caps);
    if (!ranges) return error(req, "503 Service Unavailable", "No contiguous PSRAM block");
    for (size_t i = 0; i < n; i++) {
        ranges[i].first = i * 4096;
        ranges[i].last = i * 4096 + 2047;
    }
    unsigned hits = 0;
    uint32_t seed = 1;
    int64_t start = esp_timer_get_time();
    for (unsigned i = 0; i < 20000; i++) {
        seed = seed * 1664525u + 1013904223u;
        hits += meshvpn_ip_ranges_contains(ranges, n, seed);
        if (!(i % 1000)) taskYIELD();
    }
    int64_t elapsed = esp_timer_get_time() - start;
    free(ranges);
    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "dataset", "synthetic IPv4 ranges; not a NAT throughput test");
    cJSON_AddNumberToObject(out, "ranges", n);
    cJSON_AddNumberToObject(out, "bytes", bytes);
    cJSON_AddNumberToObject(out, "lookups", 20000);
    cJSON_AddNumberToObject(out, "hits", hits);
    cJSON_AddNumberToObject(out, "elapsed_us", elapsed);
    cJSON_AddNumberToObject(out, "average_us", elapsed / 20000.0);
    return send_json(req, out);
}
static esp_err_t handler_redirect(httpd_req_t *req)
{
    if (!local_socket(req)) return error(req, "403 Forbidden", "USB management only");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "https://meshpn.local/");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_sendstr(req, "Open https://meshpn.local/ (or HTTPS at the USB gateway IP)");
}
esp_err_t meshvpn_web_start(void)
{
    if (s_server) return ESP_ERR_INVALID_STATE;
    esp_err_t err = meshvpn_config_load_https(&s_https_configured);
    if (err != ESP_OK) return err;
    s_https = s_https_configured;
    httpd_config_t server = HTTPD_DEFAULT_CONFIG();
    server.max_uri_handlers = 24;
    server.stack_size = 12288;
    server.max_open_sockets = 3;
    server.lru_purge_enable = true;
    server.recv_wait_timeout = 3;
    server.send_wait_timeout = 3;
    server.keep_alive_enable = true;
    server.ctrl_port = 32769;
    if (s_https) {
        err = meshvpn_web_tls_init();
        if (err != ESP_OK) return err; /* No silent plaintext fallback. BOOT resets NVS. */
        httpd_ssl_config_t cfg = HTTPD_SSL_CONFIG_DEFAULT();
        cfg.httpd = server;
        cfg.servercert = (const uint8_t *)meshvpn_web_tls_cert();
        cfg.servercert_len = strlen(meshvpn_web_tls_cert()) + 1;
        cfg.prvtkey_pem = (const uint8_t *)meshvpn_web_tls_key();
        cfg.prvtkey_len = strlen(meshvpn_web_tls_key()) + 1;
        err = httpd_ssl_start(&s_server, &cfg);
    } else err = httpd_start(&s_server, &server);
    if (err != ESP_OK) return err;
#define ROUTE(uri_, method_, fn_) { .uri = uri_, .method = method_, .handler = fn_ }
    const httpd_uri_t routes[] = {
        ROUTE("/", HTTP_GET, handler_index), ROUTE("/login", HTTP_GET, handler_login_page),
        ROUTE("/api/login", HTTP_POST, handler_api_login), ROUTE("/api/logout", HTTP_POST, handler_logout),
        ROUTE("/api/status", HTTP_GET, handler_api_status), ROUTE("/api/logs", HTTP_GET, handler_logs),
        ROUTE("/api/wifi/scan", HTTP_GET, handler_scan), ROUTE("/api/wifi/scan", HTTP_POST, handler_scan),
        ROUTE("/api/wifi/profiles", HTTP_GET, handler_profiles), ROUTE("/api/wifi/profiles", HTTP_POST, handler_profiles),
        ROUTE("/api/wifi/select", HTTP_POST, handler_select),
        ROUTE("/api/admin/password", HTTP_POST, handler_password),
        ROUTE("/api/admin/https", HTTP_POST, handler_https),
        ROUTE("/api/system/reboot", HTTP_POST, handler_system),
        ROUTE("/api/system/factory-reset", HTTP_POST, handler_system),
        ROUTE("/api/certificate", HTTP_GET, handler_certificate), ROUTE("/api/certificate", HTTP_POST, handler_certificate),
        ROUTE("/api/vpn/config", HTTP_POST, handler_unimplemented),
        ROUTE("/api/routing/rules", HTTP_POST, handler_unimplemented),
        ROUTE("/api/routing/default", HTTP_POST, handler_unimplemented),
        ROUTE("/api/routing/benchmark", HTTP_POST, handler_ranges_benchmark),
    };
    for (unsigned i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        err = httpd_register_uri_handler(s_server, &routes[i]);
        if (err != ESP_OK) { meshvpn_web_stop(); return err; }
    }
    if (s_https) {
        httpd_config_t plain = HTTPD_DEFAULT_CONFIG();
        plain.ctrl_port = 32768;
        plain.max_open_sockets = 2;
        plain.uri_match_fn = httpd_uri_match_wildcard;
        err = httpd_start(&s_redirect, &plain);
        if (err == ESP_OK) {
            const httpd_uri_t redirect = ROUTE("/*", HTTP_GET, handler_redirect);
            err = httpd_register_uri_handler(s_redirect, &redirect);
        }
        if (err != ESP_OK) {
            if (s_redirect) { httpd_stop(s_redirect); s_redirect = NULL; }
            ESP_LOGW(TAG, "HTTP redirect unavailable; HTTPS remains active");
        }
    }
    ESP_LOGI(TAG, "USB admin: %s://meshpn.local/", s_https ? "https" : "http");
    return ESP_OK;
#undef ROUTE
}
esp_err_t meshvpn_web_stop(void)
{
    if (s_redirect) { httpd_stop(s_redirect); s_redirect = NULL; }
    if (s_server) {
        if (s_https) httpd_ssl_stop(s_server);
        else httpd_stop(s_server);
        s_server = NULL;
    }
    memset(s_session_token, 0, sizeof(s_session_token));
    return ESP_OK;
}
