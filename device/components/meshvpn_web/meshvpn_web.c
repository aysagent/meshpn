#include "meshvpn_storage.h"
#include "meshvpn_web.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "meshvpn_board.h"
#include "meshvpn_config.h"
#include "meshvpn_dns_proxy.h"
#include "meshvpn_log.h"
#include "meshvpn_net.h"
#include "meshvpn_routing.h"
#include "meshvpn_usb.h"
#include "meshvpn_vpn.h"
#include "meshvpn_wifi.h"
#include "web_ui.h"

static const char *TAG = "meshvpn_web";
static httpd_handle_t s_server;
static char s_session_token[33];

/* Identifies which image is actually running, so a reported log can be matched
 * against a build instead of being taken on faith. */
static const char *meshvpn_web_build_id(void)
{
    return __DATE__ " " __TIME__;
}

static bool meshvpn_web_check_auth(httpd_req_t *req)
{
    char auth[128];
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth, sizeof(auth)) != ESP_OK) {
        return false;
    }
    if (strncmp(auth, "Bearer ", 7) != 0) {
        return false;
    }
    return strcmp(auth + 7, s_session_token) == 0;
}

static esp_err_t meshvpn_web_require_auth(httpd_req_t *req)
{
    if (meshvpn_web_check_auth(req)) {
        return ESP_OK;
    }
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_send(req, NULL, 0);
    return ESP_FAIL;
}

static esp_err_t send_json(httpd_req_t *req, cJSON *root)
{
    char *str = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_sendstr(req, str);
    cJSON_free(str);
    cJSON_Delete(root);
    return err;
}

static esp_err_t handler_index(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, MESHVPN_WEB_INDEX_HTML, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t handler_login_page(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, MESHVPN_WEB_LOGIN_HTML, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t handler_api_login(httpd_req_t *req)
{
    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        return ESP_FAIL;
    }
    buf[len] = '\0';

    cJSON *in = cJSON_Parse(buf);
    const cJSON *pw = cJSON_GetObjectItem(in, "password");
    char expected[64];
    meshvpn_config_load_admin_password(expected, sizeof(expected));

    if (!cJSON_IsString(pw) || strcmp(pw->valuestring, expected) != 0) {
        cJSON_Delete(in);
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_send(req, NULL, 0);
        return ESP_FAIL;
    }
    cJSON_Delete(in);

    uint8_t raw[16];
    esp_fill_random(raw, sizeof(raw));
    for (int i = 0; i < 16; i++) {
        sprintf(s_session_token + i * 2, "%02x", raw[i]);
    }
    s_session_token[32] = '\0';

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "token", s_session_token);
    return send_json(req, out);
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
    cJSON_AddStringToObject(root, "board", board->name);
    cJSON_AddNumberToObject(root, "uptime_sec", (double)(esp_timer_get_time() / 1000000));

    cJSON *wifi = cJSON_AddObjectToObject(root, "wifi");
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
    cJSON_AddBoolToObject(vpn, "enabled", vs.enabled);
    cJSON_AddBoolToObject(vpn, "connected", vs.connected);
    cJSON_AddStringToObject(vpn, "server", vs.server);
    cJSON_AddStringToObject(vpn, "transport", vs.transport);
    cJSON_AddStringToObject(vpn, "profile", vs.profile_name);
    cJSON_AddStringToObject(vpn, "last_error", vs.last_error);
    cJSON_AddNumberToObject(vpn, "bytes_in", (double)vs.bytes_in);
    cJSON_AddNumberToObject(vpn, "bytes_out", (double)vs.bytes_out);
    cJSON_AddBoolToObject(vpn, "has_ca", meshvpn_storage_has_ca());
    cJSON_AddBoolToObject(vpn, "has_psk", meshvpn_storage_has_psk());

    cJSON *routing = cJSON_AddObjectToObject(root, "routing");
    const char *def = "direct";
    meshvpn_route_action_t da = meshvpn_routing_default_action();
    if (da == MESHVPN_ROUTE_VPN) {
        def = "vpn";
    } else if (da == MESHVPN_ROUTE_BLOCK) {
        def = "block";
    }
    cJSON_AddStringToObject(routing, "default", def);

    return send_json(req, root);
}

static esp_err_t handler_wifi_scan(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }

    meshvpn_wifi_scan_start();
    cJSON *root = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(root, "networks");

    int n = meshvpn_wifi_scan_get_count();
    for (int i = 0; i < n; i++) {
        wifi_ap_record_t ap;
        if (meshvpn_wifi_scan_get_entry(i, &ap) != ESP_OK) {
            continue;
        }
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "ssid", (const char *)ap.ssid);
        cJSON_AddNumberToObject(item, "rssi", ap.rssi);
        cJSON_AddNumberToObject(item, "channel", ap.primary);
        cJSON_AddItemToArray(arr, item);
    }

    return send_json(req, root);
}

static esp_err_t handler_wifi_connect(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }

    char buf[256];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        return ESP_FAIL;
    }
    buf[len] = '\0';

    cJSON *in = cJSON_Parse(buf);
    const cJSON *ssid = cJSON_GetObjectItem(in, "ssid");
    const cJSON *pass = cJSON_GetObjectItem(in, "password");

    meshvpn_wifi_creds_t creds = {0};
    strncpy(creds.ssid, cJSON_IsString(ssid) ? ssid->valuestring : "", sizeof(creds.ssid) - 1);
    strncpy(creds.password, cJSON_IsString(pass) ? pass->valuestring : "", sizeof(creds.password) - 1);
    creds.configured = true;

    meshvpn_config_save_wifi(&creds);
    meshvpn_wifi_start_sta(&creds);

    cJSON_Delete(in);
    cJSON *out = cJSON_CreateObject();
    cJSON_AddBoolToObject(out, "ok", true);
    return send_json(req, out);
}

static esp_err_t handler_admin_password(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }

    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        return ESP_FAIL;
    }
    buf[len] = '\0';

    cJSON *in = cJSON_Parse(buf);
    const cJSON *pw = cJSON_GetObjectItem(in, "password");
    if (cJSON_IsString(pw)) {
        meshvpn_config_save_admin_password(pw->valuestring);
    }
    cJSON_Delete(in);

    cJSON *out = cJSON_CreateObject();
    cJSON_AddBoolToObject(out, "ok", true);
    return send_json(req, out);
}

static esp_err_t handler_captive_ok(httpd_req_t *req)
{
    /* iOS and macOS probe these URLs to decide whether the network has internet.
     * A plain 200 + "Success" keeps the USB interface marked as online. */
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req,
                           "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
                           HTTPD_RESP_USE_STRLEN);
}

static esp_err_t handler_generate_204(httpd_req_t *req)
{
    httpd_resp_set_status(req, "204 No Content");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
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

static esp_err_t handler_reboot(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }
    httpd_resp_sendstr(req, "{\"ok\":true}");
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;
}

static esp_err_t handler_factory_reset(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }
    meshvpn_config_factory_reset();
    httpd_resp_sendstr(req, "{\"ok\":true}");
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;
}

static meshvpn_route_action_t parse_action(const char *s)
{
    if (strcmp(s, "vpn") == 0) {
        return MESHVPN_ROUTE_VPN;
    }
    if (strcmp(s, "block") == 0) {
        return MESHVPN_ROUTE_BLOCK;
    }
    return MESHVPN_ROUTE_DIRECT;
}

static esp_err_t handler_routing_rules_get(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(root, "rules");
    int n = meshvpn_routing_get_rule_count();
    for (int i = 0; i < n; i++) {
        meshvpn_route_rule_t r;
        meshvpn_routing_get_rule(i, &r);
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "index", i);
        cJSON_AddStringToObject(item, "match", r.match);
        cJSON_AddBoolToObject(item, "enabled", r.enabled);
        const char *act = "direct";
        if (r.action == MESHVPN_ROUTE_VPN) {
            act = "vpn";
        } else if (r.action == MESHVPN_ROUTE_BLOCK) {
            act = "block";
        }
        cJSON_AddStringToObject(item, "action", act);
        cJSON_AddItemToArray(arr, item);
    }
    return send_json(req, root);
}

static esp_err_t handler_routing_rules_post(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }

    char buf[256];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        return ESP_FAIL;
    }
    buf[len] = '\0';

    cJSON *in = cJSON_Parse(buf);
    meshvpn_route_rule_t rule = {0};
    rule.type = MESHVPN_RULE_IP_CIDR;
    rule.enabled = true;
    const cJSON *match = cJSON_GetObjectItem(in, "match");
    const cJSON *action = cJSON_GetObjectItem(in, "action");
    if (cJSON_IsString(match)) {
        strncpy(rule.match, match->valuestring, sizeof(rule.match) - 1);
    }
    if (cJSON_IsString(action)) {
        rule.action = parse_action(action->valuestring);
    }
    meshvpn_routing_add_rule(&rule);
    cJSON_Delete(in);

    cJSON *out = cJSON_CreateObject();
    cJSON_AddBoolToObject(out, "ok", true);
    return send_json(req, out);
}

static esp_err_t handler_routing_default(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }

    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        return ESP_FAIL;
    }
    buf[len] = '\0';

    cJSON *in = cJSON_Parse(buf);
    const cJSON *action = cJSON_GetObjectItem(in, "action");
    if (cJSON_IsString(action)) {
        meshvpn_routing_set_default_action(parse_action(action->valuestring));
    }
    cJSON_Delete(in);

    cJSON *out = cJSON_CreateObject();
    cJSON_AddBoolToObject(out, "ok", true);
    return send_json(req, out);
}

static esp_err_t handler_vpn_config_get(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }

    meshvpn_vpn_config_t cfg;
    meshvpn_config_load_vpn(&cfg);

    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "transport", cfg.transport);
    cJSON_AddStringToObject(out, "server", cfg.server);
    cJSON_AddStringToObject(out, "tls_server_name", cfg.tls_server_name);
    cJSON_AddStringToObject(out, "tls_public_name", cfg.tls_public_name);
    cJSON_AddNumberToObject(out, "http_vers", cfg.http_vers);
    cJSON_AddStringToObject(out, "profile_name", cfg.profile_name);
    cJSON_AddBoolToObject(out, "ja3_strict", cfg.ja3_strict);
    cJSON_AddBoolToObject(out, "enabled", cfg.enabled);
    cJSON_AddBoolToObject(out, "has_ca", meshvpn_storage_has_ca());
    cJSON_AddBoolToObject(out, "has_psk", meshvpn_storage_has_psk());
    return send_json(req, out);
}

static esp_err_t read_upload_body(httpd_req_t *req, uint8_t **out_buf, size_t *out_len)
{
    size_t total = req->content_len;
    if (total == 0 || total > 65536) {
        return ESP_ERR_INVALID_SIZE;
    }
    uint8_t *buf = malloc(total);
    if (!buf) {
        return ESP_ERR_NO_MEM;
    }
    size_t got = 0;
    while (got < total) {
        int r = httpd_req_recv(req, (char *)buf + got, total - got);
        if (r <= 0) {
            free(buf);
            return ESP_FAIL;
        }
        got += (size_t)r;
    }
    *out_buf = buf;
    *out_len = got;
    return ESP_OK;
}

static esp_err_t handler_vpn_cert_ca(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }
    uint8_t *buf = NULL;
    size_t len = 0;
    if (read_upload_body(req, &buf, &len) != ESP_OK) {
        return ESP_FAIL;
    }
    esp_err_t err = meshvpn_storage_write_ca(buf, len);
    free(buf);
    cJSON *out = cJSON_CreateObject();
    cJSON_AddBoolToObject(out, "ok", err == ESP_OK);
    return send_json(req, out);
}

static esp_err_t handler_vpn_cert_psk(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }
    uint8_t *buf = NULL;
    size_t len = 0;
    if (read_upload_body(req, &buf, &len) != ESP_OK) {
        return ESP_FAIL;
    }
    esp_err_t err = meshvpn_storage_write_psk(buf, len);
    free(buf);
    cJSON *out = cJSON_CreateObject();
    cJSON_AddBoolToObject(out, "ok", err == ESP_OK);
    return send_json(req, out);
}

static esp_err_t handler_vpn_profiles_get(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }
    char names[16][32];
    int n = meshvpn_storage_list_profiles(names, 16, 32);
    cJSON *out = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(out, "profiles");
    for (int i = 0; i < n; i++) {
        cJSON_AddItemToArray(arr, cJSON_CreateString(names[i]));
    }
    return send_json(req, out);
}

static esp_err_t handler_vpn_profiles_post(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }
    uint8_t *buf = NULL;
    size_t len = 0;
    if (read_upload_body(req, &buf, &len) != ESP_OK) {
        return ESP_FAIL;
    }

    const char *name = "profile";
    char *json_start = memchr(buf, '{', len);
    if (json_start) {
        cJSON *root = cJSON_Parse((const char *)json_start);
        if (root) {
            const cJSON *ua = cJSON_GetObjectItem(root, "user_agent");
            if (cJSON_IsString(ua) && ua->valuestring[0]) {
                name = ua->valuestring;
            }
            cJSON_Delete(root);
        }
    }

    esp_err_t err = meshvpn_storage_write_profile(name, buf, len);
    free(buf);
    cJSON *out = cJSON_CreateObject();
    cJSON_AddBoolToObject(out, "ok", err == ESP_OK);
    cJSON_AddStringToObject(out, "name", name);
    return send_json(req, out);
}

static esp_err_t handler_vpn_config(httpd_req_t *req)
{
    if (meshvpn_web_require_auth(req) != ESP_OK) {
        return ESP_FAIL;
    }

    char buf[512];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        return ESP_FAIL;
    }
    buf[len] = '\0';

    cJSON *in = cJSON_Parse(buf);
    meshvpn_vpn_config_t cfg;
    meshvpn_config_load_vpn(&cfg);

    const cJSON *transport = cJSON_GetObjectItem(in, "transport");
    const cJSON *server = cJSON_GetObjectItem(in, "server");
    const cJSON *sni = cJSON_GetObjectItem(in, "sni");
    const cJSON *tls_sni = cJSON_GetObjectItem(in, "tls_server_name");
    const cJSON *pub = cJSON_GetObjectItem(in, "tls_public_name");
    const cJSON *http = cJSON_GetObjectItem(in, "http_vers");
    const cJSON *profile = cJSON_GetObjectItem(in, "profile_name");
    const cJSON *ja3s = cJSON_GetObjectItem(in, "ja3_strict");
    const cJSON *enabled = cJSON_GetObjectItem(in, "enabled");

    if (cJSON_IsString(transport)) {
        strncpy(cfg.transport, transport->valuestring, sizeof(cfg.transport) - 1);
    }
    if (cJSON_IsString(server)) {
        strncpy(cfg.server, server->valuestring, sizeof(cfg.server) - 1);
    }
    if (cJSON_IsString(sni)) {
        strncpy(cfg.tls_server_name, sni->valuestring, sizeof(cfg.tls_server_name) - 1);
    }
    if (cJSON_IsString(tls_sni)) {
        strncpy(cfg.tls_server_name, tls_sni->valuestring, sizeof(cfg.tls_server_name) - 1);
    }
    if (cJSON_IsString(pub)) {
        strncpy(cfg.tls_public_name, pub->valuestring, sizeof(cfg.tls_public_name) - 1);
    }
    if (cJSON_IsNumber(http)) {
        cfg.http_vers = (uint8_t)(http->valueint == 1 ? 1 : 2);
    }
    if (cJSON_IsString(profile)) {
        strncpy(cfg.profile_name, profile->valuestring, sizeof(cfg.profile_name) - 1);
    }
    if (cJSON_IsBool(ja3s)) {
        cfg.ja3_strict = cJSON_IsTrue(ja3s);
    }
    if (cJSON_IsBool(enabled)) {
        cfg.enabled = cJSON_IsTrue(enabled);
    }

    meshvpn_config_save_vpn(&cfg);
    meshvpn_vpn_stop();
    meshvpn_vpn_start(&cfg);
    cJSON_Delete(in);

    cJSON *out = cJSON_CreateObject();
    cJSON_AddBoolToObject(out, "ok", true);
    return send_json(req, out);
}

esp_err_t meshvpn_web_start(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.max_uri_handlers = 32;
    cfg.stack_size = 8192;

    ESP_ERROR_CHECK(httpd_start(&s_server, &cfg));

    const httpd_uri_t routes[] = {
        { .uri = "/", .method = HTTP_GET, .handler = handler_index },
        { .uri = "/login", .method = HTTP_GET, .handler = handler_login_page },
        { .uri = "/hotspot-detect.html", .method = HTTP_GET, .handler = handler_captive_ok },
        { .uri = "/library/test/success.html", .method = HTTP_GET, .handler = handler_captive_ok },
        { .uri = "/generate_204", .method = HTTP_GET, .handler = handler_generate_204 },
        { .uri = "/api/login", .method = HTTP_POST, .handler = handler_api_login },
        { .uri = "/api/status", .method = HTTP_GET, .handler = handler_api_status },
        { .uri = "/api/logs", .method = HTTP_GET, .handler = handler_logs },
        { .uri = "/api/wifi/scan", .method = HTTP_GET, .handler = handler_wifi_scan },
        { .uri = "/api/wifi/connect", .method = HTTP_POST, .handler = handler_wifi_connect },
        { .uri = "/api/admin/password", .method = HTTP_POST, .handler = handler_admin_password },
        { .uri = "/api/system/reboot", .method = HTTP_POST, .handler = handler_reboot },
        { .uri = "/api/system/factory-reset", .method = HTTP_POST, .handler = handler_factory_reset },
        { .uri = "/api/routing/rules", .method = HTTP_GET, .handler = handler_routing_rules_get },
        { .uri = "/api/routing/rules", .method = HTTP_POST, .handler = handler_routing_rules_post },
        { .uri = "/api/routing/default", .method = HTTP_POST, .handler = handler_routing_default },
        { .uri = "/api/vpn/config", .method = HTTP_GET, .handler = handler_vpn_config_get },
        { .uri = "/api/vpn/config", .method = HTTP_POST, .handler = handler_vpn_config },
        { .uri = "/api/vpn/certs/ca", .method = HTTP_POST, .handler = handler_vpn_cert_ca },
        { .uri = "/api/vpn/certs/psk", .method = HTTP_POST, .handler = handler_vpn_cert_psk },
        { .uri = "/api/vpn/profiles", .method = HTTP_GET, .handler = handler_vpn_profiles_get },
        { .uri = "/api/vpn/profiles", .method = HTTP_POST, .handler = handler_vpn_profiles_post },
    };

    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        httpd_register_uri_handler(s_server, &routes[i]);
    }

    ESP_LOGI(TAG, "HTTP server on port %d", cfg.server_port);
    return ESP_OK;
}

esp_err_t meshvpn_web_stop(void)
{
    if (s_server) {
        httpd_stop(s_server);
        s_server = NULL;
    }
    return ESP_OK;
}
