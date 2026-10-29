#include "meshvpn_vpn_tls.h"
#include "meshvpn_vpn_trust.h"
#include "meshvpn_vpn_client_identity.h"
#include "nvs.h"
#include "mbedtls/x509.h"

#include "sdkconfig.h"
#include "meshvpn_vpn_frame.h"
#include "esp_log.h"
#include "esp_tls_errors.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>

static portMUX_TYPE diag_lock = portMUX_INITIALIZER_UNLOCKED;
static meshvpn_vpn_tls_diag_t diag;
static void record(const char *reason, int sdk, int tls, int flags)
{
    portENTER_CRITICAL(&diag_lock);
    diag.sdk_error = sdk; diag.mbedtls_error = tls; diag.verify_flags = flags;
    strlcpy(diag.reason, reason, sizeof(diag.reason));
    portEXIT_CRITICAL(&diag_lock);
}
void meshvpn_vpn_tls_get_diag(meshvpn_vpn_tls_diag_t *out)
{
    portENTER_CRITICAL(&diag_lock); *out = diag; portEXIT_CRITICAL(&diag_lock);
}
static const char *TAG = "meshvpn_vpn_tls";

#if !CONFIG_MBEDTLS_SSL_PROTO_TLS1_2
#error "Raw TLS transport requires CONFIG_MBEDTLS_SSL_PROTO_TLS1_2=y"
#endif
#if !CONFIG_MBEDTLS_HAVE_TIME_DATE || CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY
#error "VPN TLS requires certificate validity checks and forbids insecure fallback"
#endif

esp_err_t meshvpn_vpn_tls_connect(const char *server, const char *tls_server_name,
                                  const char *ifname, esp_tls_t **out_tls, int *out_fd)
{
    if (!server || !ifname || !out_tls || !out_fd) { errno = EINVAL; return ESP_ERR_INVALID_ARG; }
    *out_tls = NULL; *out_fd = -1;
    if (!meshvpn_vpn_tls_name_valid(tls_server_name)) {
        record("server_name_required", 0, 0, 0); errno = EINVAL; return ESP_ERR_INVALID_ARG;
    }
    if (time(NULL) < 1704067200) {
        record("waiting_for_clock", 0, 0, 0); errno = EAGAIN; return ESP_FAIL;
    }
    uint8_t address[4]; uint16_t port;
    if (!meshvpn_vpn_endpoint(server, address, &port)) { errno = EINVAL; return ESP_ERR_INVALID_ARG; }
    char host[16];
    snprintf(host, sizeof(host), "%u.%u.%u.%u", address[0], address[1], address[2], address[3]);
    struct ifreq iface = {0};
    strlcpy(iface.ifr_name, ifname, sizeof(iface.ifr_name));
    char *ca = NULL;
    esp_err_t ca_error = meshvpn_vpn_ca_load(&ca);
    if (ca_error != ESP_OK) {
        record("ca_missing_or_unreadable", ca_error, 0, 0); errno = EACCES; return ca_error;
    }
    meshvpn_client_identity_t *identity = NULL;
    esp_err_t identity_error = meshvpn_client_identity_load(&identity);
    if (identity_error != ESP_OK && identity_error != ESP_ERR_NVS_NOT_FOUND) {
        free(ca); record("client_identity_unreadable", identity_error, 0, 0);
        errno = identity_error == ESP_ERR_NO_MEM ? ENOMEM : EACCES;
        return identity_error; /* Never downgrade a broken saved identity to anonymous TLS. */
    }
    esp_tls_t *tls = esp_tls_init();
    if (!tls) { meshvpn_client_identity_free(identity); free(ca); record("no_memory", ESP_ERR_NO_MEM, 0, 0); errno = ENOMEM; return ESP_ERR_NO_MEM; }
    esp_tls_cfg_t cfg = {0};
    cfg.if_name = &iface;
    cfg.timeout_ms = 5000;
    cfg.tls_version = ESP_TLS_VER_TLS_1_2;
    cfg.skip_common_name = false;
    cfg.common_name = tls_server_name;
    cfg.cacert_buf = (const unsigned char *)ca;
    cfg.cacert_bytes = strlen(ca) + 1;
    if (identity) {
        cfg.clientcert_buf = (const unsigned char *)identity->certificate;
        cfg.clientcert_bytes = strlen(identity->certificate) + 1;
        cfg.clientkey_buf = (const unsigned char *)identity->private_key;
        cfg.clientkey_bytes = strlen(identity->private_key) + 1;
    }
    record("connecting", 0, 0, 0);
    ESP_LOGI(TAG, "TLS 1.2 connect start: internal free=%u largest=%u, PSRAM free=%u, rx stack spare=%u",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT),
             (unsigned)uxTaskGetStackHighWaterMark(NULL));
    int result = esp_tls_conn_new_sync(host, strlen(host), port, &cfg, tls);
    meshvpn_client_identity_free(identity);
    free(ca); /* ESP-TLS parsed its own CA chain during the synchronous handshake. */
    ESP_LOGI(TAG, "TLS connect done (%d): internal free=%u largest=%u, PSRAM free=%u, rx stack spare=%u",
             result,
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT),
             (unsigned)uxTaskGetStackHighWaterMark(NULL));
    if (result != 1 || esp_tls_get_conn_sockfd(tls, out_fd) != ESP_OK) {
        esp_tls_error_handle_t handle = NULL;
        int system_error = 0, tls_error = 0, flags = 0;
        esp_err_t sdk_error = ESP_FAIL;
        if (esp_tls_get_error_handle(tls, &handle) == ESP_OK) {
            esp_tls_get_and_clear_error_type(handle, ESP_TLS_ERR_TYPE_SYSTEM, &system_error);
            sdk_error = esp_tls_get_and_clear_last_error(handle, &tls_error, &flags);
        }
        const char *reason = flags & MBEDTLS_X509_BADCERT_CN_MISMATCH ? "certificate_name_mismatch" :
            flags & MBEDTLS_X509_BADCERT_EXPIRED ? "certificate_expired" :
            flags & MBEDTLS_X509_BADCERT_FUTURE ? "certificate_not_yet_valid" :
            flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED ? "certificate_untrusted" :
            flags ? "certificate_rejected" : "handshake_failed";
        record(reason, sdk_error, tls_error, flags);
        int connect_error = flags ? EACCES : sdk_error == ESP_ERR_ESP_TLS_CONNECTION_TIMEOUT ? ETIMEDOUT :
                            system_error ? system_error : EPROTO;
        ESP_LOGW(TAG, "TLS connect to %s failed (%d): errno=%d sdk=0x%x tls=%d flags=0x%x",
                 server, result, connect_error, (unsigned)sdk_error, tls_error, (unsigned)flags);
        esp_tls_conn_destroy(tls);
        errno = connect_error;
        return ESP_FAIL;
    }
    /* esp_tls_conn_new_sync() restores blocking mode after the handshake.
     * The VPN RX/TX workers poll this socket with select(), so a partial TLS
     * record must return WANT_READ instead of blocking up to timeout_ms. */
    int flags = fcntl(*out_fd, F_GETFL, 0);
    if (flags < 0 || fcntl(*out_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        int setup_error = errno;
        record("socket_setup_failed", setup_error, 0, 0);
        ESP_LOGW(TAG, "TLS socket non-blocking setup failed: errno=%d", setup_error);
        esp_tls_conn_destroy(tls);
        errno = setup_error;
        return ESP_FAIL;
    }
    *out_tls = tls;
    record("verified", 0, 0, 0);
    ESP_LOGI(TAG, "raw TLS 1.2 connected to %s via %s (CA/name/time verified)", server, ifname);
    return ESP_OK;
}
