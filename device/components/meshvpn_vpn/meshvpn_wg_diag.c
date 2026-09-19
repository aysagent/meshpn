/* Linker wrappers around the pinned library's transport-data crypto only.
 * Handshakes/X25519 are excluded; empty keepalives are included. No heap work
 * or logging on the packet path. The original implementation runs unchanged. */
#include "meshvpn_wg_diag.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdbool.h>
#include <stddef.h>

struct wireguard_keypair;
void __real_wireguard_encrypt_packet(uint8_t *, const uint8_t *, size_t, struct wireguard_keypair *);
bool __real_wireguard_decrypt_packet(uint8_t *, const uint8_t *, size_t, uint64_t, struct wireguard_keypair *);
static portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
static meshvpn_wg_crypto_stats_t stats;

static void record(meshvpn_wg_crypto_direction_t *d, size_t bytes, uint64_t elapsed, bool ok, int core)
{
    portENTER_CRITICAL(&lock);
    d->calls++; d->bytes += bytes; d->time_us += elapsed;
    if (elapsed > d->max_us) d->max_us = elapsed;
    if (!ok) d->failed++;
    if (core >= 0 && core < 2) d->core_calls[core]++;
    portEXIT_CRITICAL(&lock);
}
void __wrap_wireguard_encrypt_packet(uint8_t *dst, const uint8_t *src, size_t len, struct wireguard_keypair *key)
{
    int core = xPortGetCoreID();
    uint64_t start = esp_timer_get_time();
    __real_wireguard_encrypt_packet(dst, src, len, key);
    uint64_t elapsed = esp_timer_get_time() - start;
    record(&stats.encrypt, len, elapsed, true, core);
}
bool __wrap_wireguard_decrypt_packet(uint8_t *dst, const uint8_t *src, size_t len, uint64_t counter,
                                    struct wireguard_keypair *key)
{
    int core = xPortGetCoreID();
    uint64_t start = esp_timer_get_time();
    bool ok = __real_wireguard_decrypt_packet(dst, src, len, counter, key);
    uint64_t elapsed = esp_timer_get_time() - start;
    /* Exclude the 16-byte authentication tag; bytes are attempted padded data,
     * including failed authentication, NOT successfully delivered IP bytes. */
    record(&stats.decrypt, len >= 16 ? len - 16 : 0, elapsed, ok, core);
    return ok;
}
void meshvpn_wg_crypto_snapshot(meshvpn_wg_crypto_stats_t *out)
{
    portENTER_CRITICAL(&lock);
    *out = stats;
    out->sampled_us = esp_timer_get_time();
    portEXIT_CRITICAL(&lock);
}
