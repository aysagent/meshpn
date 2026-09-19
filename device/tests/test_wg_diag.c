#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../components/meshvpn_vpn/meshvpn_wg_diag.c"
#include "../components/meshvpn_web/meshvpn_wg_json.c"

static uint64_t now = 5000000000ULL;
static int core;
static bool decrypt_ok;
static struct wireguard_keypair *const key = (struct wireguard_keypair *)(uintptr_t)1234;
int xPortGetCoreID(void) { return core; }
int64_t esp_timer_get_time(void) { return now; }
void __real_wireguard_encrypt_packet(uint8_t *dst, const uint8_t *src, size_t len, struct wireguard_keypair *k)
{ assert(k == key); if (len) memmove(dst, src, len); now += 123; }
bool __real_wireguard_decrypt_packet(uint8_t *dst, const uint8_t *src, size_t len, uint64_t counter, struct wireguard_keypair *k)
{ assert(k == key && counter == 42); if (decrypt_ok && len >= 16) memmove(dst, src, len - 16); now += 456; return decrypt_ok; }
int main(void)
{
    meshvpn_wg_crypto_stats_t before, after;
    meshvpn_wg_crypto_snapshot(&before);
    assert(before.sampled_us == now && !before.encrypt.calls);
    cJSON *j = cJSON_CreateObject(); meshvpn_wg_crypto_json(j);
    cJSON *enc = cJSON_GetObjectItem(cJSON_GetObjectItem(j,"crypto"),"encrypt");
    assert(cJSON_IsNull(cJSON_GetObjectItem(enc,"mean_us"))); cJSON_Delete(j);
    uint8_t src[32] = {7}, dst[32] = {0};
    __wrap_wireguard_encrypt_packet(dst, src, 32, key);
    assert(!memcmp(dst, src, 32));
    __wrap_wireguard_encrypt_packet(NULL, NULL, 0, key); /* keepalive */
    core = 1; decrypt_ok = true;
    assert(__wrap_wireguard_decrypt_packet(dst, src, 32, 42, key));
    decrypt_ok = false; memset(dst, 0xaa, sizeof(dst));
    assert(!__wrap_wireguard_decrypt_packet(dst, src, 32, 42, key));
    assert(!__wrap_wireguard_decrypt_packet(dst, src, 5, 42, key));
    assert(dst[0] == 0xaa); /* wrappers never release failed plaintext */
    meshvpn_wg_crypto_snapshot(&after); meshvpn_wg_crypto_snapshot(&before);
    assert(!memcmp(&after, &before, sizeof(after))); /* reading never resets */
    assert(after.encrypt.calls == 2 && after.encrypt.bytes == 32 && after.encrypt.time_us == 246);
    assert(after.encrypt.max_us == 123 && after.encrypt.core_calls[0] == 2 && !after.encrypt.failed);
    assert(after.decrypt.calls == 3 && after.decrypt.bytes == 32 && after.decrypt.time_us == 1368);
    assert(after.decrypt.failed == 2 && after.decrypt.core_calls[1] == 3);
    j = cJSON_CreateObject(); meshvpn_wg_crypto_json(j);
    enc = cJSON_GetObjectItem(cJSON_GetObjectItem(j,"crypto"),"encrypt");
    assert(cJSON_GetObjectItem(enc,"mean_us")->valuedouble == 123);
    cJSON_Delete(j);
    puts("WG crypto wrappers: arguments/return preserved, keepalive, failure, cores, 64-bit time, JSON and reader independence passed");
}
