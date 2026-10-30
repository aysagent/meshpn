#include "profile_gcm.h"
#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <mbedtls/gcm.h>
#include <cstring>
#include "esp_heap_caps.h"

// TLS records are at most 16KiB plus bounded TLS 1.3 padding/inner type.
// One temporary DMA slab also holds AAD/nonce/tag, ensuring the P4 full GCM
// accelerator can be used when the caller's buffers/worker stack are PSRAM.
// This is shared neither across calls nor across TLS connections.
int meshvpn_profile_gcm(bool encrypt, const uint8_t *key, size_t key_len,
                        bssl::Span<const CRYPTO_IOVEC> data,
                        bssl::Span<const uint8_t> nonce,
                        bssl::Span<const CRYPTO_IVEC> aad,
                        uint8_t *tag_out, const uint8_t *tag_in, size_t tag_len) {
    constexpr size_t max_data = 18432, max_aad = 1024, max_nonce = 64;
    if (!key || (key_len != 16 && key_len != 24 && key_len != 32) ||
        nonce.empty() || nonce.size() > max_nonce || !tag_len || tag_len > 16 ||
        (encrypt ? !tag_out : !tag_in) || data.size() > CRYPTO_IOVEC_MAX || aad.size() > CRYPTO_IOVEC_MAX) {
        OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE); return 0;
    }
    size_t length = 0, aad_len = 0;
    for (const auto &v : data) {
        if (v.len > max_data - length || (v.len && (!v.in || !v.out))) {
            OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE); return 0;
        }
        length += v.len;
    }
    for (const auto &v : aad) {
        if (v.len > max_aad - aad_len || (v.len && !v.in)) {
            OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE); return 0;
        }
        aad_len += v.len;
    }
    const size_t data_padded = (length + 15) & ~size_t(15);
    const size_t aad_padded = (aad_len + 15) & ~size_t(15);
    const size_t allocation = data_padded + aad_padded + max_nonce + 16;
    auto *slab = static_cast<uint8_t *>(heap_caps_malloc(allocation, MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA | MALLOC_CAP_8BIT));
    if (!slab) { OPENSSL_PUT_ERROR(CIPHER, ERR_R_MALLOC_FAILURE); return 0; }
    // Even empty input has a valid pointer. The IDF backend handles empty GCM
    // through its partial hardware path rather than submitting zero-byte DMA.
    uint8_t *ad = slab + data_padded, *iv = ad + aad_padded, *tag = iv + max_nonce;
    size_t at = 0;
    for (const auto &v : data) { if (v.len) std::memcpy(slab + at, v.in, v.len); at += v.len; }
    at = 0;
    for (const auto &v : aad) { if (v.len) std::memcpy(ad + at, v.in, v.len); at += v.len; }
    std::memcpy(iv, nonce.data(), nonce.size());
    if (!encrypt) std::memcpy(tag, tag_in, tag_len);
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
    if (!rc) {
        if (encrypt) rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, length, iv, nonce.size(), ad, aad_len, slab, slab, tag_len, tag);
        else rc = mbedtls_gcm_auth_decrypt(&ctx, length, iv, nonce.size(), ad, aad_len, tag, tag_len, slab, slab);
    }
    mbedtls_gcm_free(&ctx);
    if (!rc) {
        at = 0;
        for (const auto &v : data) { if (v.len) std::memcpy(v.out, slab + at, v.len); at += v.len; }
        if (encrypt) std::memcpy(tag_out, tag, tag_len);
    }
    OPENSSL_cleanse(slab, allocation);
    heap_caps_free(slab);
    if (rc) { OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT); return 0; }
    return 1;
}

bool meshvpn_profile_gcm_self_test() {
    // One-block AES-128/256 GCM KATs. These run on the real selected IDF
    // backend before each TLS connection; a failed accelerator stays closed.
    const uint8_t expected[][16] = {
        {0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78},
        {0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18}};
    const uint8_t expected_tag[][16] = {
        {0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf},
        {0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19}};
    uint8_t key[32]={},nonce[12]={},plain[16]={},cipher[16]={},tag[16]={},decoded[16]={};
    CRYPTO_IOVEC enc{cipher,plain,16},dec{decoded,cipher,16};
    for (unsigned i=0;i<2;i++) {
        const size_t key_len=i?32:16;
        if (!meshvpn_profile_gcm(true,key,key_len,{&enc,1},nonce,{},tag,nullptr,16) ||
            CRYPTO_memcmp(cipher,expected[i],16) || CRYPTO_memcmp(tag,expected_tag[i],16) ||
            !meshvpn_profile_gcm(false,key,key_len,{&dec,1},nonce,{},nullptr,tag,16) ||
            CRYPTO_memcmp(plain,decoded,16)) return false;
        tag[0]^=1;std::memset(decoded,0xa5,sizeof(decoded));
        if (meshvpn_profile_gcm(false,key,key_len,{&dec,1},nonce,{},nullptr,tag,16)) return false;
        for (auto byte:decoded) if(byte!=0xa5)return false;
        ERR_clear_error(); // Only the deliberately invalid KAT tag is expected.
    }
    return true;
}
