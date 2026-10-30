#pragma once
#include <openssl/aead.h>
#include <openssl/span.h>

// Record-sized adapter. TLS nonce sequencing remains in BoringSSL's original
// TLS AEAD wrapper. Output is published only after the operation succeeds.
int meshvpn_profile_gcm(bool encrypt, const uint8_t *key, size_t key_len,
                        bssl::Span<const CRYPTO_IOVEC> data,
                        bssl::Span<const uint8_t> nonce,
                        bssl::Span<const CRYPTO_IVEC> aad,
                        uint8_t *tag_out, const uint8_t *tag_in, size_t tag_len);
bool meshvpn_profile_gcm_self_test();

// Since boot, across connections; counts successful PSRAM slab allocations.
uint32_t meshvpn_profile_gcm_psram_fallbacks();
