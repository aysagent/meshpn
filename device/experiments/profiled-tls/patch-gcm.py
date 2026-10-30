"""Optional device-only AES-GCM adapter; keep upstream nonce discipline intact."""
def apply(root):
    p = root / 'crypto/fipsmodule/cipher/e_aes.cc.inc'
    s = p.read_text()
    def replace(old, new):
        nonlocal s
        if s.count(old) != 1:
            raise RuntimeError('GCM patch context changed: ' + old[:90])
        s = s.replace(old, new)
    replace('#include <openssl/span.h>', '#include <openssl/span.h>\n#if defined(MESHPN_P4_GCM)\n#include "profile_gcm.h"\n#endif')
    replace('struct aead_aes_gcm_ctx {\n  GCM128_KEY key;\n};', '''struct aead_aes_gcm_ctx {
#if defined(MESHPN_P4_GCM)
  uint8_t raw_key[32];
  size_t raw_key_len;
#else
  GCM128_KEY key;
#endif
};''')
    replace('  CRYPTO_gcm128_init_aes_key(&gcm_ctx->key, key, key_len);', '''#if defined(MESHPN_P4_GCM)
  memcpy(gcm_ctx->raw_key, key, key_len);
  gcm_ctx->raw_key_len = key_len;
#else
  CRYPTO_gcm128_init_aes_key(&gcm_ctx->key, key, key_len);
#endif''')
    replace('static void aead_aes_gcm_cleanup(EVP_AEAD_CTX *ctx) {}', '''static void aead_aes_gcm_cleanup(EVP_AEAD_CTX *ctx) {
#if defined(MESHPN_P4_GCM)
  OPENSSL_cleanse(&ctx->state, sizeof(ctx->state));
#endif
}''')
    # These two implementation functions are also reached through upstream's
    # TLS 1.2/1.3 nonce checks. Do not replace their wrappers or getter choices.
    first = s.index('static int aead_aes_gcm_sealv_impl(')
    last = s.index('\nstatic int aead_aes_gcm_sealv(', first)
    section = s[first:last]
    begin = section.index('  const GCM128_KEY *key = &gcm_ctx->key;')
    section = section[:begin] + '''#if defined(MESHPN_P4_GCM)
  if (!meshvpn_profile_gcm(true, gcm_ctx->raw_key, gcm_ctx->raw_key_len,
                          iovecs, nonce, aadvecs, out_tag.data(), nullptr, tag_len)) return 0;
  *out_tag_len = tag_len;
  return 1;
#else
''' + section[begin:]
    section = section.rstrip()[:-1] + '#endif\n}\n'
    s = s[:first] + section + s[last:]
    first = s.index('static int aead_aes_gcm_openv_detached_impl(')
    last = s.index('\nstatic int aead_aes_gcm_openv_detached(', first)
    section = s[first:last].replace('  uint8_t tag[EVP_AEAD_AES_GCM_TAG_LEN];', '')
    begin = section.index('  const GCM128_KEY *key = &gcm_ctx->key;')
    section = section[:begin] + '''#if defined(MESHPN_P4_GCM)
  return meshvpn_profile_gcm(false, gcm_ctx->raw_key, gcm_ctx->raw_key_len,
                            iovecs, nonce, aadvecs, nullptr, in_tag.data(), tag_len);
#else
  uint8_t tag[EVP_AEAD_AES_GCM_TAG_LEN];
''' + section[begin:]
    section = section.rstrip()[:-1] + '#endif\n}\n'
    s = s[:first] + section + s[last:]
    p.write_text(s)
