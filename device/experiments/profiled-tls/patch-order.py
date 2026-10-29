"""Per-connection ordering of native extension writers, before transcript hashing."""
from pathlib import Path

def apply(root):
    root=Path(root)
    def change(file,old,new):
        p=root/file;s=p.read_text()
        if s.count(old)!=1:raise SystemExit('Order patch context changed: '+file)
        p.write_text(s.replace(old,new))
    change('ssl/internal.h','struct SSL_CONFIG {\n','struct SSL_CONFIG {\n  Array<uint16_t> meshpn_extension_order;\n')
    change('include/openssl/ssl.h','OPENSSL_EXPORT void SSL_set_permute_extensions(SSL *ssl, int enabled);',
      'OPENSSL_EXPORT void SSL_set_permute_extensions(SSL *ssl, int enabled);\n'
      '// Cold-handshake ordering of native writers; no opaque extension replay.\n'
      'OPENSSL_EXPORT int SSL_set_meshpn_extension_order(SSL *ssl, const uint16_t *ids, size_t count);')
    change('ssl/ssl_lib.cc','void SSL_set_permute_extensions(SSL *ssl, int enabled) {', '''int SSL_set_meshpn_extension_order(SSL *ssl, const uint16_t *ids, size_t count) {
  if (!ssl->config || !ids || count == 0 || count > 32 || SSL_in_init(ssl) == 0) return 0;
  for (size_t i = 0; i < count; i++) {
    for (size_t j = 0; j < i; j++) if (ids[i] == ids[j]) return 0;
  }
  return ssl->config->meshpn_extension_order.CopyFrom(MakeConstSpan(ids, count));
}

void SSL_set_permute_extensions(SSL *ssl, int enabled) {''')
    change('ssl/extensions.cc','bool ssl_setup_extension_permutation(SSL_HANDSHAKE *hs) {', '''bool ssl_setup_extension_permutation(SSL_HANDSHAKE *hs) {
  const auto &order = hs->config->meshpn_extension_order;
  if (!order.empty()) {
    Array<uint8_t> permutation;
    if (!permutation.InitForOverwrite(kNumExtensions)) return false;
    bool used[kNumExtensions] = {};
    size_t next = 0;
    for (auto id : order) {
      bool found = false;
      for (size_t i = 0; i < kNumExtensions; i++) {
        if (kExtensions[i].value == id) {
          if (used[i]) return false;
          permutation[next++] = i;
          used[i] = true;
          found = true;
          break;
        }
      }
      if (!found) return false;
    }
    for (size_t i = 0; i < kNumExtensions; i++) if (!used[i]) permutation[next++] = i;
    hs->extension_permutation = std::move(permutation);
    return true;
  }''')
