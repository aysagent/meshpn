/**
 * boring-tls-helper: TLS 1.3 клиент (BoringSSL). Протокол: scripts/boring-tls-plan.md
 *
 * Заголовки <openssl/...> — публичное API BoringSSL (совместимо по путям с OpenSSL).
 * Include и линковка ssl/crypto задаются CMake из FetchContent (google/boringssl), не из
 * системного пакета libssl — см. native/boring_tls/CMakeLists.txt.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/x509.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <cctype>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace {

constexpr uint32_t kMaxFrame = 512 * 1024;

bool WriteExact(int fd, const void* buf, size_t n) {
  const auto* p = static_cast<const uint8_t*>(buf);
  size_t w = 0;
  while (w < n) {
    ssize_t r = write(fd, p + w, n - w);
    if (r <= 0) return false;
    w += static_cast<size_t>(r);
  }
  return true;
}

bool ReadExact(int fd, void* buf, size_t n) {
  auto* p = static_cast<uint8_t*>(buf);
  size_t r = 0;
  while (r < n) {
    ssize_t x = read(fd, p + r, n - r);
    if (x <= 0) return false;
    r += static_cast<size_t>(x);
  }
  return true;
}

bool ReadFrame(int fd, std::string* out) {
  uint32_t len_be = 0;
  if (!ReadExact(fd, &len_be, 4)) return false;
  uint32_t len = ntohl(len_be);
  if (len > kMaxFrame) return false;
  out->assign(len, '\0');
  if (len == 0) return true;
  return ReadExact(fd, out->data(), len);
}

bool WriteFrame(int fd, const std::string& payload) {
  uint32_t len_be = htonl(static_cast<uint32_t>(payload.size()));
  if (!WriteExact(fd, &len_be, 4)) return false;
  if (!payload.empty() && !WriteExact(fd, payload.data(), payload.size()))
    return false;
  return true;
}

bool TcpConnect(const std::string& host, int port, int* out_fd) {
  struct addrinfo hints {};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  struct addrinfo* res = nullptr;
  std::string ps = std::to_string(port);
  if (getaddrinfo(host.c_str(), ps.c_str(), &hints, &res) != 0 || !res)
    return false;
  int fd = -1;
  for (struct addrinfo* p = res; p; p = p->ai_next) {
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) return false;
  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  *out_fd = fd;
  return true;
}

bool LoadCaFromPem(SSL_CTX* ctx, const std::string& pem) {
  X509_STORE* store = SSL_CTX_get_cert_store(ctx);
  if (!store) return false;
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) return false;
  int added = 0;
  ERR_clear_error();
  for (;;) {
    X509* x = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!x) break;
    if (X509_STORE_add_cert(store, x) == 1) added++;
    X509_free(x);
  }
  BIO_free(bio);
  return added > 0;
}

bool AlpnWire(const nlohmann::json& j_alpn, std::vector<uint8_t>* out) {
  if (!j_alpn.is_array()) return false;
  for (const auto& item : j_alpn) {
    if (!item.is_string()) return false;
    std::string p = item.get<std::string>();
    if (p.empty() || p.size() > 255) return false;
    out->push_back(static_cast<uint8_t>(p.size()));
    out->insert(out->end(), p.begin(), p.end());
  }
  return true;
}

constexpr uint16_t kGreaseTable[] = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
};

bool IsGrease(uint16_t v) {
  for (uint16_t g : kGreaseTable) {
    if (v == g) return true;
  }
  return false;
}

std::string HexLower(const uint8_t* p, size_t len) {
  static const char kHex[] = "0123456789abcdef";
  std::string out(len * 2, '\0');
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = kHex[p[i] >> 4];
    out[i * 2 + 1] = kHex[p[i] & 0xf];
  }
  return out;
}

std::string Md5HexUtf8(const std::string& s) {
  unsigned char digest[MD5_DIGEST_LENGTH];
  MD5(reinterpret_cast<const unsigned char*>(s.data()), s.size(), digest);
  return HexLower(digest, MD5_DIGEST_LENGTH);
}

std::string JoinDashDec16(const std::vector<uint16_t>& v) {
  std::string out;
  for (size_t i = 0; i < v.size(); i++) {
    if (i) out.push_back('-');
    out += std::to_string(static_cast<unsigned>(v[i]));
  }
  return out;
}

std::string JoinDashDec8(const std::vector<uint8_t>& v) {
  std::string out;
  for (size_t i = 0; i < v.size(); i++) {
    if (i) out.push_back('-');
    out += std::to_string(static_cast<unsigned>(v[i]));
  }
  return out;
}

std::string JoinCommaDec16(const std::vector<uint16_t>& v) {
  std::string out;
  for (size_t i = 0; i < v.size(); i++) {
    if (i) out.push_back(',');
    out += std::to_string(static_cast<unsigned>(v[i]));
  }
  return out;
}

std::string JoinCommaDec8(const std::vector<uint8_t>& v) {
  std::string out;
  for (size_t i = 0; i < v.size(); i++) {
    if (i) out.push_back(',');
    out += std::to_string(static_cast<unsigned>(v[i]));
  }
  return out;
}

std::string JoinCommaStrings(const std::vector<std::string>& v) {
  std::string out;
  for (size_t i = 0; i < v.size(); i++) {
    if (i) out.push_back(',');
    out += v[i];
  }
  return out;
}

struct Ja3Computed {
  uint16_t legacy_version = 0;
  std::vector<uint16_t> ciphers;
  std::vector<uint16_t> ext_types;
  std::vector<uint16_t> curves;
  std::vector<uint8_t> ec_point_formats;
  std::vector<std::string> offered_alpn;
  std::vector<uint16_t> supported_versions;
  std::string ja3_string;
  std::string ja3_md5_hex;
};

bool ComputeJa3FromClientHelloBody(const uint8_t* body, size_t n,
                                   Ja3Computed* out) {
  size_t o = 0;
  if (n < 2) return false;
  out->legacy_version =
      (static_cast<uint16_t>(body[o]) << 8) | body[o + 1];
  o += 2 + 32;
  if (o >= n) return false;
  uint8_t sid_len = body[o++];
  if (o + sid_len > n) return false;
  o += sid_len;
  if (o + 2 > n) return false;
  uint16_t cipher_len =
      (static_cast<uint16_t>(body[o]) << 8) | body[o + 1];
  o += 2;
  if (cipher_len % 2 != 0 || o + cipher_len > n) return false;
  size_t cipher_end = o + cipher_len;
  while (o < cipher_end) {
    uint16_t cs =
        (static_cast<uint16_t>(body[o]) << 8) | body[o + 1];
    o += 2;
    if (!IsGrease(cs)) out->ciphers.push_back(cs);
  }
  if (o >= n) return false;
  uint8_t comp_len = body[o++];
  if (o + comp_len > n) return false;
  o += comp_len;
  if (o + 2 > n) return false;
  uint16_t ext_total =
      (static_cast<uint16_t>(body[o]) << 8) | body[o + 1];
  o += 2;
  size_t ext_end = o + ext_total;
  if (ext_end > n) return false;

  while (o + 4 <= ext_end && o + 4 <= n) {
    uint16_t et =
        (static_cast<uint16_t>(body[o]) << 8) | body[o + 1];
    uint16_t elen =
        (static_cast<uint16_t>(body[o + 2]) << 8) | body[o + 3];
    o += 4;
    if (o + elen > n || o + elen > ext_end) return false;
    const uint8_t* edata = body + o;
    o += elen;
    if (IsGrease(et)) continue;
    out->ext_types.push_back(et);
    if (et == 0x000a && elen >= 2) {
      uint16_t glen =
          (static_cast<uint16_t>(edata[0]) << 8) | edata[1];
      for (size_t i = 2; i < 2 + static_cast<size_t>(glen) && i + 2 <= elen;
           i += 2) {
        uint16_t g =
            (static_cast<uint16_t>(edata[i]) << 8) | edata[i + 1];
        if (!IsGrease(g)) out->curves.push_back(g);
      }
    } else if (et == 0x000b && elen >= 1) {
      uint8_t flen = edata[0];
      for (size_t i = 1; i < 1 + static_cast<size_t>(flen) && i < elen;
           i++) {
        out->ec_point_formats.push_back(edata[i]);
      }
    } else if (et == 16 && elen >= 2) {
      uint16_t list_len =
          (static_cast<uint16_t>(edata[0]) << 8) | edata[1];
      size_t ao = 2;
      while (ao + 1 <= elen && list_len > 0) {
        uint8_t pl = edata[ao];
        ao += 1;
        if (ao + pl > elen) break;
        out->offered_alpn.emplace_back(
            reinterpret_cast<const char*>(edata + ao),
            static_cast<size_t>(pl));
        ao += pl;
        uint16_t consumed = static_cast<uint16_t>(1 + pl);
        if (list_len < consumed) break;
        list_len -= consumed;
      }
    } else if (et == 43 && elen >= 1) {
      uint8_t slen = edata[0];
      size_t end = 1 + static_cast<size_t>(slen);
      if (end > elen) end = elen;
      for (size_t pos = 1; pos + 1 < end; pos += 2) {
        uint16_t sv = (static_cast<uint16_t>(edata[pos]) << 8) |
                      edata[pos + 1];
        out->supported_versions.push_back(sv);
      }
    }
  }

  std::ostringstream oss;
  oss << static_cast<unsigned>(out->legacy_version) << ','
      << JoinDashDec16(out->ciphers) << ','
      << JoinDashDec16(out->ext_types) << ','
      << JoinDashDec16(out->curves) << ','
      << JoinDashDec8(out->ec_point_formats);
  out->ja3_string = oss.str();
  out->ja3_md5_hex = Md5HexUtf8(out->ja3_string);
  return true;
}

const char* NamedGroupOpenSslName(uint16_t id) {
  switch (id) {
    case 23:
      return "P-256";
    case 24:
      return "P-384";
    case 25:
      return "P-521";
    case 29:
      return "X25519";
    case 30:
      return "X448";
    case SSL_GROUP_X25519_MLKEM768:
      return "X25519MLKEM768";
    case SSL_GROUP_X25519_KYBER768_DRAFT00:
      return "X25519Kyber768Draft00";
    case SSL_GROUP_MLKEM1024:
      return "MLKEM1024";
    default:
      return nullptr;
  }
}

/** True if |id| is a cipher suite BoringSSL can negotiate on TLS 1.3. */
static bool CipherSuiteNegotiatesTls13(uint16_t id) {
  const SSL_CIPHER* c = SSL_get_cipher_by_value(id);
  if (c == nullptr) {
    return false;
  }
  return SSL_CIPHER_get_min_version(c) <= TLS1_3_VERSION &&
         SSL_CIPHER_get_max_version(c) >= TLS1_3_VERSION;
}

struct Ja3LogCfg {
  bool log_ja3 = false;
  bool ja3_verbose = false;
  bool logged = false;
  std::string expected_ja3_md5;
  bool ja3_strict = false;
  bool ja3_mismatch = false;
};

bool ApplyClientHelloProfile(SSL_CTX* ctx, const nlohmann::json& p,
                             Ja3LogCfg* ja3_cfg, std::string* err_out) {
  if (!p.contains("cipher_suites") || !p["cipher_suites"].is_array() ||
      p["cipher_suites"].empty()) {
    *err_out =
        "client_hello_profile.cipher_suites must be a non-empty array (TLS 1.3 "
        "IANA ids)";
    return false;
  }
  std::vector<uint16_t> tls13_cipher_order;
  tls13_cipher_order.reserve(p["cipher_suites"].size());
  size_t skipped_non_tls13 = 0;
  for (const auto& item : p["cipher_suites"]) {
    if (!item.is_number_unsigned() && !item.is_number_integer()) {
      *err_out = "client_hello_profile.cipher_suites must be integers";
      return false;
    }
    unsigned long raw = item.is_number_unsigned() ? item.get<unsigned long>()
                                                  : static_cast<unsigned long>(
                                                        item.get<long>());
    if (raw > 0xffff) {
      *err_out = "client_hello_profile cipher id out of uint16 range";
      return false;
    }
    auto id = static_cast<uint16_t>(raw);
    if (CipherSuiteNegotiatesTls13(id)) {
      tls13_cipher_order.push_back(id);
    } else {
      skipped_non_tls13++;
    }
  }
  if (skipped_non_tls13 > 0) {
    std::cerr << "boring-tls-helper: note: отфильтровано " << skipped_non_tls13
              << " cipher suite id из профиля (JA3 обычно смешивает TLS 1.2 и "
                 "TLS 1.3; на wire задаётся только порядок TLS 1.3).\n";
  }
  if (tls13_cipher_order.empty()) {
    std::cerr
        << "boring-tls-helper: note: в профиле не осталось TLS 1.3 cipher — "
           "используется порядок BoringSSL по умолчанию.\n";
  }
  if (SSL_CTX_set_tls13_client_cipher_order(ctx, tls13_cipher_order.data(),
                                            tls13_cipher_order.size()) != 1) {
    ERR_print_errors_fp(stderr);
    *err_out =
        "SSL_CTX_set_tls13_client_cipher_order failed (unknown TLS 1.3 cipher "
        "id, duplicate, or compliance policy mismatch)";
    return false;
  }

  if (!p.contains("supported_groups") || !p["supported_groups"].is_array() ||
      p["supported_groups"].empty()) {
    *err_out = "client_hello_profile.supported_groups must be a non-empty array";
    return false;
  }
  // ec_point_formats: сохраняются в профиле для JA3; порядок форматов на wire в BoringSSL
  // пока не задаётся отдельным API — см. scripts/boring-tls-plan.md.

  std::string groups_colon;
  for (const auto& item : p["supported_groups"]) {
    if (!item.is_number_unsigned() && !item.is_number_integer()) {
      *err_out = "client_hello_profile.supported_groups must be integers";
      return false;
    }
    unsigned long raw = item.is_number_unsigned() ? item.get<unsigned long>()
                                                  : static_cast<unsigned long>(
                                                        item.get<long>());
    if (raw > 0xffff) {
      *err_out = "client_hello_profile group id out of uint16 range";
      return false;
    }
    auto id = static_cast<uint16_t>(raw);
    const char* name = NamedGroupOpenSslName(id);
    if (!name) {
      *err_out =
          "unsupported named group id " + std::to_string(raw) +
          " (extend helper_main.cc NamedGroupOpenSslName)";
      return false;
    }
    if (!groups_colon.empty()) groups_colon.push_back(':');
    groups_colon += name;
  }

  if (SSL_CTX_set1_groups_list(ctx, groups_colon.c_str()) != 1) {
    ERR_print_errors_fp(stderr);
    *err_out = "SSL_CTX_set1_groups_list failed for profile supported_groups";
    return false;
  }

  if (ja3_cfg && p.contains("ja3_md5") && p["ja3_md5"].is_string()) {
    ja3_cfg->expected_ja3_md5 = p["ja3_md5"].get<std::string>();
    for (auto& c : ja3_cfg->expected_ja3_md5) {
      c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    }
  }
  if (ja3_cfg) {
    ja3_cfg->ja3_strict = p.value("ja3_strict", false);
  }
  return true;
}

void Ja3MsgCallback(int is_write, int /*version*/, int content_type,
                    const void* buf, size_t len, SSL* /*ssl*/, void* arg) {
  auto* cfg = static_cast<Ja3LogCfg*>(arg);
  if (!cfg || cfg->logged) return;
  if (!is_write) return;
  if (content_type != SSL3_RT_HANDSHAKE) return;
  const auto* p = static_cast<const uint8_t*>(buf);
  // TLS handshake: ClientHello type = 1 (RFC 8446).
  if (len < 4 || p[0] != 1) return;
  uint32_t hs_body_len = (static_cast<uint32_t>(p[1]) << 16) |
                         (static_cast<uint32_t>(p[2]) << 8) | p[3];
  if (len < 4 + hs_body_len) return;
  Ja3Computed computed;
  if (!ComputeJa3FromClientHelloBody(p + 4, hs_body_len, &computed)) return;

  if (!cfg->expected_ja3_md5.empty()) {
    if (computed.ja3_md5_hex != cfg->expected_ja3_md5) {
      cfg->ja3_mismatch = true;
      std::cerr << "boring-tls-helper: ja3 profile mismatch expected="
                << cfg->expected_ja3_md5 << " actual=" << computed.ja3_md5_hex
                << '\n';
    }
  }

  if (!cfg->log_ja3) {
    cfg->logged = true;
    return;
  }

  std::cerr << "boring-tls-helper: tls hello (wire): clienthello_legacy="
            << static_cast<unsigned>(computed.legacy_version)
            << " supported_versions="
            << JoinCommaDec16(computed.supported_versions)
            << " offered_alpn=" << JoinCommaStrings(computed.offered_alpn)
            << '\n';
  std::cerr
      << "boring-tls-helper: tls hello (hint): MD5 JA3 не включает строки "
         "ALPN (только типы расширений).\n";

  std::cerr << "boring-tls-helper: ja3_md5=" << computed.ja3_md5_hex << '\n';
  if (cfg->ja3_verbose) {
    constexpr size_t kHexPrev = 96;
    size_t preview_len = len < kHexPrev ? len : kHexPrev;
    std::cerr << "boring-tls-helper: ja3_string=" << computed.ja3_string
              << '\n';
    std::cerr << "boring-tls-helper: legacy_version="
              << static_cast<unsigned>(computed.legacy_version) << '\n';
    std::cerr << "boring-tls-helper: ciphers="
              << JoinCommaDec16(computed.ciphers) << '\n';
    std::cerr << "boring-tls-helper: extensions="
              << JoinCommaDec16(computed.ext_types) << '\n';
    std::cerr << "boring-tls-helper: supported_groups="
              << JoinCommaDec16(computed.curves) << '\n';
    std::cerr << "boring-tls-helper: ec_point_formats="
              << JoinCommaDec8(computed.ec_point_formats) << '\n';
    std::cerr << "boring-tls-helper: hex_preview=" << HexLower(p, preview_len)
              << '\n';
  }
  cfg->logged = true;
}

void BridgeLoop(SSL* ssl, int sock) {
  if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) return;
  if (fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK) != 0) return;

  SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);

  std::vector<char> buf(64 * 1024);
  bool stdin_eof = false;

  auto pump_ssl_to_stdout = [&]() -> bool {
    for (;;) {
      int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
      if (n > 0) {
        if (!WriteExact(STDOUT_FILENO, buf.data(), static_cast<size_t>(n)))
          return false;
        continue;
      }
      int err = SSL_get_error(ssl, n);
      if (err == SSL_ERROR_ZERO_RETURN) return false;
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) break;
      return false;
    }
    return true;
  };

  while (true) {
    while (SSL_pending(ssl) > 0) {
      if (!pump_ssl_to_stdout()) return;
    }

    struct pollfd fds[2];
    int nfds = 0;
    fds[nfds].fd = sock;
    fds[nfds].events = POLLIN;
    nfds++;
    if (!stdin_eof) {
      fds[nfds].fd = STDIN_FILENO;
      fds[nfds].events = POLLIN;
      nfds++;
    }

    int pr = poll(fds, nfds, -1);
    if (pr < 0) {
      if (errno == EINTR) continue;
      return;
    }

    if (!stdin_eof && nfds > 1 && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
      ssize_t n = read(STDIN_FILENO, buf.data(), buf.size());
      if (n <= 0) {
        stdin_eof = true;
        SSL_shutdown(ssl);
      } else {
        size_t off = 0;
        while (off < static_cast<size_t>(n)) {
          int w = SSL_write(ssl, buf.data() + off,
                            static_cast<int>(static_cast<size_t>(n) - off));
          if (w > 0) {
            off += static_cast<size_t>(w);
            continue;
          }
          int werr = SSL_get_error(ssl, w);
          if (werr == SSL_ERROR_WANT_READ) {
            struct pollfd one {};
            one.fd = sock;
            one.events = POLLIN;
            poll(&one, 1, -1);
            continue;
          }
          if (werr == SSL_ERROR_WANT_WRITE) {
            struct pollfd one {};
            one.fd = sock;
            one.events = POLLOUT;
            poll(&one, 1, -1);
            continue;
          }
          return;
        }
      }
    }

    if (fds[0].revents & (POLLIN | POLLERR | POLLHUP)) {
      if (!pump_ssl_to_stdout()) return;
    }

    if (stdin_eof && SSL_pending(ssl) == 0) {
      struct pollfd one {};
      one.fd = sock;
      one.events = POLLIN;
      one.revents = 0;
      if (poll(&one, 1, 0) == 1 && (one.revents & POLLIN)) {
        if (!pump_ssl_to_stdout()) return;
      } else if (!SSL_pending(ssl)) {
        break;
      }
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  signal(SIGPIPE, SIG_IGN);

  SSL_library_init();
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();

  std::string config_raw;
  if (!ReadFrame(STDIN_FILENO, &config_raw)) {
    std::cerr << "boring-tls-helper: failed to read config frame\n";
    return 2;
  }

  nlohmann::json cfg;
  try {
    cfg = nlohmann::json::parse(config_raw);
  } catch (...) {
    std::cerr << "boring-tls-helper: invalid JSON config\n";
    return 2;
  }

  std::string host = cfg.value("host", "");
  int port = cfg.value("port", 0);
  std::string ca_pem = cfg.value("ca_pem", "");
  std::string servername = cfg.value("servername", "");
  std::string verify_host = cfg.value("verify_host", "");
  int handshake_ms = cfg.value("handshake_timeout_ms", 30000);
  std::string profile = cfg.value("profile", "default");
  std::cerr << "boring-tls-helper: profile=" << profile << '\n';

  auto send_err = [&](const char* msg, int code) -> int {
    nlohmann::json errj;
    errj["ok"] = false;
    errj["error"] = msg;
    WriteFrame(STDOUT_FILENO, errj.dump());
    return code;
  };

  if (host.empty() || port <= 0 || ca_pem.empty() || servername.empty() ||
      verify_host.empty()) {
    return send_err(
        "missing host, port, ca_pem, servername, or verify_host", 3);
  }

  std::vector<uint8_t> alpn_wire;
  if (!cfg.contains("alpn") || !AlpnWire(cfg["alpn"], &alpn_wire)) {
    return send_err("invalid or missing alpn array", 3);
  }

  int sock = -1;
  if (!TcpConnect(host, port, &sock)) {
    return send_err("tcp connect failed", 4);
  }

  const SSL_METHOD* method = TLS_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (!ctx) {
    close(sock);
    return 5;
  }

  Ja3LogCfg ja3_cfg;
  ja3_cfg.log_ja3 = cfg.value("log_ja3", false);
  ja3_cfg.ja3_verbose = cfg.value("ja3_verbose", false);

  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

  std::string prof_err;
  if (cfg.contains("client_hello_profile") &&
      cfg["client_hello_profile"].is_object()) {
    if (!ApplyClientHelloProfile(ctx, cfg["client_hello_profile"], &ja3_cfg,
                                 &prof_err)) {
      SSL_CTX_free(ctx);
      close(sock);
      return send_err(prof_err.c_str(), 5);
    }
  } else {
    // Порядок suite’ов в духе Chrome / TLS 1.3
    SSL_CTX_set_cipher_list(
        ctx,
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256");

    SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384");
  }

  if (ja3_cfg.log_ja3 || !ja3_cfg.expected_ja3_md5.empty()) {
    SSL_CTX_set_msg_callback(ctx, Ja3MsgCallback);
    SSL_CTX_set_msg_callback_arg(ctx, &ja3_cfg);
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

  if (SSL_CTX_set_alpn_protos(ctx, alpn_wire.data(),
                              static_cast<unsigned>(alpn_wire.size())) != 0) {
    SSL_CTX_free(ctx);
    close(sock);
    return 6;
  }

  if (!LoadCaFromPem(ctx, ca_pem)) {
    SSL_CTX_free(ctx);
    close(sock);
    return send_err("failed to load CA PEM", 7);
  }

  SSL* ssl = SSL_new(ctx);
  if (!ssl) {
    SSL_CTX_free(ctx);
    close(sock);
    return 8;
  }

  SSL_set_tlsext_host_name(ssl, servername.c_str());
  SSL_set_fd(ssl, sock);

  struct timeval tv {};
  tv.tv_sec = handshake_ms / 1000;
  tv.tv_usec = (handshake_ms % 1000) * 1000;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  if (SSL_connect(ssl) != 1) {
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return send_err("SSL_connect failed", 9);
  }

  if (ja3_cfg.ja3_strict && ja3_cfg.ja3_mismatch) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return send_err("ja3 profile mismatch (strict)", 13);
  }

  X509* peer = SSL_get_peer_certificate(ssl);
  if (!peer) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return send_err("no peer certificate", 10);
  }
  int chk = X509_check_host(peer, verify_host.c_str(), verify_host.size(), 0,
                            nullptr);
  X509_free(peer);
  if (chk != 1) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return send_err("certificate host verification failed", 11);
  }

  const uint8_t* proto = nullptr;
  unsigned plen = 0;
  SSL_get0_alpn_selected(ssl, &proto, &plen);
  std::string alpn_sel;
  if (proto && plen > 0)
    alpn_sel.assign(reinterpret_cast<const char*>(proto), plen);

  nlohmann::json okj;
  okj["ok"] = true;
  okj["alpn"] = alpn_sel;
  if (!WriteFrame(STDOUT_FILENO, okj.dump())) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return 12;
  }

  tv.tv_sec = 0;
  tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  BridgeLoop(ssl, sock);

  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(sock);
  return 0;
}
