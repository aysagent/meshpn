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
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <iostream>
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

  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

  // Порядок suite’ов в духе Chrome / TLS 1.3
  SSL_CTX_set_cipher_list(
      ctx,
      "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");

  SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384");
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
