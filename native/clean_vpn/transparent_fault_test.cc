// Real TCP workers and admission, with a raw origin to control precise faults.
// This complements (does not replace) the certificate-verified TLS socket test.
#include "transparent_socket.hpp"
#include <openssl/ssl.h>
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace cvpn;
using namespace cvpn::transparent;
static void need(bool ok, int line = __builtin_LINE()) {
  if (!ok) throw std::runtime_error("transparent_fault_line_" + std::to_string(line));
}
template<class F> static void until(F f, uint64_t ms = 3000) {
  const auto end = monotonic_ms() + ms;
  while (!f()) { need(monotonic_ms() < end); std::this_thread::sleep_for(std::chrono::milliseconds(5)); }
}
struct Listener {
  RelaySocket socket{::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
  Destination destination{{127,0,0,1},0};
  Listener() {
    auto a = socket_address(destination); need(socket.fd >= 0);
    need(bind(socket.fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
    socklen_t n = sizeof(a); need(getsockname(socket.fd, reinterpret_cast<sockaddr*>(&a), &n) == 0);
    destination.port = ntohs(a.sin_port); need(listen(socket.fd, 32) == 0);
  }
  int release() { const auto fd = socket.fd; socket.fd = -1; return fd; }
  int accept() {
    int fd = -1;
    until([&] { fd = accept4(socket.fd, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK); return fd >= 0; });
    return fd;
  }
};
static int connect_to(const Destination& d) {
  RelaySocket s(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)); need(s.fd >= 0);
  auto a = socket_address(d); need(connect(s.fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
  int one = 1; need(setsockopt(s.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0);
  need(fcntl(s.fd, F_SETFL, O_NONBLOCK) == 0);
  const auto fd = s.fd; s.fd = -1; return fd;
}
static void send_all(int fd, const Bytes& b, size_t chunk = 65536) {
  size_t at = 0;
  until([&] {
    const auto n = send(fd, b.data() + at, std::min(chunk, b.size() - at), MSG_NOSIGNAL);
    if (n > 0) at += size_t(n); else need(n < 0 && (errno == EAGAIN || errno == EINTR));
    return at == b.size();
  }, 5000);
}
static void closed(int fd, uint64_t ms = 3000) {
  until([&] { uint8_t b[4096]; const auto n = recv(fd, b, sizeof(b), 0);
    return n == 0 || (n < 0 && errno == ECONNRESET); }, ms);
}
static size_t entries(const char* p) {
  return size_t(std::distance(std::filesystem::directory_iterator(p), std::filesystem::directory_iterator{}));
}
static size_t rss() {
  std::ifstream f("/proc/self/status"); std::string key;
  while (f >> key) { if (key == "VmRSS:") { size_t n; f >> n; return n; } std::string rest; std::getline(f,rest); }
  throw std::runtime_error("missing_rss");
}
static Bytes hello() {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method())); need(bool(ctx));
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get())); need(bool(ssl));
  BIO* in = BIO_new(BIO_s_mem()); BIO* out = BIO_new(BIO_s_mem()); need(in && out);
  BIO_set_mem_eof_return(in, -1); SSL_set_bio(ssl.get(), in, out); SSL_set_connect_state(ssl.get());
  need(SSL_set_tlsext_host_name(ssl.get(), "origin.example"));
  const auto rc = SSL_do_handshake(ssl.get()); need(rc < 0 && SSL_get_error(ssl.get(), rc) == SSL_ERROR_WANT_READ);
  Bytes b(16384); const auto n = BIO_read(out, b.data(), b.size()); need(n > 0); b.resize(n); return b;
}
static Bytes recordize(const Bytes& p, size_t split) {
  Bytes b; size_t at = 0;
  for (const auto n : {split, p.size() - split}) {
    need(n > 0 && n <= record_limit);
    b.insert(b.end(), {22,3,3,uint8_t(n >> 8),uint8_t(n)});
    b.insert(b.end(), p.begin() + at, p.begin() + at + n); at += n;
  }
  return b;
}
static void fragments(const SniAuthorization& auth, const Hello& original) {
  Listener origin, e, c; const auto endpoint = e.destination, client_endpoint = c.destination;
  RelayListener exit(e.release(), false, auth, {}, {}, DestinationPolicy({origin.destination}));
  RelayListener client(c.release(), true, auth, origin.destination, endpoint, DestinationPolicy({origin.destination}));
  unsigned rounds = 0; const std::atomic<bool> stop{false};
  for (const auto split : {size_t(1), original.host_at + 2, original.payload.size() - 1}) {
    const auto wire = recordize(original.payload, split);
    for (const size_t chunk : {size_t(1), size_t(5), size_t(65536)}) {
      {
        RelaySocket app(connect_to(client_endpoint)); send_all(app.fd, wire, chunk);
        RelaySocket peer(origin.accept());
        const auto got = socket_hello(peer.fd, monotonic_ms() + 2000, stop);
        need(got.hello.wire == wire && got.tail.empty());
        // A reset before ServerHello must release both relay directions.
        linger reset{1,0}; need(setsockopt(app.fd, SOL_SOCKET, SO_LINGER, &reset, sizeof(reset)) == 0);
      }
      ++rounds; until([&] { return client.failed == rounds && exit.failed == rounds; });
    }
  }
  need(!client.broken && !exit.broken);
  std::cout << "FAULT_PASS=two_hop_record_and_tcp_fragmentation_restores_wire rounds=" << rounds << '\n';
}
static void churn(const SniAuthorization& auth, const Hello& h) {
  Listener origin, e; const auto endpoint = e.destination;
  RelayLimits limits; limits.hello_ms = 200;
  RelayListener exit(e.release(), false, auth, {}, {}, DestinationPolicy({origin.destination}), limits);
  const auto baseline_fds = entries("/proc/self/fd"), baseline_threads = entries("/proc/self/task"), baseline_rss = rss();
  size_t peak_rss = baseline_rss; unsigned rounds = 0;
  for (unsigned i = 0; i < 128; ++i) {
    { RelaySocket app(connect_to(endpoint));
      const auto count = size_t(i) % (h.wire.size() - 1) + 1;
      send_all(app.fd, Bytes(h.wire.begin(), h.wire.begin() + count));
      if (i % 2) { linger reset{1,0}; need(setsockopt(app.fd,SOL_SOCKET,SO_LINGER,&reset,sizeof(reset)) == 0); }
      else need(shutdown(app.fd, SHUT_WR) == 0);
    }
    ++rounds; until([&] { return exit.failed == rounds; }); peak_rss = std::max(peak_rss, rss());
  }
  until([&] { return entries("/proc/self/fd") == baseline_fds && entries("/proc/self/task") == baseline_threads; });
  need(peak_rss < baseline_rss + 64 * 1024 && !exit.broken);
  RelaySocket unexpected(accept4(origin.socket.fd,nullptr,nullptr,SOCK_NONBLOCK)); need(unexpected.fd < 0 && errno == EAGAIN);
  // Drip bytes cannot extend the absolute ClientHello deadline.
  { RelaySocket app(connect_to(endpoint)); const auto start = monotonic_ms(); size_t at = 0;
    until([&] {
      if (at < 20) { const auto n = send(app.fd,h.wire.data() + at,1,MSG_NOSIGNAL); if (n == 1) ++at; }
      std::this_thread::sleep_for(std::chrono::milliseconds(20)); return exit.failed == rounds + 1;
    }, 1500);
    need(at >= 2 && monotonic_ms() - start >= 150 && monotonic_ms() - start < 1000);
    need(exit.last_failure() == "relay_socket_timeout"); closed(app.fd);
  }
  // Fill every admission slot, then demonstrate rejection and full reclamation.
  std::vector<std::unique_ptr<RelaySocket>> stalled;
  for (unsigned i = 0; i < 16; ++i) stalled.push_back(std::make_unique<RelaySocket>(connect_to(endpoint)));
  until([&] { return exit.accepted == rounds + 17; });
  { RelaySocket extra(connect_to(endpoint)); closed(extra.fd); }
  need(exit.admission_dropped >= 1); stalled.clear();
  until([&] { return entries("/proc/self/fd") == baseline_fds && entries("/proc/self/task") == baseline_threads; });
  need(!exit.broken);
  std::cout << "FAULT_PASS=eof_reset_churn_slowloris_and_16_slot_reclamation rounds=" << rounds
    << " baseline_fds=" << baseline_fds << " baseline_threads=" << baseline_threads << " peak_rss_kib=" << peak_rss << '\n';
}
static Bytes server_hello() {
  Bytes p(38,0); p[0] = 2; p[4] = 3; p[5] = 3;
  p.insert(p.end(), {0,0x13,1,0,0,6,0,43,0,2,3,4}); p[3] = p.size() - 4;
  Bytes b{22,3,3,0,uint8_t(p.size())}; b.insert(b.end(),p.begin(),p.end()); return b;
}
static void deadlines(const SniAuthorization& auth, const Hello& h) {
  for (const std::string mode : {"idle", "drain", "lifetime", "handshake"}) {
    Listener origin, e; const auto endpoint = e.destination; RelayLimits limits;
    if (mode == "idle") limits.idle_ms = 200;
    if (mode == "drain") limits.drain_ms = 200;
    if (mode == "lifetime") limits.lifetime_ms = 300;
    RelayListener exit(e.release(), false, auth, {}, {}, DestinationPolicy({origin.destination}), limits);
    RelaySocket app(connect_to(endpoint)); send_all(app.fd, auth.seal(h,origin.destination,wall_seconds()));
    RelaySocket peer(origin.accept()); const std::atomic<bool> stop{false};
    need(socket_hello(peer.fd,monotonic_ms() + 2000,stop).hello.wire == h.wire);
    if (mode != "handshake") { send_all(peer.fd,server_hello()); uint8_t b[128]; until([&] { return recv(app.fd,b,sizeof(b),0) > 0; }); }
    if (mode == "drain") { need(shutdown(app.fd,SHUT_WR) == 0); closed(peer.fd); }
    const auto start = monotonic_ms();
    until([&] {
      if (mode == "handshake" || mode == "lifetime") {
        const Bytes keepalive = mode == "handshake" ? Bytes{20,3,3,0,1,1} : Bytes{1};
        (void)send(app.fd,keepalive.data(),keepalive.size(),MSG_NOSIGNAL);
        uint8_t sink[1024]; (void)recv(peer.fd,sink,sizeof(sink),0);
      }
      return exit.failed == 1;
    }, mode == "handshake" ? 12000 : 2000);
    need(exit.last_failure() == (mode == "handshake" ? "relay_handshake_timeout" : "relay_session_timeout"));
    if (mode == "handshake") need(monotonic_ms() - start >= 9500);
    closed(app.fd); closed(peer.fd); need(!exit.broken);
    std::cout << "FAULT_PASS=absolute_" << mode << "_deadline elapsed_ms=" << monotonic_ms() - start << '\n';
  }
}
int main() {
  try {
    Digest secret{}; secret.fill(0x42); SniAuthorization auth(secret,"relay.example"); const auto h = parse(hello());
    const auto fds = entries("/proc/self/fd"), threads = entries("/proc/self/task");
    fragments(auth,h); churn(auth,h); deadlines(auth,h);
    need(entries("/proc/self/fd") == fds && entries("/proc/self/task") == threads);
    std::cout << "FAULT_PASS=all_owners_released\n";
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
