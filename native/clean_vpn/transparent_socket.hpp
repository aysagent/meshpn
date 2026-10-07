#pragma once
#include "transparent_auth.hpp"
#include "transparent_handshake.hpp"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <linux/netfilter_ipv4.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <memory>

namespace cvpn::transparent {
inline uint64_t monotonic_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
inline uint64_t wall_seconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
struct RelaySocket {
  int fd = -1;
  explicit RelaySocket(int value = -1) : fd(value) {}
  ~RelaySocket() { if (fd >= 0) close(fd); }
  RelaySocket(const RelaySocket&) = delete;
  RelaySocket& operator=(const RelaySocket&) = delete;
};
inline sockaddr_in socket_address(const Destination& dst) {
  sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(dst.port);
  std::copy(dst.ipv4.begin(), dst.ipv4.end(), reinterpret_cast<uint8_t*>(&a.sin_addr)); return a;
}
inline Destination original_destination(int fd) {
  sockaddr_in original{}, local{}; socklen_t n = sizeof(original), l = sizeof(local);
  require(getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &original, &n) == 0 && n == sizeof(original) &&
          original.sin_family == AF_INET && original.sin_port &&
          getsockname(fd, reinterpret_cast<sockaddr*>(&local), &l) == 0 && l == sizeof(local) &&
          local.sin_family == AF_INET, "relay_original_destination");
  // A direct connection to the listener must not turn it into an implicit
  // forward proxy. Only a tuple actually changed by REDIRECT/DNAT is admitted.
  require(original.sin_addr.s_addr != local.sin_addr.s_addr || original.sin_port != local.sin_port,
          "relay_not_redirected");
  Destination out; out.port = ntohs(original.sin_port);
  std::copy_n(reinterpret_cast<const uint8_t*>(&original.sin_addr), 4, out.ipv4.begin()); return out;
}
struct RelayLimits {
  uint64_t hello_ms = 5000, connect_ms = 3000, idle_ms = 60000, drain_ms = 10000, lifetime_ms = 600000;
  size_t sessions = 16;
  void check() const {
    require(hello_ms && hello_ms <= 5000 && connect_ms && connect_ms <= 3000 &&
            idle_ms && idle_ms <= 60000 && drain_ms && drain_ms <= 10000 &&
            lifetime_ms && lifetime_ms <= 600000 && sessions && sessions <= 16, "relay_limits");
  }
};
inline void socket_wait(int fd, short events, uint64_t end, const std::atomic<bool>& stop) {
  while (!stop.load()) {
    require(monotonic_ms() < end, "relay_socket_timeout"); pollfd p{fd, events, 0};
    int rc = poll(&p, 1, 25); require(rc >= 0 || errno == EINTR, "relay_poll");
    if (rc > 0) {
      require(!(p.revents & (POLLNVAL | POLLERR)), "relay_socket_error");
      if (p.revents & (events | POLLHUP)) return;
    }
  }
  throw std::runtime_error("relay_cancelled");
}
struct FirstHello { Hello hello; Bytes tail; };
inline FirstHello socket_hello(int fd, uint64_t end, const std::atomic<bool>& stop) {
  HelloReader reader; uint8_t buffer[16384];
  while (!reader.done()) {
    socket_wait(fd, POLLIN, end, stop);
    ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
    if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
    require(n > 0, "relay_hello_eof");
    const size_t used = reader.feed(buffer, size_t(n));
    if (reader.done()) return {reader.take(), Bytes(buffer + used, buffer + n)};
  }
  throw std::runtime_error("relay_hello_state");
}
inline void socket_connect(int fd, const Destination& dst, uint64_t end, const std::atomic<bool>& stop) {
  auto a = socket_address(dst);
  int rc = connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a));
  require(rc == 0 || errno == EINPROGRESS, "relay_connect");
  if (rc != 0) socket_wait(fd, POLLOUT, end, stop);
  int error = 0; socklen_t n = sizeof(error);
  require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &n) == 0 && !error, "relay_connect");
}

// One accepted socket, one outbound socket, two bounded queues. fd ownership
// transfers on entry, including error paths. No payload or socket leaves C++.
inline void relay_session(int accepted, bool client, const SniAuthorization& auth,
                          const Destination& client_origin, const Destination& exit,
                          const DestinationPolicy& policy, ReplayWindow& replay,
                          const std::atomic<bool>& stop, const RelayLimits& limits,
                          std::atomic<size_t>* peak_queue = nullptr, std::atomic<uint64_t>* paused_polls = nullptr) {
  RelaySocket left(accepted); limits.check();
  const int one = 1; require(setsockopt(left.fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one)) == 0, "relay_socket_option");
  const auto started = monotonic_ms(); auto first = socket_hello(left.fd, started + limits.hello_ms, stop);
  Destination target; Bytes prefix; std::string output_sni;
  if (client) {
    policy.check(client_origin); target = exit;
    prefix = auth.seal(first.hello, client_origin, wall_seconds()); output_sni = parse(prefix).sni;
  } else {
    auto authorized = auth.accept(first.hello, policy, replay, [] { return std::make_pair(wall_seconds(), monotonic_ms()); });
    target = authorized.destination; prefix = std::move(authorized.restored); output_sni = std::move(authorized.origin_sni);
  }
  HandshakeGate gate(first.hello, output_sni, started);
  RelaySocket right(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
  require(right.fd >= 0, "relay_socket");
  require(setsockopt(right.fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one)) == 0, "relay_socket_option");
  // All exit admission, including replay reservation, precedes this connect.
  // A failed connect still consumes the token. No alternate destination retry.
  if (!client) policy.check(target); // recheck after durable I/O, immediately before connect
  socket_connect(right.fd, target, monotonic_ms() + limits.connect_ms, stop);
  Queue to_right, to_left;
  auto push = [&](Queue& q, Bytes b) {
    q.push(std::move(b));
    if (peak_queue) {
      size_t previous = peak_queue->load();
      while (previous < q.size() && !peak_queue->compare_exchange_weak(previous,q.size())) {}
    }
  };
  push(to_right,std::move(prefix));
  gate.feed(HandshakeGate::Direction::client, first.tail.data(), first.tail.size(), monotonic_ms(),
            [&](const Bytes& b) { push(to_right,b); });
  bool eof_left = false, eof_right = false, shut_left = false, shut_right = false;
  uint64_t last_io = monotonic_ms(), drain_started = 0;
  // One feed can finish an already buffered 64 KiB hello and emit its tail.
  constexpr size_t reserve = 128 * 1024;
  while (!stop.load()) {
    const auto now = monotonic_ms(); gate.check_timeout(now);
    require(now - started < limits.lifetime_ms && now - last_io < limits.idle_ms &&
            (!drain_started || now - drain_started < limits.drain_ms), "relay_session_timeout");
    if (eof_left && to_right.empty() && !shut_right) {
      require(shutdown(right.fd, SHUT_WR) == 0, "relay_shutdown"); shut_right = true;
    }
    if (eof_right && to_left.empty() && !shut_left) {
      require(shutdown(left.fd, SHUT_WR) == 0, "relay_shutdown"); shut_left = true;
    }
    if (shut_left && shut_right) return;
    pollfd p[2] = {{left.fd, 0, 0}, {right.fd, 0, 0}};
    if (!eof_left && to_right.size() <= queue_limit - reserve) p[0].events |= POLLIN;
    if (!eof_right && to_left.size() <= queue_limit - reserve) p[1].events |= POLLIN;
    if (paused_polls && ((!eof_left && !(p[0].events & POLLIN)) || (!eof_right && !(p[1].events & POLLIN)))) ++*paused_polls;
    if (!to_left.empty()) p[0].events |= POLLOUT;
    if (!to_right.empty()) p[1].events |= POLLOUT;
    for (auto& item : p) if (!item.events) item.fd = -1; // HUP must not spin while backpressured
    int rc = poll(p, 2, 25); require(rc >= 0 || errno == EINTR, "relay_poll");
    if (rc <= 0) continue;
    for (int i = 0; i < 2; ++i) {
      require(!(p[i].revents & (POLLNVAL | POLLERR)), "relay_socket_error");
      Queue& output = i ? to_right : to_left;
      if ((p[i].revents & POLLOUT) && !output.empty()) {
        ssize_t n = send(p[i].fd, output.data(), output.front_size(), MSG_NOSIGNAL);
        require(n >= 0 || errno == EINTR || errno == EAGAIN, "relay_send");
        if (n > 0) { output.consume(size_t(n)); last_io = monotonic_ms(); }
      }
      if ((p[i].events & POLLIN) && (p[i].revents & (POLLIN | POLLHUP))) {
        uint8_t buffer[16384]; ssize_t n = recv(p[i].fd, buffer, sizeof(buffer), 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        require(n >= 0, "relay_recv");
        const auto direction = i ? HandshakeGate::Direction::server : HandshakeGate::Direction::client;
        if (!n) {
          gate.end(direction); (i ? eof_right : eof_left) = true;
          if (!drain_started) drain_started = monotonic_ms();
        } else {
          Queue& incoming = i ? to_left : to_right;
          gate.feed(direction, buffer, size_t(n), monotonic_ms(), [&](const Bytes& b) { push(incoming,b); });
          last_io = monotonic_ms();
        }
      }
    }
  }
  throw std::runtime_error("relay_cancelled");
}

// Bounded worker owner used by the TCP laboratory and later engine wiring.
// Listener must already be nonblocking; it is owned here. No implicit bind,
// firewall mutation, DNS lookup, packet IPC, or direct fallback.
class RelayListener {
  struct Job { std::atomic<bool> done{false}; std::thread thread;
    ~Job() { if (thread.joinable()) thread.join(); } };
  RelaySocket listener_;
  const SniAuthorization& auth_;
  Destination origin_, exit_;
  DestinationPolicy policy_;
  std::shared_ptr<ReplayWindow> replay_;
  RelayLimits limits_;
  bool client_;
  bool redirected_;
  std::atomic<bool> stop_{false};
  std::thread thread_;
  std::vector<std::unique_ptr<Job>> jobs_;
  std::mutex diagnostic_mutex_;
  std::string last_failure_;
  void reap() {
    for (auto it = jobs_.begin(); it != jobs_.end();) if ((*it)->done.load()) it = jobs_.erase(it); else ++it;
  }
  void run() {
    while (!stop_.load()) {
      reap();
      pollfd p{listener_.fd, POLLIN, 0}; if (poll(&p, 1, 25) <= 0) continue;
      require(!(p.revents & (POLLERR | POLLNVAL)), "relay_listener");
      int fd = accept4(listener_.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (fd < 0) { require(errno == EAGAIN || errno == EINTR, "relay_accept"); continue; }
      RelaySocket pending(fd);
      reap(); // workers can finish while poll waits; do not count them as active
      if (jobs_.size() >= limits_.sessions) { ++admission_dropped; continue; }
      auto job = std::make_unique<Job>(); auto* done = &job->done;
      job->thread = std::thread([this, fd, done] {
        try {
          Destination origin = origin_;
          if (client_ && redirected_) {
            // relay_session owns fd only once invoked. Close here on metadata
            // rejection, before reading TLS bytes or opening an outbound socket.
            try { origin = original_destination(fd); policy_.check(origin); }
            catch (...) { close(fd); throw; }
          }
          relay_session(fd, client_, auth_, origin, exit_, policy_, *replay_, stop_, limits_, &peak_queue, &paused_polls); ++completed;
        }
        catch (const std::exception& e) {
          std::lock_guard<std::mutex> lock(diagnostic_mutex_);
          const std::string code = e.what();
          last_failure_ = code.size() <= 64 && (code.rfind("relay_",0) == 0 || code.rfind("hello_",0) == 0 || code == "queue_limit") ? code : "relay_internal";
          ++failed;
        }
        catch (...) { ++failed; }
        *done = true;
      });
      pending.fd = -1; jobs_.push_back(std::move(job)); ++accepted;
    }
    jobs_.clear();
  }
public:
  std::atomic<uint64_t> accepted{0}, completed{0}, failed{0}, admission_dropped{0};
  std::atomic<size_t> peak_queue{0};
  std::atomic<uint64_t> paused_polls{0};
  std::atomic<bool> broken{false};
  std::string last_failure() { std::lock_guard<std::mutex> lock(diagnostic_mutex_); return last_failure_; }
  RelayListener(int fd, bool client, const SniAuthorization& auth, Destination origin, Destination exit,
                DestinationPolicy policy, RelayLimits limits = {}, std::shared_ptr<ReplayWindow> replay = {}, bool redirected = false)
    : listener_(fd), auth_(auth), origin_(origin), exit_(exit), policy_(std::move(policy)),
      replay_(replay ? std::move(replay) : std::make_shared<ReplayWindow>()), limits_(limits), client_(client), redirected_(redirected) {
    replay_->check_scope(auth_.replay_scope());
    limits_.check(); jobs_.reserve(limits_.sessions);
    const int flags = fcntl(listener_.fd, F_GETFL);
    require(flags >= 0 && (flags & O_NONBLOCK), "relay_listener_nonblocking");
    thread_ = std::thread([this] { try { run(); } catch (...) { broken = true; stop_ = true; jobs_.clear(); } });
  }
  ~RelayListener() { stop_ = true; if (thread_.joinable()) thread_.join(); }
};
} // namespace cvpn::transparent
