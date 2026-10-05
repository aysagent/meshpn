#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <stdexcept>
#include <vector>

namespace cvpn {
constexpr size_t max_packet = 65535;
constexpr size_t queue_limit = 1024 * 1024;
using Bytes = std::vector<uint8_t>;
inline bool ipv4(const uint8_t* p, size_t n) {
  if (n < 20 || n > max_packet || p[0] >> 4 != 4) return false;
  size_t h = (p[0] & 15) * 4;
  if (h < 20 || h > n || ((size_t(p[2]) << 8) | p[3]) != n) return false;
  uint32_t sum = 0;
  for (size_t i = 0; i < h; i += 2) sum += (uint16_t(p[i]) << 8) | p[i + 1];
  while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
  return sum == 65535;
}
inline Bytes frame(const uint8_t* p, size_t n) {
  if (!ipv4(p, n)) throw std::runtime_error("invalid_ipv4");
  Bytes b(n + 4);
  b[0] = n >> 24; b[1] = n >> 16; b[2] = n >> 8; b[3] = n;
  std::memcpy(b.data() + 4, p, n);
  return b;
}
// Only a single incomplete frame is retained. Input fragmentation is arbitrary.
class Decoder {
  Bytes bytes_;
  size_t need_ = 4;
public:
  template<class F> void feed(const uint8_t* p, size_t n, F deliver) {
    while (n) {
      auto take = std::min(n, need_ - bytes_.size());
      bytes_.insert(bytes_.end(), p, p + take); p += take; n -= take;
      if (bytes_.size() != need_) continue;
      if (need_ == 4) {
        uint32_t len = (uint32_t(bytes_[0]) << 24) | (uint32_t(bytes_[1]) << 16) | (uint32_t(bytes_[2]) << 8) | bytes_[3];
        if (len < 20 || len > max_packet) throw std::runtime_error("invalid_frame_length");
        need_ = len + 4;
      } else {
        if (!ipv4(bytes_.data() + 4, bytes_.size() - 4)) throw std::runtime_error("invalid_ipv4");
        deliver(Bytes(bytes_.begin() + 4, bytes_.end()));
        bytes_.clear(); need_ = 4;
      }
    }
  }
};
// Bounded native queue. Overflow is a session error, never unlimited buffering.
class Queue {
  std::deque<Bytes> items_;
  size_t bytes_ = 0, offset_ = 0;
public:
  size_t size() const { return bytes_; }
  bool empty() const { return items_.empty(); }
  void push(Bytes b) {
    if (b.empty()) return;
    if (b.size() > queue_limit - bytes_) throw std::runtime_error("queue_limit");
    bytes_ += b.size(); items_.push_back(std::move(b));
  }
  const uint8_t* data() const { return items_.front().data() + offset_; }
  size_t front_size() const { return items_.front().size() - offset_; }
  void consume(size_t n) {
    if (n > front_size()) throw std::runtime_error("queue_consume");
    bytes_ -= n; offset_ += n;
    if (offset_ == items_.front().size()) { items_.pop_front(); offset_ = 0; }
  }
  size_t read(uint8_t* out, size_t n) {
    size_t total = 0;
    while (n && !empty()) {
      auto k = std::min(n, front_size());
      std::memcpy(out, data(), k); consume(k); out += k; n -= k; total += k;
    }
    return total;
  }
};
}
