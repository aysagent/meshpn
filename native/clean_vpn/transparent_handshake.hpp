#pragma once
#include "transparent_hello.hpp"
#include <functional>

namespace cvpn::transparent {
// Inspect only the plaintext initial handshake. The origin remains the TLS
// endpoint and verifies the transcript. HRR reuses the existing route/SNI token;
// it must never authorize a second connect or expose the original second SNI.
class HandshakeGate {
public:
  enum class Direction { client, server };
  using Emit = std::function<void(const Bytes&)>;
private:
  enum class Phase { first_server, retry_client, final_server, opaque };
  struct Stream { Bytes record, hello_wire, hello_payload; size_t expected = 0, records = 0; };
  Stream client_, server_;
  Phase phase_ = Phase::first_server;
  std::string input_sni_, output_sni_;
  Bytes identity_;
  bool offered_tls13_, failed_ = false;
  unsigned retries_ = 0;
  uint64_t started_;
  static constexpr uint64_t deadline_ms = 10000;

  void record(Direction direction, Stream& s, Bytes b, const Emit& emit) {
    const bool from_client = direction == Direction::client;
    if (b[0] != 22) {
      require(s.hello_wire.empty(), "relay_interleaved_handshake");
      if (b[0] == 20) {
        require(offered_tls13_ && b.size() == 6 && b[5] == 1, "relay_ccs");
      } else if (b[0] == 21) {
        require(b.size() == 7, "relay_alert");
      } else {
        // TLS 1.3 0-RTT is opaque and may cross HRR in flight. It neither
        // disables ClientHello2 inspection nor extends the handshake deadline.
        require(b[0] == 23 && offered_tls13_ && from_client &&
                phase_ != Phase::final_server, "relay_sequence");
      }
      emit(b); return;
    }
    require(from_client ? phase_ == Phase::retry_client :
            (phase_ == Phase::first_server || phase_ == Phase::final_server), "relay_sequence");
    require(++s.records <= record_count_limit, "relay_record_count");
    require(b.size() <= hello_limit - s.hello_wire.size(), "relay_hello_limit");
    s.hello_wire.insert(s.hello_wire.end(), b.begin(), b.end());
    s.hello_payload.insert(s.hello_payload.end(), b.begin() + 5, b.end());
    if (!s.expected && s.hello_payload.size() >= 4) {
      const auto& p = s.hello_payload;
      require(p[0] == (from_client ? 1 : 2), "relay_sequence");
      s.expected = 4 + (size_t(p[1]) << 16) + (size_t(p[2]) << 8) + p[3];
      require(s.expected >= 42 && s.expected <= hello_limit - 5, "relay_hello_limit");
    }
    if (!s.expected || s.hello_payload.size() < s.expected) return;
    if (from_client) {
      require(s.hello_payload.size() == s.expected, "relay_retry_boundary");
      Hello h = parse(s.hello_wire);
      require(h.tls13 && h.sni == input_sni_ && h.identity == identity_, "relay_retry_identity");
      Bytes out = replace(h, output_sni_);
      phase_ = Phase::final_server; emit(out);
    } else {
      const auto& p = s.hello_payload;
      require(u16(p, 4) == 0x0303 && p[38] <= 32, "relay_server_hello");
      size_t at = 39 + p[38] + 2;
      require(at < s.expected && p[at++] == 0, "relay_server_hello");
      uint16_t version = 0x0303;
      if (at < s.expected) {
        const size_t n = u16(p, at); at += 2;
        require(at <= s.expected && n == s.expected - at, "relay_server_hello");
        std::set<uint16_t> seen;
        while (at < s.expected) {
          require(s.expected - at >= 4, "relay_server_hello");
          const uint16_t type = u16(p, at); const size_t k = u16(p, at + 2); at += 4;
          require(k <= s.expected - at && seen.insert(type).second, "relay_server_hello");
          if (type == 43) {
            require(k == 2, "relay_server_hello"); version = u16(p, at);
            require(version == 0x0304, "relay_server_version");
          }
          at += k;
        }
      }
      constexpr std::array<uint8_t, 32> retry_random = {
        0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
        0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
      const bool retry = std::equal(retry_random.begin(), retry_random.end(), p.begin() + 6);
      require(version != 0x0304 || (offered_tls13_ && s.expected == p.size()), "relay_server_boundary");
      if (retry) {
        require(offered_tls13_ && version == 0x0304 && phase_ == Phase::first_server &&
                s.expected == p.size(), "relay_retry_sequence");
        ++retries_; phase_ = Phase::retry_client;
      } else {
        require(phase_ != Phase::final_server || version == 0x0304, "relay_retry_version");
        phase_ = Phase::opaque;
      }
      emit(s.hello_wire);
    }
    s.hello_wire.clear(); s.hello_payload.clear(); s.expected = 0; s.records = 0;
  }
public:
  HandshakeGate(const Hello& first, std::string replacement, uint64_t now_ms)
    : input_sni_(first.sni), output_sni_(std::move(replacement)), identity_(first.identity),
      offered_tls13_(first.tls13), started_(now_ms) {
    require(hostname(output_sni_), "hello_replacement");
  }
  bool opaque() const { return phase_ == Phase::opaque; }
  unsigned retries() const { return retries_; }
  void check_timeout(uint64_t now_ms) {
    require(!failed_, "relay_failed");
    if (!opaque() && (now_ms < started_ || now_ms - started_ >= deadline_ms)) {
      failed_ = true; throw std::runtime_error("relay_handshake_timeout");
    }
  }
  void feed(Direction direction, const uint8_t* p, size_t n, uint64_t now_ms, const Emit& emit) {
    check_timeout(now_ms);
    Stream& s = direction == Direction::client ? client_ : server_;
    try {
      while (n) {
        if (opaque()) {
          // A partially received opaque 0-RTT/CCS record may still be pending
          // when ServerHello crosses the other direction. Preserve it exactly.
          if (!s.record.empty()) { emit(s.record); s.record.clear(); }
          const size_t k = std::min(n, record_limit);
          emit(Bytes(p, p + k)); p += k; n -= k; continue;
        }
        size_t end = s.record.size() < 5 ? 5 : 5 + u16(s.record, 3);
        const size_t k = std::min(n, end - s.record.size());
        s.record.insert(s.record.end(), p, p + k); p += k; n -= k;
        require(s.record[0] >= 20 && s.record[0] <= 23, "relay_record_type");
        if (s.record[0] == 22) {
          require(direction == Direction::client ? phase_ == Phase::retry_client :
                  (phase_ == Phase::first_server || phase_ == Phase::final_server), "relay_sequence");
        }
        if (s.record.size() < 5) continue;
        const size_t size = u16(s.record, 3);
        require(s.record[1] == 3 && s.record[2] >= 1 && s.record[2] <= 3 && size &&
                size <= (s.record[0] == 23 ? record_limit + 256 : record_limit), "relay_record");
        if (s.record[0] == 22) {
          // Refuse a CH2 before HRR as soon as its header arrives. It must not
          // become opaque merely because ServerHello subsequently arrives.
          require(direction == Direction::client ? phase_ == Phase::retry_client :
                  (phase_ == Phase::first_server || phase_ == Phase::final_server), "relay_sequence");
        }
        if (s.record.size() == size + 5) {
          Bytes complete = std::move(s.record); s.record.clear();
          record(direction, s, std::move(complete), emit);
        }
      }
    } catch (...) { failed_ = true; throw; }
  }
  void end(Direction direction) {
    const auto& s = direction == Direction::client ? client_ : server_;
    require(!failed_, "relay_failed");
    if (!s.record.empty() || !s.hello_wire.empty() || !opaque()) {
      failed_ = true; throw std::runtime_error("relay_handshake_eof");
    }
  }
};
} // namespace cvpn::transparent
