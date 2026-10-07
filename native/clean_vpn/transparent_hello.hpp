#pragma once
// Bounded ClientHello record codec. No socket, resolver, TLS termination or
// fallback policy lives here. Every failure is fatal to the caller's stream.
#include "protocol.hpp"
#include <array>
#include <set>
#include <string>

namespace cvpn::transparent {
constexpr size_t hello_limit = 65536;
constexpr size_t record_limit = 16384;
constexpr size_t record_count_limit = 128;
inline void require(bool ok, const char* code) {
  if (!ok) throw std::runtime_error(code); // fixed codes only; never SNI/payload
}
inline uint16_t u16(const Bytes& b, size_t at) {
  require(at <= b.size() && b.size() - at >= 2, "hello_length");
  return (uint16_t(b[at]) << 8) | b[at + 1];
}
inline void put16(Bytes& b, size_t at, size_t value) {
  require(value <= 65535 && at <= b.size() && b.size() - at >= 2, "hello_length");
  b[at] = value >> 8; b[at + 1] = value;
}
inline bool hostname(const std::string& s) {
  if (s.empty() || s.size() > 253) return false;
  size_t label = 0;
  for (size_t i = 0; i < s.size(); ++i) {
    const unsigned char c = s[i];
    if (c == '.') {
      if (!label || s[i - 1] == '-') return false;
      label = 0;
    } else {
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-')) return false;
      if ((!label && c == '-') || ++label > 63) return false;
    }
  }
  return label && s.back() != '-';
}

struct Hello {
  Bytes wire, payload;
  std::string sni;
  size_t host_at = 0, host_size = 0, list_at = 0, sni_size_at = 0, extensions_at = 0;
  bool tls13 = false;
  Bytes identity; // legacy version, random, session ID (no auth material)
};

inline Hello inspect(Bytes wire, Bytes p) {
  require(p.size() >= 4 + 38 && p[0] == 1, "hello_structure");
  const size_t length = (size_t(p[1]) << 16) | (size_t(p[2]) << 8) | p[3];
  require(length == p.size() - 4 && u16(p, 4) == 0x0303, "hello_structure");
  Hello h; size_t at = 38;
  const size_t sid = p[at++];
  require(sid <= 32 && at + sid <= p.size(), "hello_session_id");
  at += sid; h.identity.assign(p.begin() + 4, p.begin() + at);
  const size_t ciphers = u16(p, at); at += 2;
  require(ciphers >= 2 && !(ciphers & 1) && ciphers <= p.size() - at, "hello_ciphers");
  at += ciphers;
  require(at + 2 <= p.size() && p[at] == 1 && p[at + 1] == 0, "hello_compression");
  at += 2; h.extensions_at = at;
  const size_t extensions = u16(p, at); at += 2;
  require(extensions == p.size() - at, "hello_extensions");
  std::set<uint16_t> seen;
  while (at < p.size()) {
    const uint16_t type = u16(p, at);
    const size_t n = u16(p, at + 2); at += 4;
    require(n <= p.size() - at && seen.insert(type).second, "hello_extension");
    if (type == 0) {
      require(n >= 6 && u16(p, at) == n - 2 && p[at + 2] == 0 &&
              u16(p, at + 3) == n - 5, "hello_sni");
      h.list_at = at; h.sni_size_at = at - 2;
      h.host_at = at + 5; h.host_size = n - 5;
      h.sni.assign(p.begin() + h.host_at, p.begin() + at + n);
      require(hostname(h.sni), "hello_sni");
    } else if (type == 43) {
      require(n >= 3 && p[at] == n - 1 && !(p[at] & 1), "hello_versions");
      for (size_t v = at + 1; v < at + n; v += 2) h.tls13 |= u16(p, v) == 0x0304;
    }
    at += n;
  }
  require(!h.sni.empty(), "hello_sni_missing");
  h.wire = std::move(wire); h.payload = std::move(p); return h;
}

// Consumes only the records containing CH; leaves the rest of a TCP chunk to
// the stream state machine. A CH must end at a record boundary (also required
// here for TLS 1.2). TCP fragmentation and TLS-record fragmentation are separate.
class HelloReader {
  Bytes wire_, payload_;
  size_t record_at_ = 0, record_end_ = 5, records_ = 0, expected_ = 0;
  bool header_ = true, done_ = false, failed_ = false;
public:
  bool done() const { return done_; }
  size_t retained() const { return wire_.size() + payload_.size(); }
  size_t feed(const uint8_t* p, size_t n) {
    require(!failed_ && !done_, "hello_reader_state");
    size_t used = 0;
    try {
      while (used < n && !done_) {
        size_t take = std::min(n - used, record_end_ - wire_.size());
        require(take <= hello_limit - wire_.size(), "hello_limit");
        wire_.insert(wire_.end(), p + used, p + used + take); used += take;
        if (wire_.size() != record_end_) continue;
        if (header_) {
          require(++records_ <= record_count_limit, "hello_record_count");
          const size_t size = u16(wire_, record_at_ + 3);
          require(wire_[record_at_] == 22 && wire_[record_at_ + 1] == 3 &&
                  wire_[record_at_ + 2] >= 1 && wire_[record_at_ + 2] <= 3 &&
                  size && size <= record_limit, "hello_record");
          require(size <= hello_limit - record_end_, "hello_limit");
          record_end_ += size; header_ = false;
        } else {
          payload_.insert(payload_.end(), wire_.begin() + record_at_ + 5, wire_.end());
          if (!expected_ && payload_.size() >= 4) {
            require(payload_[0] == 1, "hello_type");
            expected_ = 4 + (size_t(payload_[1]) << 16) + (size_t(payload_[2]) << 8) + payload_[3];
            require(expected_ >= 42 && expected_ <= hello_limit - 5, "hello_limit");
          }
          if (expected_ && payload_.size() >= expected_) {
            require(payload_.size() == expected_, "hello_record_boundary"); done_ = true;
          } else {
            record_at_ = record_end_; record_end_ += 5; header_ = true;
            require(record_end_ <= hello_limit, "hello_limit");
          }
        }
      }
    } catch (...) { failed_ = true; throw; }
    return used;
  }
  Hello take() {
    require(done_ && !failed_, "hello_incomplete");
    failed_ = true; // one-shot, including a malformed complete message
    return inspect(std::move(wire_), std::move(payload_));
  }
};

inline Hello parse(const Bytes& wire) {
  HelloReader r;
  require(r.feed(wire.data(), wire.size()) == wire.size() && r.done(), "hello_incomplete");
  return r.take();
}

// Grow/shrink exactly the record owning the first hostname byte. Restoring the
// original SNI inverts all record boundaries, even when SNI spans records. No
// silent re-fragmentation: impossible layouts fail before any output is emitted.
inline Bytes replace(const Hello& h, const std::string& name) {
  require(hostname(name), "hello_replacement");
  const ptrdiff_t delta = ptrdiff_t(name.size()) - ptrdiff_t(h.host_size);
  const ptrdiff_t total = ptrdiff_t(h.wire.size()) + delta;
  require(total > 0 && total <= ptrdiff_t(hello_limit), "hello_limit");
  Bytes p(h.payload.begin(), h.payload.begin() + h.host_at);
  p.insert(p.end(), name.begin(), name.end());
  p.insert(p.end(), h.payload.begin() + h.host_at + h.host_size, h.payload.end());
  for (size_t at : {h.list_at, h.sni_size_at, h.extensions_at}) {
    const ptrdiff_t value = ptrdiff_t(u16(p, at)) + delta;
    require(value >= 0 && value <= 65535, "hello_length"); put16(p, at, size_t(value));
  }
  put16(p, h.host_at - 2, name.size());
  const size_t size = p.size() - 4;
  p[1] = size >> 16; p[2] = size >> 8; p[3] = size;
  Bytes out; out.reserve(size_t(total)); size_t payload_at = 0, source = 0;
  for (size_t at = 0; at < h.wire.size();) {
    const size_t n = u16(h.wire, at + 3);
    const bool owner = payload_at <= h.host_at && h.host_at < payload_at + n;
    const ptrdiff_t resized = ptrdiff_t(n) + (owner ? delta : 0);
    require(resized > 0 && resized <= ptrdiff_t(record_limit) &&
            (!owner || resized > ptrdiff_t(h.host_at - payload_at)), "hello_record_resize");
    const size_t k = size_t(resized), header = out.size();
    require(source <= p.size() && k <= p.size() - source, "hello_record_resize");
    out.insert(out.end(), h.wire.begin() + at, h.wire.begin() + at + 5);
    put16(out, header + 3, k);
    out.insert(out.end(), p.begin() + source, p.begin() + source + k);
    source += k; payload_at += n; at += 5 + n;
  }
  require(source == p.size(), "hello_record_resize"); return out;
}
} // namespace cvpn::transparent
