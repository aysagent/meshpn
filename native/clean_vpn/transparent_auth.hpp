#pragma once
#include "transparent_replay.hpp"
#include "transparent_destination.hpp"
#include <openssl/aead.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <map>
#include <mutex>

namespace cvpn::transparent {
inline std::string lowercase(std::string s) {
  for (char& c : s) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
  return s;
}
inline std::string base32(const Bytes& b) {
  constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
  std::string out; uint32_t acc = 0; unsigned bits = 0;
  for (uint8_t c : b) {
    acc = (acc << 8) | c; bits += 8;
    while (bits >= 5) { bits -= 5; out.push_back(alphabet[(acc >> bits) & 31]); }
  }
  if (bits) out.push_back(alphabet[(acc << (5 - bits)) & 31]);
  return out;
}
inline Bytes unbase32(const std::string& text) {
  require(!text.empty() && text.size() <= 253, "relay_token_encoding");
  Bytes out; uint32_t acc = 0; unsigned bits = 0;
  for (char c : text) {
    unsigned v = c >= 'a' && c <= 'z' ? unsigned(c - 'a') :
                 c >= '2' && c <= '7' ? unsigned(c - '2' + 26) : 32;
    require(v < 32, "relay_token_encoding"); acc = (acc << 5) | v; bits += 5;
    if (bits >= 8) { bits -= 8; out.push_back((acc >> bits) & 255); }
  }
  require(base32(out) == text, "relay_token_encoding"); return out;
}
inline void push64(Bytes& b, uint64_t value) { for (int i = 7; i >= 0; --i) b.push_back(value >> (i * 8)); }
inline uint64_t read64(const Bytes& b, size_t at) {
  require(at <= b.size() && b.size() - at >= 8, "relay_token_format");
  uint64_t value = 0; for (size_t i = 0; i < 8; ++i) value = (value << 8) | b[at + i]; return value;
}

struct AuthorizedHello { Destination destination; Bytes restored; std::string origin_sni; };
class SniAuthorization {
  std::string suffix_, aad_;
  Digest replay_scope_{};
  bssl::UniquePtr<EVP_AEAD_CTX> aead_;
  std::string encode(const Bytes& wire) const {
    const auto text = base32(wire); std::string out = "n1";
    for (size_t at = 0; at < text.size(); at += 63) out += "." + text.substr(at, 63);
    out += "." + suffix_;
    require(hostname(out), "relay_token_hostname_limit"); return out;
  }
  Bytes decode(std::string sni) const {
    require(hostname(sni), "relay_token_hostname"); sni = lowercase(std::move(sni));
    const std::string suffix = "." + suffix_;
    require(sni.size() > suffix.size() + 3 && sni.compare(0, 3, "n1.") == 0 &&
            sni.compare(sni.size() - suffix.size(), suffix.size(), suffix) == 0, "relay_token_suffix");
    std::string text;
    for (size_t i = 3; i < sni.size() - suffix.size(); ++i) if (sni[i] != '.') text += sni[i];
    auto wire = unbase32(text);
    require(encode(wire) == sni, "relay_token_encoding"); return wire;
  }
public:
  SniAuthorization(const Digest& secret, std::string public_name) : suffix_(lowercase(std::move(public_name))) {
    require(hostname(suffix_), "relay_public_name");
    aad_ = "clean-vpn/native/transparent/sni/v1/" + suffix_;
    Digest key{}; unsigned n = 0;
    require(HMAC(EVP_sha256(), secret.data(), secret.size(), reinterpret_cast<const uint8_t*>(aad_.data()),
                 aad_.size(), key.data(), &n) && n == key.size(), "relay_crypto");
    aead_.reset(EVP_AEAD_CTX_new(EVP_aead_aes_256_gcm(), key.data(), key.size(), 16));
    OPENSSL_cleanse(key.data(), key.size()); require(bool(aead_), "relay_crypto");
    const auto context = "clean-vpn/native/transparent/replay/v1/" + suffix_;
    require(HMAC(EVP_sha256(), secret.data(), secret.size(), reinterpret_cast<const uint8_t*>(context.data()),
                 context.size(), replay_scope_.data(), &n) && n == replay_scope_.size(), "relay_crypto");
  }
  const Digest& replay_scope() const { return replay_scope_; }
  // n1 is a new native wire format, independent of legacy Node enc-SNI v2.
  // Authenticate the ORIGINAL record prefix as well as destination and SNI.
  Bytes seal(const Hello& hello, const Destination& dst, uint64_t wall) const {
    require(dst.port != 0, "relay_destination");
    Bytes pt{1}; push64(pt, wall); pt.insert(pt.end(), dst.ipv4.begin(), dst.ipv4.end());
    pt.push_back(dst.port >> 8); pt.push_back(dst.port); pt.push_back(hello.sni.size());
    pt.insert(pt.end(), hello.sni.begin(), hello.sni.end());
    auto hash = digest(hello.wire); pt.insert(pt.end(), hash.begin(), hash.end());
    Bytes wire(12 + pt.size() + 16); require(RAND_bytes(wire.data(), 12) == 1, "relay_crypto");
    size_t n = 0;
    require(EVP_AEAD_CTX_seal(aead_.get(), wire.data() + 12, &n, wire.size() - 12, wire.data(), 12,
            pt.data(), pt.size(), reinterpret_cast<const uint8_t*>(aad_.data()), aad_.size()) == 1,
            "relay_crypto");
    wire.resize(12 + n); return replace(hello, encode(wire));
  }
  template<class Clock> AuthorizedHello accept(const Hello& incoming, const DestinationPolicy& policy,
                                               ReplayWindow& replay, Clock clock) const {
    replay.check_scope(replay_scope_);
    Bytes wire = decode(incoming.sni);
    require(wire.size() >= 12 + 16 + 49, "relay_token_format");
    Bytes pt(wire.size() - 12); size_t n = 0;
    require(EVP_AEAD_CTX_open(aead_.get(), pt.data(), &n, pt.size(), wire.data(), 12,
            wire.data() + 12, wire.size() - 12, reinterpret_cast<const uint8_t*>(aad_.data()), aad_.size()) == 1,
            "relay_token_auth");
    pt.resize(n);
    require(pt.size() >= 49 && pt[0] == 1 && pt[15] && pt.size() == size_t(48 + pt[15]), "relay_token_format");
    const uint64_t issued = read64(pt, 1);
    AuthorizedHello result; std::copy_n(pt.begin() + 9, 4, result.destination.ipv4.begin());
    result.destination.port = u16(pt, 13);
    result.origin_sni.assign(pt.begin() + 16, pt.begin() + 16 + pt[15]);
    require(hostname(result.origin_sni), "relay_token_format");
    result.restored = replace(incoming, result.origin_sni);
    const auto hash = digest(result.restored);
    require(CRYPTO_memcmp(hash.data(), pt.data() + 16 + pt[15], hash.size()) == 0, "relay_hello_binding");
    policy.check(result.destination);
    replay.consume(digest(wire), issued, clock); // last step, before any connect
    return result;
  }
  AuthorizedHello accept(const Hello& incoming, const DestinationPolicy& policy, ReplayWindow& replay,
                         uint64_t wall, uint64_t monotonic_ms) const {
    return accept(incoming, policy, replay, [=] { return std::make_pair(wall, monotonic_ms); });
  }
};
} // namespace cvpn::transparent
