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
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/x509.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <iostream>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>
#include <map>

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
  std::string ja3_sorted_string;
  std::string ja3_sorted_md5_hex;
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

  auto ciphers_s = out->ciphers;
  std::sort(ciphers_s.begin(), ciphers_s.end());
  auto ext_s = out->ext_types;
  std::sort(ext_s.begin(), ext_s.end());
  auto curves_s = out->curves;
  std::sort(curves_s.begin(), curves_s.end());
  auto ecf_s = out->ec_point_formats;
  std::sort(ecf_s.begin(), ecf_s.end());
  std::ostringstream oss_s;
  oss_s << static_cast<unsigned>(out->legacy_version) << ','
        << JoinDashDec16(ciphers_s) << ','
        << JoinDashDec16(ext_s) << ','
        << JoinDashDec16(curves_s) << ','
        << JoinDashDec8(ecf_s);
  out->ja3_sorted_string = oss_s.str();
  out->ja3_sorted_md5_hex = Md5HexUtf8(out->ja3_sorted_string);
  return true;
}

std::string Hex4LowerU16(uint16_t v) {
  static const char kHex[] = "0123456789abcdef";
  std::string s(4, '\0');
  s[0] = kHex[(v >> 12) & 0xf];
  s[1] = kHex[(v >> 8) & 0xf];
  s[2] = kHex[(v >> 4) & 0xf];
  s[3] = kHex[v & 0xf];
  return s;
}

std::string Ja4Count99(size_t n) {
  size_t c = n;
  if (c > 99) c = 99;
  char buf[8];
  snprintf(buf, sizeof(buf), "%02zu", c);
  return std::string(buf);
}

std::string Ja4VersionTwoChars(uint16_t v) {
  switch (v) {
    case 0x0304:
      return "13";
    case 0x0303:
      return "12";
    case 0x0302:
      return "11";
    case 0x0301:
      return "10";
    case 0x0300:
      return "s3";
    case 0x0002:
      return "s2";
    case 0xfeff:
      return "d1";
    case 0xfefd:
      return "d2";
    case 0xfefc:
      return "d3";
    default:
      return "00";
  }
}

std::string Ja4ResolvedTlsVersion(const std::vector<uint16_t>& supported_versions,
                                  uint16_t legacy_version) {
  uint16_t best = 0;
  bool any = false;
  for (uint16_t x : supported_versions) {
    if (IsGrease(x)) continue;
    any = true;
    if (x > best) best = x;
  }
  if (any) return Ja4VersionTwoChars(best);
  return Ja4VersionTwoChars(legacy_version);
}

std::string Ja4AlpnFingerprintPair(const std::vector<uint8_t>& proto) {
  if (proto.empty()) return "00";
  uint8_t fb = proto.front();
  uint8_t lb = proto.back();
  auto alnum = [](uint8_t b) {
    return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') ||
           (b >= 'a' && b <= 'z');
  };
  if (alnum(fb) && alnum(lb)) {
    return std::string(1, static_cast<char>(fb)) +
           std::string(1, static_cast<char>(lb));
  }
  std::string hex;
  hex.reserve(proto.size() * 2);
  for (uint8_t b : proto) {
    static const char kH[] = "0123456789abcdef";
    hex.push_back(kH[b >> 4]);
    hex.push_back(kH[b & 0xf]);
  }
  if (hex.empty()) return "00";
  return std::string(1, hex.front()) + std::string(1, hex.back());
}

std::string Sha256Trunc12Utf8(const std::string& s) {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), digest);
  return HexLower(digest, 6);
}

std::string JoinCommaStringsVec(const std::vector<std::string>& v) {
  std::string out;
  for (size_t i = 0; i < v.size(); i++) {
    if (i) out.push_back(',');
    out += v[i];
  }
  return out;
}

/** Элементы мультимножества |a|, которых недостаточно в |b| (учёт повторов типов). */
std::string MultisetExtraInFirst(const std::vector<uint16_t>& a,
                                   const std::vector<uint16_t>& b) {
  std::map<uint16_t, int> ca, cb;
  for (uint16_t x : a) ca[x]++;
  for (uint16_t x : b) cb[x]++;
  std::vector<uint16_t> extra;
  for (const auto& kv : ca) {
    int nb = 0;
    auto it = cb.find(kv.first);
    if (it != cb.end()) nb = it->second;
    for (int i = 0; i < kv.second - nb; ++i) extra.push_back(kv.first);
  }
  std::sort(extra.begin(), extra.end());
  return JoinCommaDec16(extra);
}

struct Ja4Computed {
  std::string fingerprint;
  std::string ja4_a;
  std::string ja4_b;
  std::string ja4_c;
  std::string raw_r;
  std::string raw_o;
  /** Порядок как JA4_c: расширения 13 и 50 на проводе, без GREASE внутри списков. */
  std::vector<uint16_t> signature_algorithms_merged;
};

/** FoxIO JA4 — логика как в scripts/lib/tls-clienthello-ja4.mjs `ja4FromClientHelloBody`. */
bool ComputeJa4FromClientHelloBody(const uint8_t* body, size_t n,
                                   Ja4Computed* out) {
  size_t o = 0;
  if (n < 2) return false;
  uint16_t legacy_version =
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
  std::vector<uint16_t> ciphers;
  while (o < cipher_end) {
    uint16_t cs =
        (static_cast<uint16_t>(body[o]) << 8) | body[o + 1];
    o += 2;
    if (!IsGrease(cs)) ciphers.push_back(cs);
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

  bool has_sni_extension = false;
  std::vector<uint8_t> first_alpn_bytes;
  std::vector<uint16_t> supported_versions;
  std::vector<uint16_t> signature_algorithms;
  std::vector<uint16_t> ext_types;

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
    ext_types.push_back(et);
    if (et == 0) {
      has_sni_extension = true;
    } else if (et == 16 && elen >= 2) {
      uint16_t list_len =
          (static_cast<uint16_t>(edata[0]) << 8) | edata[1];
      size_t ao = 2;
      while (ao + 1 <= elen && list_len > 0) {
        uint8_t pl = edata[ao];
        ao += 1;
        if (ao + pl > elen) break;
        if (first_alpn_bytes.empty()) {
          first_alpn_bytes.assign(edata + ao, edata + ao + pl);
        }
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
        uint16_t sv =
            (static_cast<uint16_t>(edata[pos]) << 8) | edata[pos + 1];
        supported_versions.push_back(sv);
      }
    } else if (et == 13 && elen >= 2) {
      uint16_t alg_len =
          (static_cast<uint16_t>(edata[0]) << 8) | edata[1];
      for (size_t i = 2; i < 2 + static_cast<size_t>(alg_len) && i + 2 <= elen;
           i += 2) {
        uint16_t sid =
            (static_cast<uint16_t>(edata[i]) << 8) | edata[i + 1];
        if (!IsGrease(sid)) signature_algorithms.push_back(sid);
      }
    } else if (et == 50 && elen >= 2) {
      uint16_t alg_len =
          (static_cast<uint16_t>(edata[0]) << 8) | edata[1];
      for (size_t i = 2; i < 2 + static_cast<size_t>(alg_len) && i + 2 <= elen;
           i += 2) {
        uint16_t sid =
            (static_cast<uint16_t>(edata[i]) << 8) | edata[i + 1];
        if (!IsGrease(sid)) signature_algorithms.push_back(sid);
      }
    }
  }

  if (o != ext_end) return false;

  std::string ver =
      Ja4ResolvedTlsVersion(supported_versions, legacy_version);
  char sni_mark = has_sni_extension ? 'd' : 'i';
  std::string alpn_pair = Ja4AlpnFingerprintPair(first_alpn_bytes);

  std::string ja4_a = std::string("t") + ver + sni_mark +
                      Ja4Count99(ciphers.size()) +
                      Ja4Count99(ext_types.size()) + alpn_pair;

  std::vector<std::string> cipher_hex_sorted;
  cipher_hex_sorted.reserve(ciphers.size());
  for (uint16_t c : ciphers) cipher_hex_sorted.push_back(Hex4LowerU16(c));
  std::sort(cipher_hex_sorted.begin(), cipher_hex_sorted.end());
  std::string sorted_cipher_hex = JoinCommaStringsVec(cipher_hex_sorted);

  std::string ja4_b;
  if (ciphers.empty()) {
    ja4_b = "000000000000";
  } else {
    ja4_b = Sha256Trunc12Utf8(sorted_cipher_hex);
  }

  std::vector<std::string> ext_for_c_hex;
  for (uint16_t t : ext_types) {
    if (t != 0 && t != 16) ext_for_c_hex.push_back(Hex4LowerU16(t));
  }
  std::sort(ext_for_c_hex.begin(), ext_for_c_hex.end());

  std::string ja4_c;
  if (ext_for_c_hex.empty()) {
    ja4_c = "000000000000";
  } else {
    std::string ext_part = JoinCommaStringsVec(ext_for_c_hex);
    std::vector<std::string> sig_hex;
    sig_hex.reserve(signature_algorithms.size());
    for (uint16_t s : signature_algorithms) sig_hex.push_back(Hex4LowerU16(s));
    std::string sig_part = JoinCommaStringsVec(sig_hex);
    std::string payload =
        signature_algorithms.empty() ? ext_part : ext_part + "_" + sig_part;
    ja4_c = Sha256Trunc12Utf8(payload);
  }

  std::vector<std::string> cipher_wire_hex;
  for (uint16_t c : ciphers) cipher_wire_hex.push_back(Hex4LowerU16(c));
  std::vector<std::string> ext_wire_hex;
  for (uint16_t t : ext_types) ext_wire_hex.push_back(Hex4LowerU16(t));
  std::vector<std::string> sig_wire_hex;
  for (uint16_t s : signature_algorithms)
    sig_wire_hex.push_back(Hex4LowerU16(s));

  std::string raw_r =
      ja4_a + "_" + sorted_cipher_hex + "_" + JoinCommaStringsVec(ext_for_c_hex);
  if (!signature_algorithms.empty()) {
    raw_r += "_" + JoinCommaStringsVec(sig_wire_hex);
  }

  std::string raw_o = ja4_a + "_" + JoinCommaStringsVec(cipher_wire_hex) +
                      "_" + JoinCommaStringsVec(ext_wire_hex);
  if (!signature_algorithms.empty()) {
    raw_o += "_" + JoinCommaStringsVec(sig_wire_hex);
  }

  out->ja4_a = ja4_a;
  out->ja4_b = ja4_b;
  out->ja4_c = ja4_c;
  out->signature_algorithms_merged = signature_algorithms;
  out->fingerprint = ja4_a + "_" + ja4_b + "_" + ja4_c;
  out->raw_r = raw_r;
  out->raw_o = raw_o;
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

/** TLS 1.2-(или SSL3-)only suite: идёт во второй блок списка cipher в ClientHello. */
static bool CipherSuiteMaxBelowTls13(const SSL_CIPHER* c) {
  return c != nullptr && SSL_CIPHER_get_max_version(c) < TLS1_3_VERSION;
}

struct Ja3LogCfg {
  bool log_ja3 = false;
  bool ja3_verbose = false;
  bool logged = false;
  std::string expected_ja3_md5;
  std::string expected_ja3_string;
  std::string expected_ja4_fingerprint;
  bool ja3_strict = false;
  bool ja3_mismatch = false;
  /** Из JSON профиля (диагностика паритета с wire). */
  std::vector<uint16_t> profile_extension_types;
  std::vector<uint16_t> profile_cipher_order;
  std::vector<uint16_t> profile_sigalgs_merged;
};

bool MeshvpnTlsExtensionIsGrease(uint16_t et) {
  return (static_cast<uint16_t>(et & 0x0f0f) == 0x0a0a) &&
         (((static_cast<unsigned>(et) >> 8) & 0xff) ==
          (static_cast<unsigned>(et) & 0xff));
}

bool MeshvpnOpaqueExtensionBlocked(uint16_t t) {
  if (MeshvpnTlsExtensionIsGrease(t)) {
    return true;
  }
  switch (t) {
    case 0:     // server_name
    case 5:     // status_request — OCSP из профиля
    case 10:    // supported_groups
    case 11:    // ec_point_formats
    case 13:    // signature_algorithms
    case 16:    // ALPN
    case 18:    // signed_certificate_timestamp (стек Chromium/BoringSSL)
    case 21:    // padding
    case 23:    // extended_master_secret
    case 27:    // compress_certificate
    case 35:    // session_ticket
    case 41:    // pre_shared_key
    case 43:    // supported_versions
    case 45:    // psk_key_exchange_modes
    case 50:    // signature_algorithms_cert
    case 51:    // key_share
    case 65281: // renegotiation_info (0xff01)
      return true;
    default:
      return false;
  }
}

bool HexDecodeStrict(const std::string& hex, std::vector<uint8_t>* out,
                     std::string* err_out) {
  out->clear();
  std::string compact;
  compact.reserve(hex.size());
  for (unsigned char uc : hex) {
    char c = static_cast<char>(uc);
    if (std::isspace(static_cast<unsigned char>(c))) continue;
    compact.push_back(c);
  }
  if (compact.size() % 2 != 0) {
    *err_out = "client_hello_extra_extensions: hex length must be even";
    return false;
  }
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
  };
  for (size_t i = 0; i < compact.size(); i += 2) {
    int hi = nibble(compact[i]);
    int lo = nibble(compact[i + 1]);
    if (hi < 0 || lo < 0) {
      *err_out = "client_hello_extra_extensions: invalid hex digit";
      return false;
    }
    out->push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

bool ApplyClientHelloProfile(SSL_CTX* ctx, const nlohmann::json& p,
                             Ja3LogCfg* ja3_cfg, std::string* err_out) {
  bool permute_extensions = true;
  if (p.contains("permute_extensions")) {
    if (!p["permute_extensions"].is_boolean()) {
      *err_out =
          "client_hello_profile.permute_extensions must be boolean";
      return false;
    }
    permute_extensions = p["permute_extensions"].get<bool>();
  }
  SSL_CTX_set_permute_extensions(ctx, permute_extensions ? 1 : 0);

  SSL_CTX_meshvpn_clear_client_hello_extensions(ctx);

  const bool ja3_strict_cfg = p.value("ja3_strict", false);
  if (ja3_strict_cfg && permute_extensions) {
    *err_out =
        "client_hello_profile: ja3_strict is incompatible with "
        "permute_extensions (set permute_extensions to false)";
    return false;
  }

  if (ja3_cfg) {
    ja3_cfg->profile_extension_types.clear();
    ja3_cfg->profile_cipher_order.clear();
    ja3_cfg->profile_sigalgs_merged.clear();
  }

  if (ja3_cfg && p.contains("extension_types")) {
    if (!p["extension_types"].is_array()) {
      *err_out = "client_hello_profile.extension_types must be array";
      return false;
    }
    for (const auto& item : p["extension_types"]) {
      if (!item.is_number_unsigned() && !item.is_number_integer()) {
        *err_out =
            "client_hello_profile.extension_types entries must be integers";
        return false;
      }
      unsigned long raw = item.is_number_unsigned()
                              ? item.get<unsigned long>()
                              : static_cast<unsigned long>(item.get<long>());
      if (raw > 0xffff) {
        *err_out =
            "client_hello_profile.extension_types value out of uint16 range";
        return false;
      }
      ja3_cfg->profile_extension_types.push_back(static_cast<uint16_t>(raw));
    }
  }

  if (!p.contains("cipher_suites") || !p["cipher_suites"].is_array() ||
      p["cipher_suites"].empty()) {
    *err_out =
        "client_hello_profile.cipher_suites must be a non-empty array (TLS 1.3 "
        "IANA ids)";
    return false;
  }
  std::vector<uint16_t> tls13_cipher_order;
  tls13_cipher_order.reserve(p["cipher_suites"].size());
  std::string tls12_cipher_rule;
  size_t tls12_suite_count = 0;
  size_t skipped_unknown_cipher = 0;
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
      if (ja3_cfg) ja3_cfg->profile_cipher_order.push_back(id);
      continue;
    }
    const SSL_CIPHER* c = SSL_get_cipher_by_value(id);
    if (!CipherSuiteMaxBelowTls13(c)) {
      skipped_unknown_cipher++;
      continue;
    }
    const char* nm = SSL_CIPHER_get_name(c);
    if (nm == nullptr || nm[0] == '\0') {
      skipped_unknown_cipher++;
      continue;
    }
    if (!tls12_cipher_rule.empty()) {
      tls12_cipher_rule.push_back(':');
    }
    tls12_cipher_rule += nm;
    tls12_suite_count++;
    if (ja3_cfg) ja3_cfg->profile_cipher_order.push_back(id);
  }
  if (skipped_unknown_cipher > 0) {
    std::cerr << "boring-tls-helper: warning: client_hello_profile.cipher_suites — "
              << skipped_unknown_cipher
              << " id не распознаны BoringSSL как TLS 1.2/1.3 suite (пропущены).\n";
  }

  if (!tls12_cipher_rule.empty()) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    if (SSL_CTX_set_cipher_list(ctx, tls12_cipher_rule.c_str()) != 1) {
      ERR_print_errors_fp(stderr);
      *err_out =
          "SSL_CTX_set_cipher_list failed for TLS 1.2 cipher suites from profile";
      return false;
    }
    std::cerr << "boring-tls-helper: note: TLS 1.2 cipher block из профиля ("
              << tls12_suite_count
              << " suite) для паритета JA3 с браузером.\n";
  } else {
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
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

  auto parse_u16_vec_key = [&](const char* key,
                               std::vector<uint16_t>* out) -> bool {
    if (!p.contains(key)) return true;
    if (!p[key].is_array()) {
      *err_out =
          std::string("client_hello_profile.") + key + " must be array";
      return false;
    }
    for (const auto& item : p[key]) {
      if (!item.is_number_unsigned() && !item.is_number_integer()) {
        *err_out = std::string("client_hello_profile.") + key +
                   " entries must be integers";
        return false;
      }
      unsigned long raw =
          item.is_number_unsigned()
              ? item.get<unsigned long>()
              : static_cast<unsigned long>(item.get<long>());
      if (raw > 0xffff) {
        *err_out = std::string("client_hello_profile.") + key +
                   " value out of uint16 range";
        return false;
      }
      out->push_back(static_cast<uint16_t>(raw));
    }
    return true;
  };

  std::vector<uint16_t> sig_algs13;
  std::vector<uint16_t> sig_algs50;
  if (!parse_u16_vec_key("signature_algorithms", &sig_algs13)) return false;
  if (!parse_u16_vec_key("signature_algorithms_cert", &sig_algs50)) return false;

  if (ja3_cfg) {
    ja3_cfg->profile_sigalgs_merged.reserve(sig_algs13.size() +
                                            sig_algs50.size());
    ja3_cfg->profile_sigalgs_merged.insert(ja3_cfg->profile_sigalgs_merged.end(),
                                           sig_algs13.begin(), sig_algs13.end());
    ja3_cfg->profile_sigalgs_merged.insert(ja3_cfg->profile_sigalgs_merged.end(),
                                           sig_algs50.begin(), sig_algs50.end());
  }

  if (!sig_algs13.empty()) {
    if (SSL_CTX_set_verify_algorithm_prefs(ctx, sig_algs13.data(),
                                           sig_algs13.size()) != 1) {
      ERR_print_errors_fp(stderr);
      *err_out =
          "SSL_CTX_set_verify_algorithm_prefs failed for profile "
          "signature_algorithms";
      return false;
    }
  }

  if (!sig_algs50.empty()) {
    if (SSL_CTX_set_meshvpn_client_signature_algorithms_cert(
            ctx, sig_algs50.data(), sig_algs50.size()) != 1) {
      ERR_print_errors_fp(stderr);
      *err_out =
          "SSL_CTX_set_meshvpn_client_signature_algorithms_cert failed for "
          "profile signature_algorithms_cert";
      return false;
    }
  }

  if (ja3_cfg) {
    for (uint16_t et : ja3_cfg->profile_extension_types) {
      if (et == 5) {
        SSL_CTX_enable_ocsp_stapling(ctx);
        std::cerr << "boring-tls-helper: note: профиль содержит расширение 5 "
                     "(status_request) — SSL_CTX_enable_ocsp_stapling.\n";
        break;
      }
    }
  }

  if (p.contains("client_hello_extra_extensions")) {
    if (!p["client_hello_extra_extensions"].is_array()) {
      *err_out =
          "client_hello_profile.client_hello_extra_extensions must be array";
      return false;
    }
    size_t added = 0;
    for (const auto& item : p["client_hello_extra_extensions"]) {
      if (!item.is_object()) {
        *err_out =
            "client_hello_profile.client_hello_extra_extensions entries must "
            "be objects";
        return false;
      }
      if (!item.contains("type") ||
          (!item["type"].is_number_unsigned() &&
           !item["type"].is_number_integer())) {
        *err_out =
            "client_hello_extra_extensions.type must be integer (uint16)";
        return false;
      }
      unsigned long et_raw =
          item["type"].is_number_unsigned()
              ? item["type"].get<unsigned long>()
              : static_cast<unsigned long>(item["type"].get<long>());
      if (et_raw > 0xffff) {
        *err_out = "client_hello_extra_extensions.type out of uint16 range";
        return false;
      }
      auto et = static_cast<uint16_t>(et_raw);
      if (!item.contains("hex") || !item["hex"].is_string()) {
        *err_out = "client_hello_extra_extensions.hex must be string";
        return false;
      }
      if (MeshvpnOpaqueExtensionBlocked(et)) {
        std::cerr << "boring-tls-helper: note: пропуск opaque расширения типа "
                  << static_cast<unsigned>(et)
                  << " (GREASE или тип, который задаёт сам BoringSSL/профиль).\n";
        continue;
      }
      std::vector<uint8_t> body;
      std::string hex_err;
      if (!HexDecodeStrict(item["hex"].get<std::string>(), &body, err_out)) {
        return false;
      }
      if (body.size() > 65535) {
        *err_out =
            "client_hello_extra_extensions: decoded body exceeds 65535 bytes";
        return false;
      }
      if (SSL_CTX_meshvpn_add_client_hello_extension(
              ctx, et,
              body.empty() ? nullptr : body.data(), body.size()) != 1) {
        *err_out =
            "SSL_CTX_meshvpn_add_client_hello_extension failed (duplicate "
            "extension type?)";
        return false;
      }
      added++;
    }
    if (added > 0) {
      std::cerr << "boring-tls-helper: note: meshvpn_opaque_extensions_added="
                << added << '\n';
      std::cerr << "boring-tls-helper: note: добавлено opaque расширений из "
                   "профиля: "
                << added << ".\n";
    }
  }

  if (ja3_cfg && p.contains("ja3_md5") && p["ja3_md5"].is_string()) {
    ja3_cfg->expected_ja3_md5 = p["ja3_md5"].get<std::string>();
    for (auto& c : ja3_cfg->expected_ja3_md5) {
      c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    }
  }
  if (ja3_cfg && p.contains("ja3_string") && p["ja3_string"].is_string()) {
    ja3_cfg->expected_ja3_string = p["ja3_string"].get<std::string>();
  }
  if (ja3_cfg && p.contains("ja4") && p["ja4"].is_object()) {
    const auto& j4 = p["ja4"];
    if (j4.contains("fingerprint") && j4["fingerprint"].is_string()) {
      ja3_cfg->expected_ja4_fingerprint =
          j4["fingerprint"].get<std::string>();
      for (auto& c : ja3_cfg->expected_ja4_fingerprint) {
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
      }
    }
  }
  if (ja3_cfg) {
    ja3_cfg->ja3_strict = ja3_strict_cfg;
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
  Ja4Computed ja4_comp;
  bool ja4_ok =
      ComputeJa4FromClientHelloBody(p + 4, hs_body_len, &ja4_comp);
  std::string ja4_fp_lower = ja4_comp.fingerprint;
  for (auto& c : ja4_fp_lower) {
    c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
  }

  if (!cfg->expected_ja4_fingerprint.empty() && ja4_ok &&
      ja4_fp_lower != cfg->expected_ja4_fingerprint) {
    std::cerr << "boring-tls-helper: warning: ja4 profile mismatch expected="
              << cfg->expected_ja4_fingerprint << " actual=" << ja4_fp_lower
              << '\n';
  }

  if (!cfg->expected_ja3_md5.empty()) {
    if (computed.ja3_md5_hex != cfg->expected_ja3_md5) {
      cfg->ja3_mismatch = true;
      std::cerr << "boring-tls-helper: ja3 profile mismatch expected="
                << cfg->expected_ja3_md5 << " actual=" << computed.ja3_md5_hex
                << '\n';
      std::cerr << "boring-tls-helper: ja3_string actual(wire)="
                << computed.ja3_string << '\n';
      if (!cfg->expected_ja3_string.empty()) {
        std::cerr << "boring-tls-helper: ja3_string expected(profile)="
                  << cfg->expected_ja3_string << '\n';
      } else {
        std::cerr
            << "boring-tls-helper: hint: полный профиль от ja3-snif уже содержит "
               "ja3_string — передайте его в helper (clean-vpn передаёт при наличии "
               "в JSON), если не включён permute без ja3_strict; иначе --tls-log-ja3 + "
               "--ja3-verbose на клиенте. Частая причина расхождения — порядок типов "
               "расширений (Chromium ≠ upstream BoringSSL); для фиксированного wire-JA3 "
               "задайте \"permute_extensions\": false и совместимый профиль.\n";
      }
    }
  }

  if (!cfg->profile_extension_types.empty()) {
    std::string ep = MultisetExtraInFirst(cfg->profile_extension_types,
                                          computed.ext_types);
    std::string ew = MultisetExtraInFirst(computed.ext_types,
                                          cfg->profile_extension_types);
    std::cerr << "boring-tls-helper: profile_vs_wire extensions: "
                 "extra_in_profile(multiset)="
              << ep << " extra_on_wire(multiset)=" << ew << '\n';
    if (cfg->ja3_verbose && ep.empty() && ew.empty() &&
        cfg->profile_extension_types != computed.ext_types) {
      std::cerr
          << "boring-tls-helper: profile_vs_wire extensions: multiset совпадает, "
             "порядок типов на wire отличается (permute_extensions / стек).\n";
    }
  }

  if (cfg->ja3_verbose && !cfg->profile_cipher_order.empty()) {
    std::cerr << "boring-tls-helper: profile_vs_wire ciphers: "
                 "extra_in_profile(multiset)="
              << MultisetExtraInFirst(cfg->profile_cipher_order, computed.ciphers)
              << " extra_on_wire(multiset)="
              << MultisetExtraInFirst(computed.ciphers, cfg->profile_cipher_order)
              << '\n';
  }

  if (cfg->ja3_verbose && ja4_ok &&
      !cfg->profile_sigalgs_merged.empty()) {
    std::cerr << "boring-tls-helper: profile_vs_wire ja4_sig_algs: "
                 "extra_in_profile(multiset)="
              << MultisetExtraInFirst(cfg->profile_sigalgs_merged,
                                      ja4_comp.signature_algorithms_merged)
              << " extra_on_wire(multiset)="
              << MultisetExtraInFirst(ja4_comp.signature_algorithms_merged,
                                      cfg->profile_sigalgs_merged)
              << '\n';
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
  std::cerr << "boring-tls-helper: ja3_sorted_md5=" << computed.ja3_sorted_md5_hex
            << '\n';
  if (ja4_ok) {
    std::cerr << "boring-tls-helper: ja4=" << ja4_fp_lower << '\n';
  }
  if (cfg->ja3_verbose) {
    constexpr size_t kHexPrev = 96;
    size_t preview_len = len < kHexPrev ? len : kHexPrev;
    std::cerr << "boring-tls-helper: ja3_string=" << computed.ja3_string
              << '\n';
    std::cerr << "boring-tls-helper: ja3_sorted_string=" << computed.ja3_sorted_string
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
    if (ja4_ok) {
      std::cerr << "boring-tls-helper: ja4_a=" << ja4_comp.ja4_a << '\n';
      std::cerr << "boring-tls-helper: ja4_b=" << ja4_comp.ja4_b << '\n';
      std::cerr << "boring-tls-helper: ja4_c=" << ja4_comp.ja4_c << '\n';
      std::cerr << "boring-tls-helper: ja4_raw_r=" << ja4_comp.raw_r << '\n';
      std::cerr << "boring-tls-helper: ja4_raw_o=" << ja4_comp.raw_o << '\n';
    }
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

  bool emit_clienthello_sni = true;
  if (cfg.contains("client_hello_profile") &&
      cfg["client_hello_profile"].is_object()) {
    const auto& chp = cfg["client_hello_profile"];
    if (chp.contains("emit_sni")) {
      if (!chp["emit_sni"].is_boolean()) {
        return send_err("client_hello_profile.emit_sni must be boolean", 3);
      }
      emit_clienthello_sni = chp["emit_sni"].get<bool>();
    }
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
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    // Порядок suite’ов в духе Chrome / TLS 1.3
    SSL_CTX_set_cipher_list(
        ctx,
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256");

    SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384");
  }

  bool profile_extension_diag = false;
  if (cfg.contains("client_hello_profile") &&
      cfg["client_hello_profile"].is_object()) {
    const auto& ch = cfg["client_hello_profile"];
    if (ch.contains("extension_types") && ch["extension_types"].is_array() &&
        !ch["extension_types"].empty()) {
      profile_extension_diag = true;
    }
  }

  if (ja3_cfg.log_ja3 || ja3_cfg.ja3_verbose || profile_extension_diag ||
      !ja3_cfg.expected_ja3_md5.empty() ||
      !ja3_cfg.expected_ja4_fingerprint.empty()) {
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

  if (!emit_clienthello_sni) {
    std::cerr << "boring-tls-helper: note: ClientHello без расширения server_name "
                 "(emit_sni=false), JA4_a как у клиента без SNI; проверка сертификата "
                 "по verify_host без изменений.\n";
  } else {
    SSL_set_tlsext_host_name(ssl, servername.c_str());
  }
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
