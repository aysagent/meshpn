#include "transparent_handshake.hpp"
#include "transparent_auth.hpp"
#include "transparent_config.hpp"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <iostream>
#include <memory>
#include <thread>
#include <atomic>

using namespace cvpn;
using namespace cvpn::transparent;
using Direction = HandshakeGate::Direction;
static void need(bool ok) { require(ok, "transparent_test_assertion"); }
template<class F> static void rejected(F f) {
  bool fail = false; try { f(); } catch (const std::runtime_error&) { fail = true; } need(fail);
}
static void append16(Bytes& b, size_t n) { b.push_back(n >> 8); b.push_back(n); }
static Bytes recordize(const Bytes& payload, const std::vector<size_t>& lengths, uint8_t type = 22) {
  Bytes out; size_t at = 0;
  for (size_t n : lengths) {
    need(n && n <= record_limit && n <= payload.size() - at);
    out.insert(out.end(), {type, 3, 3}); append16(out, n);
    out.insert(out.end(), payload.begin() + at, payload.begin() + at + n); at += n;
  }
  need(at == payload.size()); return out;
}
static Bytes synthetic(const std::string& host = "origin.example", size_t padding = 0) {
  Bytes body(34, 0x55); body[0] = 3; body[1] = 3; body.push_back(0);
  body.insert(body.end(), {0,2,0x13,1,1,0});
  Bytes ex = {0,0}; append16(ex, 5 + host.size()); append16(ex, 3 + host.size());
  ex.push_back(0); append16(ex, host.size()); ex.insert(ex.end(), host.begin(), host.end());
  ex.insert(ex.end(), {0,43,0,5,4,3,4,3,3});
  // ECH/GREASE and PSK bytes are opaque and must survive round-trip exactly.
  ex.insert(ex.end(), {0xfe,0x0d,0,5,0xff,0x00,0x22,0x11,0x33});
  if (padding) { ex.insert(ex.end(), {0,21}); append16(ex, padding); ex.insert(ex.end(), padding, 0); }
  ex.insert(ex.end(), {0,41,0,4,1,2,3,4});
  append16(body, ex.size()); body.insert(body.end(), ex.begin(), ex.end());
  Bytes p = {1, uint8_t(body.size() >> 16), uint8_t(body.size() >> 8), uint8_t(body.size())};
  p.insert(p.end(), body.begin(), body.end()); return p;
}
static Bytes server_hello(bool retry, bool tls13 = true) {
  Bytes p(38, 0); p[0] = 2; p[4] = 3; p[5] = 3;
  const uint8_t random[] = {0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
    0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
  if (retry) std::copy(std::begin(random), std::end(random), p.begin() + 6);
  p.insert(p.end(), {0,0x13,1,0});
  if (tls13) p.insert(p.end(), {0,6,0,43,0,2,3,4});
  p[3] = p.size() - 4; return recordize(p, {p.size()});
}
static Bytes feed(HandshakeGate& gate, Direction direction, const Bytes& b, size_t chunk = 1, uint64_t now = 1) {
  Bytes out;
  for (size_t at = 0; at < b.size();) {
    size_t n = std::min(chunk, b.size() - at);
    gate.feed(direction, b.data() + at, n, now, [&](const Bytes& part) { out.insert(out.end(), part.begin(), part.end()); });
    at += n;
  }
  return out;
}
static void authorization_units() {
  {
    const auto policy = DestinationPolicy::public_https({});
    for (const char* text : {"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
         "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24",
         "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15",
         "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"}) {
      const auto prefix=IPv4Prefix::parse(text);
      for(uint32_t number : {prefix.network,prefix.network|~prefix.mask}) {
        const Destination d{{uint8_t(number>>24),uint8_t(number>>16),uint8_t(number>>8),uint8_t(number)},443};
        rejected([&]{policy.check(d);});
      }
    }
    for(uint16_t port : {0,22,53,80,444,8443,65535}) rejected([&]{policy.check(Destination{{1,1,1,1},port});});
    for(const char* invalid : {"1.1.1.1", "1.1.1.1/24", "1.1.1.0/024", "1.1.1.0/33", "1.1.1.0/-1",
         "1.1.1.0/", "1.1.1.0/24/1", "01.1.1.0/24", "::/0", "1.1.1.0/ 24"})
      rejected([&]{(void)IPv4Prefix::parse(invalid);});
    rejected([&]{DestinationPolicy::public_https({"1.1.1.0/24","1.1.1.0/24"});});
    rejected([&]{DestinationPolicy::public_https(std::vector<std::string>(65,"1.1.1.1/32"));});
    rejected([&]{DestinationPolicy::public_https({"0.0.0.0/0"}).check(Destination{{1,1,1,1},443});});
    using J=nlohmann::json;
    J config={{"version",1},{"transport","transparent-tls"},{"role","client"},
      {"listen",{{"ipv4","127.0.0.1"},{"port",33002}}},{"exit",{{"ipv4","8.8.8.8"},{"port",33001}}},
      {"secret_path","/fixture/secret"},{"public_name","relay.example"},
      {"destination_policy",{{"mode","public-https"},{"deny_ipv4",J::array({"1.1.1.0/24"})}}}};
    TransparentConfig c(config);need(c.public_https);
    rejected([&]{c.policy().check(Destination{{8,8,8,8},443});}); // endpoint address, any port
    rejected([&]{c.policy().check(Destination{{1,1,1,1},443});});
    for(const J& bad_policy : {J{{"mode","public-https"}}, J{{"mode","all"},{"deny_ipv4",J::array()}},
         J{{"mode","public-https"},{"deny_ipv4",J::array()},{"allow_private",true}},
         J{{"mode","public-https"},{"deny_ipv4",J::array({"1.1.1.1/24"})}}}) {
      auto bad=config;bad["destination_policy"]=bad_policy;
      bool failed=false;try{TransparentConfig invalid(bad);}catch(const std::exception&){failed=true;}need(failed);
    }
    config["destinations"]=J::array({{{"ipv4","1.1.1.1"},{"port",443}}});
    rejected([&]{TransparentConfig ambiguous(config);});
    std::cout<<"native public policy units PASS: 18 special ranges and boundaries, ports, canonical prefixes, schema, protected exit\n";
  }
  Digest secret{}; secret.fill(0x42); SniAuthorization auth(secret, "relay.example");
  const Destination dst{{192,0,2,8},443}; DestinationPolicy policy({dst});
  const auto p = synthetic(), wire = recordize(p, {p.size()}); const auto original = parse(wire);
  auto encoded = parse(auth.seal(original, dst, 1000));
  ReplayWindow replay;
  need(auth.accept(encoded, policy, replay, 1000, 100).restored == wire);
  rejected([&] { auth.accept(encoded, policy, replay, 1000, 101); });
  auto upper = encoded.sni; for (char& c : upper) if (c >= 'a' && c <= 'z') c -= 'a' - 'A';
  auto uppercase = parse(replace(encoded, upper));
  rejected([&] { auth.accept(uppercase, policy, replay, 1000, 102); });
  ReplayWindow case_replay; need(auth.accept(uppercase, policy, case_replay, 1000, 100).restored == wire);
  Digest bad = secret; bad[0] ^= 1; SniAuthorization wrong(bad, "relay.example");
  ReplayWindow unused;
  rejected([&] { wrong.accept(encoded, policy, unused, 1000, 100); });
  auto tampered = encoded.sni; tampered[5] = tampered[5] == 'a' ? 'b' : 'a';
  rejected([&] { auth.accept(parse(replace(encoded, tampered)), policy, unused, 1000, 100); });
  auto changed = encoded.wire; changed[11] ^= 1;
  rejected([&] { auth.accept(parse(changed), policy, unused, 1000, 100); });
  SniAuthorization other_suffix(secret, "other.example");
  auto suffix = encoded.sni; suffix.replace(suffix.size() - 13, 13, "other.example");
  rejected([&] { other_suffix.accept(parse(replace(encoded, suffix)), policy, unused, 1000, 100); });
  DestinationPolicy denied({Destination{{192,0,2,9},443}});
  rejected([&] { auth.accept(encoded, denied, unused, 1000, 100); });
  need(auth.accept(encoded, policy, unused, 1000, 100).restored == wire); // bad input did not reserve
  for (uint64_t now : {969, 1031}) { ReplayWindow r; rejected([&] { auth.accept(encoded, policy, r, now, 100); }); }
  ReplayWindow full(1); auth.accept(encoded, policy, full, 1000, 100);
  auto next = parse(auth.seal(original, dst, 1000));
  rejected([&] { auth.accept(next, policy, full, 1000, 102); });
  auto fresh = parse(auth.seal(original, dst, 1062));
  need(auth.accept(fresh, policy, full, 1062, 62101).restored == wire);
  rejected([&] { auth.accept(encoded, policy, full, 1000, 62102); }); // clock rollback poisons instance
  rejected([&] { auth.accept(parse(auth.seal(original, dst, 1063)), policy, full, 1063, 62103); });
  ReplayWindow frozen(1); auth.accept(encoded, policy, frozen, 1000, 1);
  rejected([&] { auth.accept(next, policy, frozen, 1000, 1000000); }); // no eviction with frozen wall time
  ReplayWindow parallel; std::atomic<unsigned> accepted{0}; std::vector<std::thread> workers;
  for (int i = 0; i < 16; ++i) workers.emplace_back([&] { try { auth.accept(encoded, policy, parallel, 1000, 100); ++accepted; } catch (...) {} });
  for (auto& t : workers) t.join();
  need(accepted == 1);
  for (size_t n = 1; n <= 150; ++n) {
    Bytes bytes(n); for (size_t i = 0; i < n; ++i) bytes[i] = uint8_t(i);
    need(unbase32(base32(bytes)) == bytes);
  }
  rejected([&] { unbase32("a"); }); rejected([&] { unbase32("ab"); });
  auto longp = synthetic(std::string(60, 'a') + "." + std::string(60, 'b'));
  rejected([&] { auth.seal(parse(recordize(longp, {longp.size()})), dst, 1000); });
  std::cout << "native transparent auth PASS: binding, AEAD, policy, clocks, replay, capacity, concurrent admission\n";
}
static void units() {
  authorization_units();
  const std::string relay = "Abc123.encrypted-routing-token.public.example";
  const auto p = synthetic(); const auto wire = recordize(p, {p.size()});
  const auto first = parse(wire);
  need(first.sni == "origin.example" && first.tls13);
  size_t layouts = 0;
  for (size_t split = 1; split < p.size(); ++split) {
    const auto fragmented = recordize(p, {split, p.size() - split});
    for (size_t chunk : {1, 2, 5, 17, 4096}) {
      HelloReader r;
      for (size_t at = 0; at < fragmented.size();) {
        size_t n = std::min(chunk, fragmented.size() - at);
        need(r.feed(fragmented.data() + at, n) == n); at += n;
      }
      need(r.done() && r.retained() <= hello_limit * 2);
      auto h = r.take(); auto replaced = replace(h, relay); auto encoded = parse(replaced);
      need(encoded.sni == relay && replace(encoded, h.sni) == fragmented);
      need(encoded.identity == h.identity && encoded.tls13); ++layouts;
    }
  }
  // Tail belongs to the gate, not the first ClientHello reader.
  auto with_tail = wire; with_tail.insert(with_tail.end(), {23,3,3,0,1,0xaa});
  HelloReader r; need(r.feed(with_tail.data(), with_tail.size()) == wire.size()); need(r.done());
  need(r.take().wire == wire); rejected([&] { r.take(); });
  for (size_t cut = 0; cut < wire.size(); ++cut) rejected([&] { parse(Bytes(wire.begin(), wire.begin() + cut)); });
  for (const auto& name : {"", "-bad.test", "bad-.test", "bad..test", "bad.test.", "bad/test", "a b", "\xc3\xa9.test"}) {
    rejected([&] { replace(first, name); });
  }
  rejected([&] { replace(first, std::string(64, 'a') + ".test"); });
  for (size_t offset : {size_t(0),size_t(1),size_t(3),size_t(4),size_t(5),size_t(6),size_t(7),size_t(8)}) {
    auto b = wire; b[offset] = 0xff; rejected([&] { parse(b); });
  }
  auto invalid = p; invalid[first.host_at] = '/';
  rejected([&] { parse(recordize(invalid, {invalid.size()})); });
  invalid = p; put16(invalid, first.host_at - 2, 65535);
  rejected([&] { parse(recordize(invalid, {invalid.size()})); });
  invalid = p; put16(invalid, first.extensions_at, 0);
  rejected([&] { parse(recordize(invalid, {invalid.size()})); });
  invalid = p; put16(invalid, first.host_at + first.host_size, 0); // duplicate SNI extension
  rejected([&] { parse(recordize(invalid, {invalid.size()})); });
  invalid = p; invalid.push_back(1); // CH+extra in one record is unsupported
  rejected([&] { parse(recordize(invalid, {invalid.size()})); });
  auto crowded = synthetic("origin.example", record_limit - p.size() - 4);
  need(crowded.size() == record_limit);
  rejected([&] { replace(parse(recordize(crowded, {crowded.size()})), relay); });
  auto longhello = synthetic("origin.example", 300);
  std::vector<size_t> tiny(129, 1); tiny.push_back(longhello.size() - 129);
  rejected([&] { parse(recordize(longhello, tiny)); });
  rejected([&] { parse(Bytes{22,3,3,0,4,1,255,255,255}); });
  // A shorter replacement cannot erase the first hostname byte's record.
  const auto split_sni = recordize(p, {first.host_at + 1, p.size() - first.host_at - 1});
  rejected([&] { replace(parse(split_sni), "a"); });
  // Deterministic malformed input exercise. Successful parses must round-trip;
  // invalid resizes are explicitly permitted, memory corruption is not.
  uint32_t random = 0x12345678;
  for (size_t i = 0; i < 10000; ++i) {
    Bytes b = wire;
    for (size_t j = 0; j < 1 + i % 4; ++j) {
      random = random * 1664525 + 1013904223; size_t at = random % b.size();
      random = random * 1664525 + 1013904223; b[at] = random >> 24;
    }
    try { auto h = parse(b); auto changed = replace(h, relay); need(replace(parse(changed), h.sni) == b); }
    catch (const std::runtime_error& e) { if (std::string(e.what()) == "transparent_test_assertion") throw; }
  }
  const Bytes ccs = {20,3,3,0,1,1}, early = {23,3,3,0,3,0xaa,0xbb,0xcc};
  const auto hrr = server_hello(true), final = server_hello(false);
  HandshakeGate client(first, relay, 0);
  HandshakeGate exit(parse(replace(first, relay)), first.sni, 0);
  need(feed(client, Direction::client, early) == early);
  need(feed(exit, Direction::client, early) == early);
  need(feed(client, Direction::server, hrr) == hrr && feed(exit, Direction::server, hrr) == hrr);
  need(feed(client, Direction::client, ccs) == ccs && feed(exit, Direction::client, ccs) == ccs);
  need(feed(exit, Direction::client, feed(client, Direction::client, wire)) == wire);
  need(feed(exit, Direction::server, final) == final && feed(client, Direction::server, final) == final);
  need(client.retries() == 1 && exit.retries() == 1 && client.opaque() && exit.opaque());
  need(feed(client, Direction::client, early) == early);
  client.end(Direction::client); exit.end(Direction::server);
  // A partial early-data record may overlap the server flight without loss.
  HandshakeGate overlap(first, relay, 0);
  need(feed(overlap, Direction::client, Bytes(early.begin(), early.begin() + 3)).empty());
  need(feed(overlap, Direction::server, final) == final);
  need(feed(overlap, Direction::client, Bytes(early.begin() + 3, early.end())) == early);
  for (int scenario = 0; scenario < 10; ++scenario) {
    HandshakeGate g(first, relay, 0);
    rejected([&] {
      if (scenario == 0) feed(g, Direction::client, Bytes{22}); // partial premature CH2
      if (scenario == 1) { feed(g, Direction::server, hrr); feed(g, Direction::server, hrr); }
      if (scenario == 2) { feed(g, Direction::server, hrr); feed(g, Direction::client, replace(first, "other.example")); }
      if (scenario == 3) { feed(g, Direction::server, hrr); auto b = wire; b[11] ^= 1; feed(g, Direction::client, b); }
      if (scenario == 4) { feed(g, Direction::server, hrr); feed(g, Direction::client, wire); feed(g, Direction::server, hrr); }
      if (scenario == 5) { feed(g, Direction::server, hrr); feed(g, Direction::client, wire); feed(g, Direction::server, server_hello(false, false)); }
      if (scenario == 6) g.check_timeout(10000);
      if (scenario == 7) { feed(g, Direction::server, Bytes{22,3}); g.end(Direction::server); }
      if (scenario == 8) feed(g, Direction::client, Bytes{20,3,3,0,1,2});
      if (scenario == 9) { feed(g, Direction::client, early, 1, 9999); g.check_timeout(10000); }
    });
    rejected([&] { feed(g, Direction::client, early); }); // failures are sticky
  }
  std::cout << "native transparent codec PASS: " << layouts << " fragmented layouts, 10000 mutations, HRR gates\n";
}

// Test-only origin and application TLS endpoints. Relay objects never receive
// private keys, terminate TLS or inspect plaintext application bytes.
struct Endpoint {
  bssl::UniquePtr<SSL> ssl;
  explicit Endpoint(SSL_CTX* ctx, bool server) : ssl(SSL_new(ctx)) {
    need(bool(ssl)); BIO* in = BIO_new(BIO_s_mem()); BIO* out = BIO_new(BIO_s_mem()); need(in && out);
    BIO_set_mem_eof_return(in, -1); BIO_set_mem_eof_return(out, -1);
    SSL_set_bio(ssl.get(), in, out);
    if (server) SSL_set_accept_state(ssl.get()); else SSL_set_connect_state(ssl.get());
  }
  void step() {
    int rc = SSL_do_handshake(ssl.get());
    if (rc == 1) return;
    int e = SSL_get_error(ssl.get(), rc); need(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE);
  }
  Bytes drain() {
    Bytes b; uint8_t buf[4096]; int n;
    while ((n = BIO_read(SSL_get_wbio(ssl.get()), buf, sizeof(buf))) > 0) b.insert(b.end(), buf, buf + n);
    need(b.size() <= 1024 * 1024); return b;
  }
  void input(const Bytes& b) { if (!b.empty()) need(BIO_write(SSL_get_rbio(ssl.get()), b.data(), b.size()) == int(b.size())); }
};

static bssl::UniquePtr<SSL_SESSION> saved_session;
static int remember_session(SSL*, SSL_SESSION* session) { saved_session.reset(session); return 1; }
static void tls_trial(const char* cert, const char* key, int version, bool retry, size_t chunk) {
  bssl::UniquePtr<SSL_CTX> cc(SSL_CTX_new(TLS_method())), sc(SSL_CTX_new(TLS_method())); need(cc && sc);
  for (SSL_CTX* c : {cc.get(), sc.get()}) {
    need(SSL_CTX_set_min_proto_version(c, version) && SSL_CTX_set_max_proto_version(c, version));
  }
  need(SSL_CTX_use_certificate_chain_file(sc.get(), cert) && SSL_CTX_use_PrivateKey_file(sc.get(), key, SSL_FILETYPE_PEM));
  need(SSL_CTX_load_verify_locations(cc.get(), cert, nullptr));
  SSL_CTX_set_verify(cc.get(), SSL_VERIFY_PEER, nullptr); SSL_CTX_set_grease_enabled(cc.get(), 1);
  SSL_CTX_set_session_cache_mode(cc.get(), SSL_SESS_CACHE_CLIENT);
  SSL_CTX_sess_set_new_cb(cc.get(), remember_session);
  const uint8_t context[] = {1,2,3}; need(SSL_CTX_set_session_id_context(sc.get(), context, sizeof(context)));
  need(SSL_CTX_set1_groups_list(cc.get(), "X25519:P-256"));
  need(SSL_CTX_set1_groups_list(sc.get(), retry ? "P-256" : "X25519:P-256"));
  saved_session.reset();
  for (bool resume : {false, true}) {
  Endpoint app(cc.get(), false), origin(sc.get(), true);
  if (resume) { need(bool(saved_session)); need(SSL_set_session(app.ssl.get(), saved_session.get())); }
  need(SSL_set_tlsext_host_name(app.ssl.get(), "localhost") && SSL_set1_host(app.ssl.get(), "localhost"));
  app.step(); Bytes first_wire = app.drain(); auto h = parse(first_wire);
  // Real endpoints also see fragmented TLS records, not merely split TCP
  // reads. Split the handshake header and the SNI itself on every TLS trial.
  first_wire = recordize(h.payload, {1, h.host_at + 1, h.payload.size() - h.host_at - 2});
  h = parse(first_wire);
  Digest secret{}; secret.fill(0x42); SniAuthorization auth(secret, "relay.example");
  const Destination dst{{192,0,2,8},443}; DestinationPolicy policy({dst}); ReplayWindow replay;
  auto changed = auth.seal(h, dst, 1000); auto remote = parse(changed); const auto relay = remote.sni;
  auto authorized = auth.accept(remote, policy, replay, 1000, 0);
  need(remote.sni == relay && changed != first_wire && replace(remote, h.sni) == first_wire);
  HandshakeGate cg(h, relay, 0), eg(remote, h.sni, 0);
  origin.input(authorized.restored);
  for (int i = 0; i < 100 && (!SSL_is_init_finished(app.ssl.get()) || !SSL_is_init_finished(origin.ssl.get())); ++i) {
    origin.step(); auto b = origin.drain();
    app.input(feed(cg, Direction::server, feed(eg, Direction::server, b, chunk), chunk));
    app.step(); b = app.drain();
    auto encoded = feed(cg, Direction::client, b, chunk);
    auto decoded = feed(eg, Direction::client, encoded, chunk);
    need(decoded == b); origin.input(decoded);
  }
  need(SSL_is_init_finished(app.ssl.get()) && SSL_is_init_finished(origin.ssl.get()));
  need(SSL_get_verify_result(app.ssl.get()) == X509_V_OK);
  need(SSL_session_reused(app.ssl.get()) == int(resume));
  need(std::string(SSL_get_servername(origin.ssl.get(), TLSEXT_NAMETYPE_host_name)) == "localhost");
  need(cg.retries() == unsigned(retry) && eg.retries() == unsigned(retry) && cg.opaque() && eg.opaque());
  // Authenticated bidirectional application bytes, not just successful parsing.
  for (bool reverse : {false, true}) {
    Endpoint& sender = reverse ? origin : app; Endpoint& receiver = reverse ? app : origin;
    const Direction dir = reverse ? Direction::server : Direction::client;
    Bytes plain(16384); for (size_t i = 0; i < plain.size(); ++i) plain[i] = uint8_t(i);
    need(SSL_write(sender.ssl.get(), plain.data(), plain.size()) == int(plain.size()));
    auto b = sender.drain();
    receiver.input(feed(cg, dir, feed(eg, dir, b, chunk), chunk));
    Bytes received(plain.size()); int n = SSL_read(receiver.ssl.get(), received.data(), received.size());
    need(n == int(plain.size()) && received == plain);
  }
  }
  saved_session.reset();
  std::cout << "native transparent TLS PASS: version=" << version << " HRR=" << retry << " chunk=" << chunk << " full+resumed\n";
}
int main(int argc, char** argv) {
  try {
    if (argc == 1) units();
    else if (argc == 3) for (size_t chunk : {1, 7, 16384}) {
      tls_trial(argv[1], argv[2], TLS1_2_VERSION, false, chunk);
      tls_trial(argv[1], argv[2], TLS1_3_VERSION, false, chunk);
      tls_trial(argv[1], argv[2], TLS1_3_VERSION, true, chunk);
    } else return 2;
    return 0;
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; ERR_print_errors_fp(stderr); return 1; }
}
