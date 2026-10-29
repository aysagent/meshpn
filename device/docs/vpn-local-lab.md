# Local VPN acceptance, no VPS

The synthetic peer answers only test IPv4 addresses; it does not forward to the
internet, install TUN/routes, change Wi-Fi or add certificates to macOS trust.

```sh
node device/scripts/create-vpn-lab-pki.mjs device/perf-results/vpn-pki
node device/scripts/vpn-local-lab.mjs --board stamp --host MAC_LAN_IPV4 \
  --out device/perf-results/vpn-stamp \
  --ca device/perf-results/vpn-pki/ca.pem \
  --cert device/perf-results/vpn-pki/valid.pem \
  --key device/perf-results/vpn-pki/server.key \
  --server-name exit.meshpn.test --pki device/perf-results/vpn-pki \
  --soak-seconds 600
```

Incoming Node connections must be permitted by the host firewall. No script
changes firewall settings. TCP, UDP, TLS framing, synthetic HTTP/DNS/MSS, admin
responsiveness and reconnect are exercised. Optional `--pki` adds wrong-name,
untrusted-CA, expired and future certificate checks on fresh TLS peers. Trust is
never disabled. TLS throughput is synthetic and is not an internet benchmark.

With incoming connections blocked, `--without-peer` exercises DIRECT, TCP/UDP/TLS
kill-switch failures, DNS, PMTUD and configuration restoration on a real board.
Supply `--ca` and `--server-name` from the same temporary PKI for the TLS case;
`--cert`, `--key` and `--pki` are not needed. This mode uses a small public HTTP
DIRECT control; it does not test a successful hardware TLS handshake or VPN speed.

The original VPN configuration and public CA are saved in a private
`restore.json` before changes. Normal cleanup disables the test tunnel, restores
CA, then restores the original configuration and checks the result. WireGuard
private/PSK fields are not read or changed. `GET /api/vpn/tls-ca` requires admin
authentication and returns public certificates only. A power loss/SIGKILL can
prevent cleanup: recover an unfinished restoration journal with
`node device/scripts/vpn-local-restore.mjs RUN/restore.json`;
do not assume the original VPN policy was restored without checking the report.

Host tests `test-vpn-trust.mjs`, `test-vpn-tls-io.mjs`, `test-vpn-config.mjs` run
production C code with mbedTLS and sanitizers. These are useful without hardware,
but do not establish firmware performance or a real WireGuard/server connection.
`VPN_TLS_IO_PACKETS=8192` extends the TLS I/O case from its normal 128 packets
to a bounded concurrent-read/write stress run (maximum 32768). The peer fragments
the framed stream into 17-byte writes; packet totals and contents are checked.

The synthetic peer validates IPv4 and ICMP/TCP/UDP checksums before replying
(IPv4 zero UDP checksum remains permitted). TCP state is isolated per outer
TCP/TLS connection or UDP endpoint, so a reconnect cannot inherit a previous
connection's SYN/ACK state. These safeguards are tested on loopback; they do
not replace a successful hardware tunnel test.

## Repeated offline connections and slow peers

From the repository root, without a board or VPS:

```sh
VPN_PEER_STRESS_ROUNDS=100 VPN_PEER_STRESS_OUT=/tmp/meshpn-peer-stress.json \
  node device/tests/test-vpn-peer-stress.mjs
IDF_PATH=/Users/yurich/esp/esp-idf-meshpn-v5.5.5 \
  bash device/scripts/test-host.sh
```

The first test runs TCP/UDP/TLS echo cycles, fragmented stream headers, partial
disconnects, and non-reading TCP/TLS clients. It checks packet counts and that
tracked sockets, flows and queued output are released. Memory samples are saved,
but RSS changes alone do not prove a leak or absence of one. This exercises the
Node test peer, not an ESP32 RTOS, radio, WireGuard or an internet exit.

The full host suite prints its temporary artifact directory. To repeat the
production TLS I/O wrapper with its built mbedTLS libraries in one process per
scenario, use that directory:

```sh
VPN_TLS_IO_ROUNDS=12 node device/tests/test-vpn-tls-io.mjs \
  /tmp/meshpn-host-tests.REPLACE/mbedtls/library
```

`VPN_TLS_IO_ROUNDS` accepts 1–100. Each round creates and destroys a fresh TLS
context/socket; the default is 128 verified frames each way. Both fragmentation
and forced read/write backpressure scenarios run. At most 64 frames remain
unacknowledged, keeping extended runs bounded. Certificate verification remains
enabled. ASan/UBSan and the production TX-worker cancellation tests are separate
checks; this is not a complete firmware lifecycle simulation.

The synthetic TCP/TLS peer now honours `write()` backpressure and bounds its
pending application output (default 256 KiB per connection). Overflow closes
that connection; it never drops bytes from the middle of a framed stream and
continues. `startPeer()` accepts `maxPendingBytes` and `writeDelayMs` for tests.
These limits exclude kernel/TLS buffers and do not add UDP delivery guarantees.
