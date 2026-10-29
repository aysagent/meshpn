# Profiled TLS feasibility lab

Isolated research code, **not a firmware transport**. No normal product build
includes this directory. The experiment compares real ClientHello bytes and
TLS 1.3 exporters, and compiles a minimal BoringSSL probe for ESP32-S3/P4.
It does not flash anything, switch Wi-Fi, configure TUN/NAT or contact a VPS.

[Results and remaining work](../../reports/2026-10-29-profiled-tls-feasibility.md).

## Requirements and reproduction

Run commands from the repository root. Requires CMake, a C/C++ compiler, Python,
OpenSSL CLI, Node with TLS 1.3 `X25519MLKEM768` support (tested Node 24.13.0 /
OpenSSL 3.5.4), and ESP-IDF **v5.5.5** with installed S3/P4 toolchains.
The host mbedTLS probe builds the SDK submodule's default host configuration;
this is **not** the production firmware's TLS configuration.

The existing clean-vpn helper and its patched, pinned BoringSSL checkout must
already be built. If absent, prepare them once with the existing command:

```sh
npm run build:boring-tls-helper-lowmem
```

The experiment copies that checkout; it does not patch the helper, installed
SDK or product managed components. Default inputs:

- `native/boring_tls/build/_deps/boringssl-src`, revision
  `a7481f34712bc056a47ab91015536166b3a6cebb` with the six clean-vpn patches;
- `native/boring_tls/build/boring-tls-helper`;
- `$HOME/esp/esp-idf-meshpn-v5.5.5`.

Override with `BSSL_SOURCE`, `BSSL_HELPER`, `IDF_PATH`. An inherited `IDF_PATH`
pointing at another SDK is rejected, not silently reused. Use a **new** output
directory for each command:

```sh
IDF_PATH="$HOME/esp/esp-idf-meshpn-v5.5.5" \
  bash device/experiments/profiled-tls/build-host.sh /tmp/meshpn-profile-host-new

IDF_PATH="$HOME/esp/esp-idf-meshpn-v5.5.5" \
  bash device/experiments/profiled-tls/build-idf.sh esp32s3 /tmp/meshpn-profile-s3-new

IDF_PATH="$HOME/esp/esp-idf-meshpn-v5.5.5" \
  bash device/experiments/profiled-tls/build-idf.sh esp32p4 /tmp/meshpn-profile-p4-new
```

Host output contains `run/result.json`, actual ClientHello `.bin`/decoded `.json`,
client stderr logs, build logs and disposable PKI. Output root is private (0700).
**Do not commit `run/pki`**. Only loopback listeners are created, on ephemeral ports.
The runner requires the server to finish each successful handshake before
comparing exporters; negative cases must fail in TLS, not by process timeout.
`result.json` appears only after all assertions pass. A successful experiment
can correctly report **zero fingerprint matches**; it does not authorize a
profiled VPN connection. Exporter secrets are compared in memory, not saved.

IDF output contains `size-stack.json`, `build.log`, SDK config, source manifest
and a standalone ELF/bin. Size includes IDF and the probe, not just TLS overhead.
Stack reports distinguish compiled frames from matching linked symbols;
individual frames are not a full stack high-water measurement.
The standalone main uses a conservative 64 KiB stack and bootloader entropy
while radio is inactive. This does **not** validate product entropy/allocator,
Wi-Fi coexistence or that stack size on a board. Do not flash this image as a
MeshPN update: it has no product networking, admin, USB or saved-profile code.

## What is compared

The frozen reference comes from a real repository Chromium capture; see
[its provenance and limitations](../../docs/vpn-profile-validation.md).
Each new connection is checked against both exact wire JA3 and FoxIO JA4.
Sorted JA3 is never accepted as a substitute. Captures must be distinct.

- Three captures each: mbedTLS default TLS 1.2, default TLS 1.3, preferences;
  BoringSSL default and preferences.
- Three successful TLS 1.3 connections per backend with CA/name verification,
  matching `EXPORTER-clean-vpn-bind` on both endpoints and no exporter reuse.
- Wrong CA rejected by both backends.
- Three successful BoringSSL connections with a hybrid-only server
  (`X25519MLKEM768`); mbedTLS rejection with that server is checked separately.
- Three captures from the existing desktop helper using the reference's fields.
  The reference lacks opaque extension payloads; this does not test the helper
  with a complete replayable browser profile.

Preference mode configures real ciphers, key exchange and verification algorithms
where APIs allow. No fake opaque extensions or byte rewriting after transcript
hashing is used. The IDF image only generates a ClientHello into a memory BIO;
compilation alone is not evidence of a device handshake.

## Port scope

`prepare-bssl.py` verifies the upstream revision and clean-vpn patch markers,
records the input diff hash, then adjusts an isolated copy:

- Recognize 32-bit Xtensa in `target.h`.
- Use `uint32_t` for two extension indices (Xtensa's `uint32_t` is not `unsigned`).
- Enable explicit allocator hooks only for host measurement; upstream ELF weak
  hooks are not active on Mach-O. Hook activity is asserted, not assumed.

IDF uses `OPENSSL_SMALL`, no assembly/filesystem/POSIX socket BIO, pthread locks,
SDK lwIP headers and a standalone `esp_fill_random` entropy adapter. Host heap
figures count BoringSSL requested allocations only: no allocator overhead,
stack or other firmware tasks, and host pointer sizes differ from ESP32.
No BoringSSL sources or generated build products are vendored here.
