# Offline browser fingerprint comparison

`device/scripts/vpn-profile-check.mjs` compares one observed ClientHello with a
saved clean-vpn profile. It uses the project's production JA3/JA4 parsers.

```sh
node device/scripts/vpn-profile-check.mjs PROFILE.json CLIENTHELLO.bin REPORT.json
```

Input is binary TLS records containing one connection's complete first
ClientHello, not a pcap or ASCII hex dump (maximum 64 KiB). Extract/reassemble the
TCP stream before calling this tool. Do not combine connections in one file.
The profile must contain both `ja3_md5` and `ja4.fingerprint`; the tool also
accepts a reference document wrapping it in `profile`.

A match requires the exact saved wire JA3 and FoxIO JA4. Sorted JA3 is diagnostic
only; it cannot turn a mismatch into a success. Reports include expected/actual
values and profile/ClientHello SHA256. Exit status is 0 for match, 2 for mismatch;
invalid input fails. Existing output files are not overwritten. Each connection
must provide a fresh capture; no previous successful result is reused.

`tests/fixtures/browser-fingerprint-reference.json` records the source/hash of
one actual Chromium capture already in this repository. That capture used a
private test CA and automation flags; it is not a stock public-Web baseline.
The reference is sufficient for fingerprint comparison, not a complete replayable
TLS helper profile. Chromium extension ordering can vary: a different wire JA3
is a mismatch against this particular reference even when sorted values match.

Tests capture three new ordinary Node ClientHellos, check exact references and
negative/missing/truncated cases, and reject their match to the Chromium
reference. No ESP32 TLS mimicry or on-device validation gate is implemented here.
The [isolated backend experiment](../experiments/profiled-tls/README.md) now
compares actual mbedTLS/BoringSSL/helper ClientHellos and TLS 1.3 exporters;
minimal BoringSSL builds for S3/P4 pass. None of its 27 captures matches the
browser reference. See [results and stack limits](../reports/2026-10-29-profiled-tls-feasibility.md).
This is not a supported profiled firmware transport.

Next: select a complete reproducible target profile, implement the remaining
extension semantics/order and device memory/I/O integration, capture
every new device connection at exit, and block activation on missing or mismatched
validation. Matching JA3/JA4 alone does not establish full browser equivalence.
