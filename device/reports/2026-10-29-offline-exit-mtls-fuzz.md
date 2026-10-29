# Offline: real exit, mTLS, fuzzing and browser references

29 October 2026. No board connected; no flashing, Mac Wi-Fi/firewall, router,
C6, VPS, host routes or system certificate-store changes.

## Implemented

- Real JavaScript clean-vpn `runExit`/bridge compatibility fixture. Only TUN and
  system network setup are replaced; actual TCP/UDP/raw TLS sockets run on
  loopback. The C client uses production packet framing and real mbedTLS.
- Optional raw TLS client authentication. Exit flag `--tls-raw-client-ca=PATH`
  requires trusted client certificates before tunnel attachment. Existing raw
  TLS without the flag is unchanged. This flag belongs to the JS exit, not the
  separately developed native exit.
- Device admin import/removal of a client certificate and private key. Pair
  validation, one NVS blob, zeroized temporary key buffers, active TLS restart,
  persistence across transports; no private key in status/API responses. A
  corrupt/unreadable saved pair fails closed. Server CA/name/time checks remain.
- Standalone libFuzzer harness for packet validation/checksums, MSS, ICMP,
  Ethernet and fragmented stream/batch framing under ASan/UBSan.
- Offline expected/actual wire JA3 + FoxIO JA4 comparator and a reference from
  an existing captured Chromium ClientHello. No ESP32 mimicry claim.

## Evidence

| Check | Result |
|---|---|
| Full `device/scripts/test-host.sh` | Passed, including production storage/API/TLS tests and new real-exit fixture |
| Real exit TCP | 3 × 64 exact packet round trips, plus 64 after a broken partial-header connection |
| Real exit UDP and raw TLS | 3 × 64 round trips each |
| Real exit mTLS | Missing, wrong-CA and expired clients rejected before TUN; 3 × 64 round trips with valid client |
| Production TLS connection adapter | 3 new connections for each of 9 server/client trust scenarios; clock, missing CA and unreadable client identity reject before handshake |
| Client identity storage | Valid/mismatched keys, CA/server leaf rejection, malformed PEM/blob, clear, storage/commit failures and allocation failures passed |
| HTTP/UI | Auth, invalid input, persistence errors, active TLS restart/removal, other-transport preservation and restart-failure reporting; JavaScript/DOM checks passed |
| Fuzz | **39,599,275 executions in 121 s**, 167 covered counters / 449 features, no ASan/UBSan findings |
| Browser reference comparison | Three fresh captured Node ClientHellos; match, mismatch, missing fingerprint and truncated input checks passed |
| Firmware builds | Stamp P4 + C6, Waveshare P4, XIAO S3; ESP-IDF v5.5.5, NCM/WireGuard enabled |

The XIAO build retains an iot_bridge Kconfig warning about the undefined
`BRIDGE_CUSTOM_MAX_CONNECT_NUMBER` default; the build completes. This dependency
warning was not changed by the TLS work.

Apple clang lacks a bundled libFuzzer archive in this environment. Only the
LLVM 19.1.7 libFuzzer runtime was built in `/tmp`, then linked through
`LIBFUZZER_ARCHIVE`; no installed SDK/toolchain was replaced.

Logs, exit result JSON and generated fuzz corpus are retained locally at
[`perf-results/2026-10-29-offline-exit-mtls-fuzz`](../perf-results/2026-10-29-offline-exit-mtls-fuzz/).
Test PKI remains disposable private temporary material and is not committed.

## Limits and next steps

This is not Linux TUN/NAT, real internet forwarding or radio testing. It does
not demonstrate board TLS memory headroom, speed, AP+STA stability or physical
kill-switch behavior. Fuzzing is bounded to the tested packet paths, not the
entire firmware. Production tests with host ESP-TLS/NVS adapters do not replace
hardware acceptance.

Next, when boards return: one successful and one denied mTLS connection per P4,
actual HTTPS through the tunnel, import/reconnect memory peaks and a short
disconnect/recovery check. Then resume the planned AP+STA A/B/A with two boards.
Do not infer an AP throughput improvement from these offline results.

The JA3/JA4 comparator validates one supplied capture at a time; integration as
a mandatory gate on every new profiled device connection is still pending.
The reference capture's private CA/automation conditions are recorded, and its
fingerprint fields alone cannot recreate a complete browser TLS profile.

Instructions: [mTLS](../VPN.md#optional-raw-tls-client-authentication-mtls),
[local checks/fuzzing](../docs/vpn-local-lab.md#tests-without-any-board),
[browser comparison](../docs/vpn-profile-validation.md).
