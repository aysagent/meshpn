# Experimental profiled TLS backend

This component is opt-in (`CONFIG_MESHVPN_PROFILED_TLS_ENABLE=n` by default).
It supplies the frozen Chromium capture profile, a local ClientHello gate, a
socket BIO that enforces the gate, bounded PSRAM allocation and a dedicated
FreeRTOS executor. It is wired into the separate **boring-tls** VPN transport, with ALPN-selected HTTP/2 or HTTP/1.1 Bearer v2 and single-owner RX/TX.
[Build, exit flags, admin settings and limitations](../../docs/profiled-tls.md).
The ordinary `tls` transport remains esp-tls/mbedTLS.

The standalone IDF lab uses this component, rather than a separate copy of the
backend. [Build and tests](../../experiments/profiled-tls/README.md).

- `meshvpn_profiled_context(true)` configures native TLS semantics. Load trusted
  CA certificates and set the verified peer name before handshake. No insecure
  fallback is provided by the component.
- `meshvpn_profiled_connection()` applies the supported cold profile. This is
  one frozen profile, not an importer for arbitrary browser JSON.
- `meshvpn_profiled_attach_fd()` installs a per-connection observer and gated
  BIO. A new state must outlive the SSL object. The descriptor stays caller-owned.
  Callers must serialize access to SSL and enforce I/O deadlines/cancellation.
- `meshvpn_profiled_tls_check()` computes exact JA3 and JA4 from the actual
  handshake message. The BIO cannot write before a matching observation, nor
  after a mismatching second ClientHello (e.g. HRR). Fingerprints are not an
  authentication mechanism; normal TLS peer verification is still necessary.
- `meshvpn_profiled_tls_run()` runs a bounded callback synchronously on a lazy
  **32 KiB PSRAM stack**. Semaphore/task allocation failure returns an error;
  execution never falls back onto the caller's 6 KiB VPN RX stack. The external
  caller deletes the completed worker and releases its stack before returning.
  Returned stack spare is for future hardware measurement, not a host estimate.
- All BoringSSL allocations use PSRAM with a **1 MiB aggregate cap**, including
  allocation headers. Exhaustion never falls back to internal/DMA RAM. The
  certificate decoder also limits output to 64 KiB, live decoder allocations to
  256 KiB and cumulative decoder allocation to 1 MiB per certificate. These are
  hard limits, not promised measured peaks. Secrets are cleared before free.

IDF must permit external task stacks. Entropy must be active before TLS: the
standalone lab enables bootloader entropy only while radio/ADC are inactive;
a product integration must use the documented active Wi-Fi entropy source and
valid clock. The component does not reconfigure those shared peripherals.
PSRAM stacks must not run cache-disabled flash/NVS operations; load/store
configuration on the caller before/after the TLS job. Do not forcibly delete
an in-progress TLS job; use bounded nonblocking I/O with cooperative cancellation.

The integrated session verifies CA/name/time, exports the channel binding,
requires a strict HTTP tunnel ACK before marking connected, and checks
configuration cancellation throughout nonblocking I/O. Credentials/endpoints
are persisted by the VPN config component. Real board memory/stack validation
is still required; arbitrary profile import is not implemented. HTTP/2 uses pinned
nghttp2 (see `nghttp2.cmake`) with custom bounded PSRAM session allocation, HPACK,
flow control and one duplex POST stream. Raw IPv4 framing is wrapped in DATA.
The native exit ALPS subset (codepoint 17613, at most six unique settings IDs
1–6 in one bounded SETTINGS frame) is applied before stream creation. The
private nghttp2 adapter shares the native pin and must be re-audited on upgrade.
No synthetic SETTINGS ACK or h2c upgrade is used. Current native engine tests
cover ALPS on/off; JS exit tests retain H1 compatibility.
Matching JA3/JA4 does not establish complete browser or HTTP/2 fingerprint fidelity.
