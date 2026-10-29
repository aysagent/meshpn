# Experimental profiled TLS backend

This component is opt-in (`CONFIG_MESHVPN_PROFILED_TLS_ENABLE=n` by default).
It supplies the frozen Chromium capture profile, a local ClientHello gate, a
socket BIO that enforces the gate, bounded PSRAM allocation and a dedicated
FreeRTOS executor. It is **not yet wired into the VPN transport selector**.
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

Future VPN integration still needs the clean-vpn HTTP/auth/exporter protocol,
configuration persistence, cancellation, a clear connected-state gate, and
real board memory/stack validation. Do not send raw IPv4 framing on a negotiated
HTTP/2 connection. Matching JA3/JA4 does not establish complete browser fidelity.
