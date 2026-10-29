# VPN throughput investigation, 29–30 October 2026

Both P4 boards use the existing native `boring-tls` exit, TLS 1.3 / HTTP/2,
TLS_AES_128_GCM_SHA256 and their distinct peer identities. The exit, router,
Mac Wi-Fi, firewall, saved credentials and captured browser profiles were not
changed. VPN was disabled only for bounded DIRECT controls and restored in
`finally`. All reported Internet measurements below use Mac curl explicitly
bound to the respective USB interface; the phone speed test is not reproduced
as an identical workload.

## Baseline and isolation

Same HTTPS endpoint, 4 MiB download and 1 MiB upload, including setup:

| Board / mode | Download Mbit/s | Upload Mbit/s |
|---|---:|---:|
| Stamp, original VPN | 2.09 | 2.28 |
| Stamp, DIRECT | 32.33 | 26.75 |
| Waveshare, original VPN | 1.12 | 1.00 |
| Waveshare, DIRECT during investigation | 2.27 | 1.40 |

A later Stamp DIRECT control remained 32.97 / 18.66. Waveshare DIRECT after
reselecting the same saved Wi-Fi profile was 1.33 / 0.51. Its slow path therefore
exists without VPN. Local board-generated 8 MiB HTTP responses reached 45.87
Mbit/s on Waveshare and 44.23 on Stamp; this is a USB-path check, not a Wi-Fi
measurement. The Waveshare local check briefly overlapped a later VPN control;
that later VPN control is not used to attribute a performance change.

## Changes and rejected experiments

- Added per-connection TLS I/O timings, cipher and once-per-second snapshots.
  Timings include framing, socket I/O and preemption, not isolated encryption.
- Added a read-only snapshot of the owned outer TCP socket on the lwIP core:
  exact four-tuple, congestion/window state, outstanding/queued bytes and
  current retries. No PCB pointers escape the core. Retry counts reset on ACK;
  RTT uses lwIP's coarse timer and must not be read as precise ping latency.
- During active traffic poll for newly queued LAN data at 1 ms; after 100 ms
  without successful TLS I/O return to 10 ms. A permanently short poll raised
  idle CPU and is not retained.
- P4 network allocations prefer PSRAM. In the Waveshare old-buffer control,
  internal minimum free reached 2,416 bytes and the TLS connection broke.
  With PSRAM-first allocations the observed internal minimum was over 60 KiB.
  This preference can fall back to internal RAM if PSRAM is exhausted; it is
  not an absolute allocation isolation guarantee.
- Tried larger TCP receive/send windows. Receive 128 KiB / send 112 KiB alone
  did not establish a reliable speed improvement. Send 128 KiB fails lwIP's
  16-bit low-watermark sanity check; those checks were not disabled. A 64 KiB
  send buffer also failed to improve the short upload consistently.
- Added selective ACK support. Stamp's first receive-128/send-32/SACK trial
  reached 5.36 / 2.15; repeat 2.75 / 1.97. This is variance, not a sustained
  5.36 Mbit/s claim. USB/SDIO counters did not locate corresponding drops;
  the outer TCP socket did show retry/duplicate-ACK recovery and shrinking cwnd.
- P4 HTTP stack spare fell below 1 KiB with the expanded status snapshot.
  Increased its HTTP/HTTPS stack to 12/16 KiB; XIAO retains its old budget.
- Corrected Wi-Fi diagnostic serialization for remote Kconfig that defines
  TX_BUFFER_TYPE=0 without the static-choice boolean. Host build buffer counts
  are explicitly labelled as defaults, not measured C6 runtime settings.

## Evidence and limits

Private ignored artifacts: `perf-results/vpn-slow-20261029/` (status samples,
per-run curl results, baseline/variant comparisons). A reconnect invalidates
subtraction of per-connection TLS counters; negative deltas in exploratory
summaries are not timing results. Raw before/after snapshots remain available.

Stamp's 4 MiB receive runs spent about 4.2 s in SSL_read and 0.6 s in SSL_write.
Its worker core reached 84–88% in the faster trial. The current BoringSSL build
uses OPENSSL_NO_ASM and does not dispatch AES-GCM records to the P4 accelerator.
That is a candidate for further measured acceleration, not proof that all idle
network time or the Waveshare slowdown is caused by cryptography. Fingerprint,
CA/name verification, Bearer v2 and kill switch remain enabled.

Waveshare's old vendor C6 image does not report its firmware version through the
current query; Stamp reports Hosted 2.12.1. No C6 image/calibration/NVS was changed.
The existing independent Waveshare Wi-Fi-path issue remains open; a low VPN
number alone cannot identify its cause or justify a C6 flash.

## Retained P4 configuration and validation

Receive window 128 KiB with scale 2, send buffer 32 KiB, receive mailbox 100,
SACK output enabled, lwIP PSRAM-first allocation and TCP timer interval 100 ms
(previously 250 ms). XIAO keeps its existing network-memory/timer defaults.
The shorter interval improves delayed-ACK and RTT-estimator granularity; the
initial RTO policy is not bypassed. Large TX buffer experiments were rejected.
TLS read/write is still serialized on the same worker, with unchanged TLS
profile, certificate checks and HTTP framing.

With this configuration Stamp completed 4 MiB download at 5.44 Mbit/s and
8 MiB at 5.00 Mbit/s; paired 1 MiB uploads were 2.31 and 2.19 Mbit/s. A 4 MiB
upload completed at 1.87 Mbit/s with ingress queue drops, without reconnect.
A repeat 8 MiB download completed at 5.63 Mbit/s with 2.31 Mbit/s upload.
All three final short/8 MiB pairs completed without reconnect.
An attempted 16 MiB Cloudflare download returned HTTP 403 and is **excluded**
from throughput results. These are short WAN tests, not a loss-free capacity
or phone-speed guarantee. Stamp's public egress IP matched the configured VPS.

Validation: full host suite; production profile tunnel H1/H2 tests including
cancellation, malformed traffic and bounded flow control; actual native H2
engine with ALPS on/off and seven malformed-ALPS cases. Native successful cases
each completed 2,368 packet round-trips. Both P4 and XIAO profiled firmware built;
XIAO was not connected or flashed.


## Waveshare compatibility control

A temporary STA b/g/n (11ax disabled) image did not restore throughput:
DIRECT 4 MiB download / 1 MiB upload completed at 1.60 / 0.92 Mbit/s;
VPN download timed out after 35 s with an incomplete body, upload 1.00 Mbit/s.
The logged set operation succeeded, but this vendor C6 does not support the
runtime protocol readback used by the new diagnostic. This is not a verified
radio-negotiation result. The experimental STA override was removed; the
normal board setting is retained. VPN was restored after the DIRECT control.

The final normal Waveshare configuration also had an incomplete VPN download
at the 35 s deadline. Partial-body rates are not successful benchmark results.
Waveshare performance remains unresolved, including without VPN; the Stamp
improvement must not be generalized to this board or to the phone AP test.

## Final flash and health

Both identity-bound P4s were automatically flashed with committed firmware
`3ba7a9f`; ROM entry, programming and return to application CDC succeeded without
buttons or unplugging. Both joined the saved Wi-Fi, authenticated `boring-tls`
over H2 with certificate verification error 0, and returned VPS public IP
154.62.226.216 through their respective USB interfaces. VPN and kill switch
remain enabled; tunnel addresses remain Stamp 10.99.0.4 / Waveshare 10.99.0.3.
Observed internal minimum free was 78,584 / 77,176 bytes (Stamp / Waveshare),
with HTTP task stack spare 3,924 / 4,008 bytes. These are short health checks,
not endurance or speed acceptance.

A final local STA control used authenticated `/api/diag/link-download` and
`link-upload` over Mac's unchanged en0 connection to the home AP. It bypasses
Internet/VPS transport, but includes the Mac Wi-Fi leg and the AP:

| Board | Board → Mac, 8 MiB requested | Mac → board, 1 MiB |
|---|---|---|
| Waveshare | Incomplete: 1,531,904 bytes in 30.87 s, curl 18 | 0.92 Mbit/s, HTTP 200 |
| Stamp | Complete: 4.28 Mbit/s, HTTP 200 | 22.13 Mbit/s, HTTP 200 |

The Waveshare partial-body transfer is a failure, not a valid throughput result.
The initial attempt at the USB-only endpoint through STA returned expected HTTP
403; it was replaced by the existing authenticated local-link endpoint, without
changing access restrictions. Post-test Wi-Fi/VPN remained up on both boards.
Host SDIO queue-full, expiry and RX-drop counters were zero on Waveshare in this
final boot. This local failure further excludes VPS-only explanations, but does
not distinguish C6 radio/firmware from its interaction with the AP. MAC/network
settings, C6 firmware/calibration, Mac Wi-Fi and router were not changed.
