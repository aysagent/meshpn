# P4 AP+STA queue changes and unresolved slow link — 26 October 2026

Status: **host robustness fixes implemented and installed; AP+STA speedup and
the original phone stall's root cause are not yet established**.

This follows the [initial AP+STA assessment](2026-10-26-p4-apsta-performance.md).
Only the bound P4 `E8F60AE395D0` was flashed. C6 firmware/NVS, router settings,
and Mac Wi-Fi association were not changed. VPN stayed disabled. The S3 of the
other project was not flashed or reset.

## Implemented changes

1. **Bounded Wi-Fi handoff.** Pinned Hosted 1.4.7 used an indefinite wait when
   placing a Wi-Fi frame in the SDIO TX descriptor queue, directly from the
   network caller. It also rejected STA frames immediately while C6 asserted
   Wi-Fi throttling. Wi-Fi SDIO enqueue now uses zero wait and frees a rejected
   DMA copy exactly once without posting the descriptor semaphore.
2. **Congestion staging with interface fairness.** Each interface has 64
   PSRAM-owned frame slots, a 100 ms pre-send age limit and explicit full,
   expiry, policy-change and link-generation cancellation counters. A worker
   can defer STA while continuing AP delivery. Only unaccepted transient errors
   are retried. No C6 capacity wait runs inside lwIP. The uncontended path keeps
   the original direct call, avoiding a PSRAM copy and task switch; SDIO
   completions do not wake an idle staging worker unnecessarily.
3. **Policy serialization.** Deferred final checks/handoffs run in bounded
   batches on the TCP/IP thread, serialized with VPN/endpoint/kill-switch changes.
   All handoffs there are nonblocking; capacity waits remain in the worker.
   Existing in-flight descriptors are not claimed to be recalled after a policy
   change. Tests cover a failed direct send being placed before frames that
   another producer staged while it ran.
4. **Shared bus availability.** The SDIO write task used to keep its driver mutex
   during 1 ms sleeps while waiting for slave credits. It now releases that
   mutex only during sleep and reacquires it before all register access and
   credit reservation. New counters show credit waits and unavailable-buffer
   drops separately from physical I/O errors.
5. **Bounded SDIO RX wait.** A 10 ms IRQ wait is followed by reading the pending
   byte counter. Streaming RX no longer requires NEW_PACKET to remain set to
   drain advertised pending data. Normal idle timeouts, data found after a
   timeout, reads without NEW_PACKET, successful progress and read errors are
   distinguished. After failed CMD53, the byte counter advances only by the
   successfully completed portion, rather than the full requested length.

The RX change is motivated by a published report on the same Hosted version
and P4/C6 topology, not by proof that our phone hit that exact condition
([Espressif EHM-253](https://github.com/espressif/esp-hosted-mcu/issues/221)).
That report also describes indefinite queue waits in the **C6 firmware**;
those slave-side paths have **not** been modified by these host fixes.

Diagnostics are exposed under `wifi.hosted.tx_queue` and
`wifi.hosted.rx_progress`. `sent` means accepted into SDIO, **not** successful
RF delivery. Queue residence covers released staged copies; `direct_sent` is
included in `sent`. `rx_progress.wait_timeouts` is an expected polling counter,
not a transport-error count. Data found after timeout alone does not prove a
lost interrupt edge.

## Local link diagnostic

Admin → Status → Diagnostics → **Test local download** fetches 8 MiB from the
board through the current USB/AP/STA connection. It requires authentication,
an empty POST and a same-subnet peer connecting to one of those local addresses.
The original USB-only endpoint retains its restriction. Responses identify the
actual interface in `X-MeshPN-Link`; the generator has a 30 s budget between
writes, plus any blocking socket-write timeout. Incomplete bodies are rejected.

The page pauses status polling during the transfer, streams/counts bytes without
retaining the whole body, and restores the prior polling state on success or
error. A 35 s client deadline also bounds the request. The test measures a local
TCP/HTTP transfer, **not raw PHY capacity**, WAN or VPN speed. Socket/HTTP chunk
behavior and the Mac-to-router leg can affect its result.

## Hardware observations and comparison limits

A single ROM connection verified the P4 MAC and saved its previous **3 MiB app
partition**, identifying version `d82220a-dirty`, before any new image write.
The auxiliary backup wrapper then attempted to load an already-running stub;
that attempt failed before writing, and the old app returned. Subsequent writes
used the normal identity-bound flasher. The exact saved old app was temporarily
restored for comparison. These were commanded resets/reflashes, not spontaneous
reboots under traffic. No button/cable action was requested.

| Variant and test | Observation |
|---|---|
| First always-staged candidate, WAN download with 0.75 s telemetry | HTTP 200 but only 3,588,636 / 10,000,000 B in 35 s; timed out; 0.82 Mbit/s over that partial window |
| Exact old app, same endpoint and telemetry | HTTP 200 but only 8,441,392 / 10,000,000 B in 35 s; timed out; 1.93 Mbit/s over that partial window |
| Old app, an earlier request without concurrent telemetry | 10,000,000 B in 14.19 s, about 5.64 Mbit/s |
| Direct-fast-path candidate `252de8b-dirty`, local USB | Complete 8 MiB in 1.335 s, 50.27 Mbit/s |
| Same candidate, local STA through router to Mac en0 | Incomplete 2,838,528 B in 30.46 s; generator deadline; 0.75 Mbit/s over the partial window |
| Installed RX-poll build `c91233f`, local USB | Complete 8 MiB in 1.239 s, **54.18 Mbit/s** |
| Same build, local STA | Incomplete 3,833,856 B in 30.38 s; generator deadline; 1.01 Mbit/s over the partial window |

These are not completed AP benchmarks, and failed-body rates are diagnostic,
not speed acceptance results. Small samples and changing link conditions do not
establish a regression ratio or a speedup. The old app is also substantially
slower now than the earlier evening working baseline. Do not attribute the
entire degradation to the candidate, or dismiss its first slow result.

The final observed boot was **1100**, STA online, VPN off. During the last
local test there were no staging rejects/expiry/retries, no C6 throttle events,
no SDIO credit-unavailable drops and no physical read errors. All 2917 STA
handoffs used the direct path; maximum send call was 363 us. RX recorded three
data-bearing reads after a wait timeout, but **zero reads without NEW_PACKET**;
that is not evidence of a reproduced missing-notification stall. Post-test free
internal/DMA memory was **89323 / 49535 B** (overlapping classes). Web stack
minimum remaining was 2420 B; no out-of-memory explanation was observed.

USB ping after the tests: 10/10, mean 0.945 ms. An earlier STA ping under the
affected conditions was 10/10 but mean 300 ms, max 852 ms. Rootless Mac TCP
connection snapshots during separate short STA reads showed a 65535 B receive
window and out-of-order bytes; they do not measure C6 MAC retries or PHY rate.
An attempted tcpdump was unavailable because sudo required a password; no
password prompt or firewall/network-setting change was introduced.

## Validation and remaining work

ASan/UBSan tests compile the actual generated SDIO TX/credit/RX-loop code and
exercise lost-notification recovery, normal idle timeout, throttle-only IRQ,
failed-read counter accounting, zero-wait ownership and semaphore behavior.
Queue tests cover FIFO/fairness, retry, expiry, concurrent fast-call fallback,
link/policy cancellation and allocation/task/queue-init failure cleanup. UI tests
cover completed, truncated and stalled streams and polling-state restoration.
The full host suite and P4 build pass. XIAO build compatibility is checked
without flashing the connected S3.
Final XIAO and P4 builds both passed. After the tests, an unauthenticated USB
login-page request returned HTTP 200 in 16.5 ms, and an en17-bound external
HTTPS request returned HTTP 200 in 516 ms, without changing the admin session.

The phone was asked to run the new local AP test, followed if possible by its
usual internet test. **That AP result is pending.** Avoid agent re-login while
the phone uses the admin: the current single session would be invalidated.
After it completes, correlate AP/STA counters and compare the local AP path
with the slow STA path. Do not call the original phone stall fixed yet.

A separate C6 rate-control degradation report is a hypothesis reference only
([IDFGH-18378](https://github.com/espressif/esp-idf/issues/19164)); no actual C6
rate has been measured here. A new C6 image, forcing PHY rates, HT40/router
changes or automatic resets on throughput alone are not applied as speculative
fixes.

Ignored private artifacts: `perf-results/p4-apsta-queues-b_jujsu5/`, including
`rollback-app.bin`, load samples/results, `old-baseline/`, `rx-poll/`, local
link results and rootless TCP receiver snapshots. Raw metadata and firmware
backups are not committed. The `logs/` subdirectory contains copied test,
build and flash logs; working copies are also in `/tmp/meshpn-apsta-*.log`.
