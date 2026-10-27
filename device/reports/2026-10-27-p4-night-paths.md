# P4 AP/STA night investigation — 27 October 2026

**Observation completed with warnings. STA slowdown and the original phone stall
remain unresolved. A separate confirmed RPC crash is fixed.**

The background observation ran 01:50–04:50 MSK on 27 October. Final analysis was
completed after the user's morning follow-up, not continuously throughout the
night. No claim of restored Wi-Fi throughput follows from the diagnostics below.

VPN is off. Mac Wi-Fi association, router configuration, Mac firewall and C6
firmware are unchanged. Only bound P4 `E8F60AE395D0` is flashed, without buttons.
All temporary radio/USB controls have saved images, source and SHA-256 manifests
under private artifacts. They are not proposed production defaults.

## Starting evidence

The user retried from phone AP and numeric 1.1.1.1 eventually opened. Actual
phone `192.168.11.2` handshake traces reached all five stages, including reverse
NAPT and AP SDIO acceptance. This establishes a working request after reboot,
not the cause of the previous failure. The phone later disconnected.

A separate direct Mac request downloaded the same Cloudflare 3 MB object in
0.178 s. Via USB/P4, the transfer received only 2071785 B in 35 s and timed out.
A local STA connect also timed out; another received only 24440 B in 35 s.
Five STA ping replies eventually arrived, four beyond the 1 s wait window;
RTT ranged 923–2544 ms. USB admin remained reachable. This is not a DNS-only
or phone-only failure.

Radio snapshots: channel 4, HT20, power save off, configured maximum transmit
power **20 dBm**, uplink RSSI around -47 to -55 dBm. These are not measured
PHY rate, RF noise or C6 retry counts. No RF rate is inferred from RSSI.

## Implemented diagnostics

* Authenticated local upload (1..8 MiB, bounded time and fixed-size discard
  buffer), with a board receipt. Mac bytes queued to its own TCP socket are
  **not** counted as completed uploads.
* Paced synthetic AP UDP echo through real NAPT and STA, with distinct
  injected/SDIO-accepted/server-received/returned counts, sequence, nonce,
  checksum checks and bounded cleanup. It does not exercise AP radio delivery.
* Cached, read-only TX power limit; failed unsupported getter calls are latched.
* IDF wlanif branch counters: down, allocation failure, input rejection and
  accepted-to-lwIP. Default esp_netif_receive returns success even when its
  internal input discards a packet, so its public return was insufficient.
  The instrumentation preserves the original return policy and buffer frees.
* Read-only checksum sampling before NAPT and before SDIO on first/every 32nd
  contiguous, unfragmented STA/AP IPv4 packet. No repair by this observer.
* A bounded path soak with incremental private artifacts, failure snapshots,
  load backoff, reboot/link events and no automatic resets/settings changes.

Usage and limits: [local diagnostics](../docs/p4-local-paths.md).

## Local comparisons

All downloads request 8388608 B. Incomplete bodies are failures, not accepted
throughput values. Uploads send 1000000 B; only a complete board receipt counts.
Controls were sequential; reboot and changing radio conditions remain confounders.

| Variant | Local STA upload | Local STA download | USB controls |
|---|---|---|---|
| Initial APSTA, AX allowed, HS | Both uploads failed; one Mac send queued all 1 MB without a receipt | Both incomplete | Upload 0.142 s; download 1.723 s |
| STA only, same AX/HT20 | Receipts in 8.719 / 6.734 s (~0.92 / 1.19 Mbit/s including request/response) | 2994176 / 1855488 B, both incomplete | Upload 0.155 s; download 1.742 s |
| APSTA b/g/n HT20, AX not requested | Both failed, partial Mac sends | 348248 / 55784 B, both incomplete | Upload 0.146 s; download 1.756 s |
| APSTA, RX AMPDU init override off | Both failed | 196608 / 835584 B, both incomplete | Upload 0.148 s; download 1.685 s |
| Restored normal APSTA + RX/checksum counters | Both failed | Incomplete, including 38008 B / 35 s | Upload 0.353 s; download 1.704 s |
| USB Full-Speed on existing UTMI PHY | Both failed | 76144 / 309872 B, both incomplete | Upload 1.168 s; download 9.235 s |

None of STA-only, removing AX or disabling RX aggregation restored the earlier
35–40 Mbit/s. RX-aggregation override is a requested Wi-Fi init parameter, not
a readback of C6's live aggregation. Normal settings are restored after controls.

During the RX-off control, all 2149 observed STA wlanif handoffs queued to lwIP:
zero down/allocation/input-rejected events. The restored baseline also had zero
observed handoff failures and no bad checksums in its initial sampled input.
These close host observability gaps; they do not prove loss-free RF delivery.

## UDP test limitation on this Mac

Read-only checks found macOS Application Firewall enabled in **block all incoming**
mode. A fresh UDP echo listener received nothing. Those trials are invalid as
radio loss measurements. No firewall setting was changed.

An outbound initiation plus continued small control packets allowed some data:
server receive and returned counts generally matched at low/moderate offered
rates, but no clean low-rate control was established. For example, 250 kbit/s
saw only 8/32 and a 2.4 s maximum observed RTT; this still has firewall/test-flow
uncertainty. At high offered rates, host staging full/expiry also occurred and
is recorded separately. These figures do **not** establish a loss-free rate or
prove a C6 PHY fault. The reusable endpoint remains useful on a validated peer.

## USB speed control

A temporary DWC2 control forces Full-Speed on the existing HS UTMI PHY, retaining
normal descriptors and cabling. Mac IORegistry confirmed Device Speed=1, versus
2 for the HS baseline. STA transfers still failed. Normal HS was restored and
read back as Device Speed=2. This control did not restore STA throughput and
does not establish or exclude RF interference from the physical USB connection.

## Three-hour observation

Normal APSTA/AMPDU/HS was restored before the run (`2da8985-dirty`). There were
2462 status samples and 221 transfer attempts. Failure status/logs were saved
before any later commanded reset; the runner never resets the board.

| Check | Result |
|---|---|
| Local USB upload, 1 MB with board receipt | 32/32 complete; median 59.21 Mbit/s |
| Local USB download, 8 MiB | 32/32 complete; median 40.10 Mbit/s |
| Local STA upload | 0/156 complete; timeout |
| Local STA download | 0/1 complete; 110592 B before timeout |
| Synthetic AP→NAPT→STA DNS UDP | 156/156 pass; median 66.5 ms, max 3440 ms |
| Synthetic AP TCP SYN | 154/156 pass; median 196 ms, max 3516 ms |
| API | Two timeouts, subsequent requests recovered; median 171 ms, max 14.44 s |
| STA link / boot | No sampled disconnection or reboot during these three hours |

The runner backs off after repeated STA failures to one upload followed by at
least 60 seconds idle. The STA directions are therefore not balanced throughput
samples. No spontaneous bulk-STA recovery was observed. There was no real AP RF
client during the soak; synthetic forwarding success is not AP radio acceptance.

All 72873 observed STA wlanif frames queued to lwIP: zero interface-down,
allocation or input-rejection events. Host SDIO calls and Hosted RX allocation/
stream drops recorded no failures. RX checksums: STA 1500 and AP 16 checked;
TX checksums: STA 494 and AP 18 checked; no sampled failures. Unsampled packets,
C6 firmware queues and RF retries remain outside this observation.

Temperature max 39.1°C. CPU0 median/p95 1.21/5.54%, CPU1 0.06/3.76%; brief peaks
99.82/81.78% occurred around USB downloads, not idle Wi-Fi saturation.
Recovery-idle internal-free medians by successive 30-minute windows were
84059, 82391, 82391, 82391, 80723, 80723 B. First/last 15-minute medians were
85727/80723 B; largest internal and DMA blocks stayed 31744/28672 B. PSRAM free
median stayed 31547040 B. Internal/DMA overlap. This is not proof of a leak or
absence of one; stalled/closing TCP allocations confound the heap samples.

## Confirmed crash after the observation window

The morning status reported boot 1113 with reset reason PANIC, whereas the
three-hour window stayed at boot 1112. The preserved core was decoded with the
exact installed ELF before reflashing. It shows a null response dereference:

```
rpc_wifi_get_ps → esp_wifi_remote_get_ps → esp_wifi_get_ps
  → meshvpn_wifi_radio_sample → wifi_profiles manager
```

ESP-Hosted 1.4.7 copied `resp->u.wifi_ps.ps_mode` without checking the response.
The build-copy patch now copies only on a non-null successful reply, preserves
caller output on failure, and retains the original response callback/cleanup.
The other radio-sample getters were inspected for response guards. A sanitizer
test exercises 100 success/failure/null-response/recovery cycles and null output.
This fixes the demonstrated crash path; it does not explain the RF slowdown.
The core read and subsequent firmware flash are commanded resets outside the
soak, not hidden recovery within its results.

Bound P4 was automatically flashed with `fe89fe7-dirty`, without buttons. A
five-minute follow-up (`p4-paths-w0q3tai2/`, 08:22–08:27 MSK) completed with
warnings: both USB controls and all four synthetic AP probe pairs passed;
five STA transfers failed/incomplete as before. There were zero API errors,
sampled link outages or boot changes (boot 1115). This is a short hardware smoke
check, not multi-hour acceptance of the crash fix or restored Wi-Fi throughput.

## Remaining work

Investigate actual C6 PHY rate/retries, firmware backpressure and the peer path
under a validated test setup. An unmodified old P4 image is also slow in this
state; none of the above controls isolates a production regression. Do not
increase buffers, claim an AP optimization, or replace C6 firmware based on these
results alone. C6, router, Mac Wi-Fi association and firewall remain unchanged.

Offline inspection of the preserved original C6 application identifies
`network_adapter`, version `release/ng-v1.0.2-330-g83efce6`, compiled October 18,
2024 with IDF `v5.4-dev-3602-ga97a7b0962`. This is backup image metadata, not a
successful live version RPC or evidence of a negotiated Wi-Fi 6 link. The tag
name alone does not identify the transport protocol.

## Validation and artifacts

Host sanitizer tests cover actual probe/echo/checksum code, pacing, ranges,
loss/duplicate/corruption accounting, pass-through, late replies, policy guards
and cleanup; IDF RX tests cover both copy modes and both return-code policies
with exactly-once frees. Runner tests cover privacy, private modes, deadlines,
failed bodies/probes, reboot recording and refusing wrong-board/enabled-VPN load.
P4 and XIAO compatibility builds and full host sanitizer checks passed. XIAO was
not flashed. The crash fix adds a separate passing response-timeout regression.

Seeded mutation harnesses compiled the production AP probe/echo parsers with
ASan/UBSan and mocked network boundaries: 192500000 probe cases and 294400000
echo cases, 300 seconds each, no findings. These were deterministic mutation
runs, not coverage-guided libFuzzer or hardware fuzzing.

Private artifact root: `device/perf-results/p4-night-ewzcfb74/`.
It includes baseline/variant binaries and source manifests, before/after status,
local transfer results, raw logs, echo trials, `night-analysis.json`, the completed
`p4-paths-z_o8stu7/` soak, `morning-coredump.bin` and exact image/ELF bundles.
Firmware, raw network metadata and credentials are not committed.
