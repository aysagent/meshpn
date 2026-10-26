# P4 AP+STA assessment without VPN — 26 October 2026

Status: **a shared-radio penalty is expected; the phone's upload stall remains
unexplained. No performance firmware change was applied.**

The phone previously achieved approximately 13.5/20 Mbit/s down/up through
MeshPN AP. During this check the user reported 8.5 Mbit/s down, upload falling
to 0.5 Mbit/s and stopping, followed by a hanging page reload. These are user
observations, not a completed repeatable benchmark. The observer started after
the test had begun; it did not capture the entire download phase. We did not
switch Mac Wi-Fi, change the router, reset or flash either chip, or enable VPN.

## Observed during the affected session

- Production build `d82220a-dirty`; 110 USB API samples, boot **1093** throughout.
  STA stayed connected with its DHCP address and reason 0. No observed reboot
  or STA disconnection. After the report, USB admin returned HTTP 200 in 18 ms
  and an en17-bound external HTTPS request returned HTTP 200 in 322 ms.
- One AP client, cached RSSI approximately -20 to -17 dBm at the start. The
  client's capability flags included 11n/11ax; these **do not establish the
  negotiated mode or actual PHY rate**. An AP-client disconnect event appeared
  later, without a reason in the retained log; it does not explain the initial
  stall. The retained log tail does not cover the complete load phase.
- Channel **4**, no secondary channel, interface width **20 MHz**, power save
  off. Uplink AP advertises 11n but not 11ax; actual negotiated mode is not
  available through the current factory C6 firmware.
- STA TX **3404 calls / 3375 accepted / 29 NETIF_TX_FAILED**, AP TX **2545
  accepted / 0 failures**, within the observation window. Acceptance is a host
  stack result, not confirmed RF delivery. In pinned ESP-Hosted 1.4.7 the STA
  transport explicitly returns `ESP_ERR_ESP_NETIF_TX_FAILED` while the C6's
  Wi-Fi flow-control flag is asserted; AP TX lacks this particular early gate.
  This is a concrete queue-pressure candidate, not proof that 29 rejects
  account for the whole stall or that all such errors have that origin.
- All four SDIO I/O failure counters remained unchanged at zero. Hosted RX
  allocation/format drop counters remained zero. No new DNS `forward_fail`
  appeared. This does not validate every DNS lookup or RF packet.
- Minimum sampled P4 free internal/DMA memory: **65123 / 24899 bytes**;
  classes overlap. P4 core maximum sampled load: **36.60% / 12.94%**. C6 CPU
  and RF retries are not measured. Historical DMA/internal minima were already
  very low before this test; do not attribute them to this particular stall.

## Why USB+STA should generally be faster

The C6 has one 2.4 GHz 1T1R radio, and AP/STA must share the home channel
([C6 datasheet](https://documentation.espressif.com/esp32-c6_dataSheet_en.pdf),
[IDF channel rules](https://docs.espressif.com/projects/esp-idf/en/v5.5.5/esp32c6/api-guides/wifi.html#home-channel)).
In this implementation, the two remote Wi-Fi netifs and NAT live on P4:

```text
USB+STA: router --radio--> C6 --SDIO--> P4 --USB HS--> client
AP+STA:  router --radio--> C6 --SDIO--> P4 NAT --SDIO--> C6 --radio--> phone
```

The AP relay consumes radio airtime twice and makes another SDIO pass. With
equal isolated link payload rates, an airtime-only estimate approaches half
the single-link rate. This is not a fixed multiplier for our WAN measurements:
PHY rates, acknowledgments, retries, contention and the test service differ.
The former 35–40 Mbit/s USB result cannot establish an exact AP ceiling.
The 0.5 Mbit/s upload collapse should not be accepted as that architectural
penalty without isolating its cause.

## Useful optimization targets

1. **Observe then smooth C6 backpressure.** Add transition/held-time counters
   for the host's throttle flag and bounded SDIO enqueue timing/depth. If
   sustained reject bursts align with AP upload collapse, evaluate a bounded
   PSRAM staging queue and paced retry outside the lwIP thread. Preserve packet
   ownership, ordering, expiry, VPN policy and reconnect cancellation. Do not
   block lwIP waiting for a C6 event, and do not disable flow control.
2. **Keep aggregation; avoid an indiscriminate DMA queue increase.** The host
   already requests 16 static RX, 64 dynamic RX/TX buffers and AMPDU TX/RX with
   BA windows 32. These match Espressif's current C6 tuning example, although
   factory firmware behavior and on-air aggregation remain unverified
   ([Hosted tuning](https://github.com/espressif/esp-hosted-mcu/blob/main/docs/design/performance.md)).
   The guide describes a newer Hosted revision, so its settings are a reference,
   not permission to upgrade dependencies blindly. SDIO host queues are 8/8;
   increasing DMA-backed queued payloads needs a measured memory budget.
3. **Measure AP independently before accepting a forwarding optimization.**
   Compare a local phone↔P4 transfer with a WAN transfer and a synchronized
   USB baseline against the same endpoint. Capture AP client RSSI, per-window
   rejects, RF rate/retries if safely obtainable, and both directions. A phone
   browser stall alone does not distinguish AP delivery, forwarding and the
   external speed-test service. Mac Wi-Fi need not be changed for these tests.

HT40/router changes and replacement C6 firmware were deliberately excluded.
Forwarding/NAT directly on C6 is a larger architectural option that could
remove the P4 SDIO round trip, but would need separate firmware/policy work
and still would not remove the two uses of radio airtime.

## Artifacts

Ignored private directory `perf-results/p4-apsta-analysis-32met484/` contains
`status.ndjson`, `summary.json`, `analysis-summary.json`, and the retained
`after-test-logs.txt`. Raw network/device metadata is not committed.
