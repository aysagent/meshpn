# P4 Wi-Fi recovered after extended power-off — 26 October 2026

Status: **connection working; original failure's root cause remains unknown**.
Follow-up performed in the evening after the failed overnight investigation.

## New evidence before any firmware change

The user reports disconnecting both USB cables and leaving P4 unpowered in a
cupboard for the day. They did not restart the Mac or change the router.
At the first observation, the same production build **d82220a-dirty** was already
online with STA DHCP address `192.168.1.11`, boot 1093. The overnight final
observations had boot 1092 and repeated reason 2 on that same firmware.

No P4/C6 image was flashed in this follow-up. The planned autonomous C6 AP image
was deferred because the failure had disappeared before it could be tested.
Instead, the actual production AP/STA path was tested in its working state.
This does not establish that an autonomous AP diagnostic has passed.

A first 90-second observer saw no disconnect. HTTP to `1.1.1.1` and HTTPS to
`example.com` succeeded from USB interface **en17**, address `192.168.10.2`.
The user then confirmed that the phone saw **MeshPN_9e07c1**, connected and
opened `http://192.168.11.1/login`. Status subsequently reported one AP client.
This confirms actual AP association and bidirectional local HTTP, rather than
only a successful AP-start API call. AP throughput and a DHCP renewal were not
separately measured.

## Bounded load and reconnect check

A 69.23-second check completed all **12 HTTPS transfers** through
USB en17 → P4 NAT → C6 STA → WAN: six downloads totalling **60,000,000 bytes**
and six uploads totalling **6,000,000 bytes**. Every transfer returned HTTP 200
and reported local socket address `192.168.10.2`. No unsolicited offline sample
was recorded during the load phase. Boot count stayed **1093** throughout.

| Direction | Transfers | Body bytes | Min Mbit/s | Median Mbit/s | Max Mbit/s |
|---|---:|---:|---:|---:|---:|
| down | 6 | 60000000 | 17.35 | 22.24 | 23.66 |
| up | 6 | 6000000 | 6.14 | 19.81 | 24.93 |

Rates above are body bytes divided by client-observed request duration, including
connection setup/response time. Upload rates are not iperf receiver statistics.
This is a short WAN check, not a board throughput ceiling or endurance test.
TLS terminated on the Mac and Cloudflare; **VPN was disabled**. DNS resolution
used the Mac's resolver, so this does not independently validate board DNS or
IPv6. The service endpoints are documented by
[Cloudflare's speedtest project](https://github.com/cloudflare/speedtest).

The first attempted load request received HTTP 403 from the public measurement
service; it did not cause a Wi-Fi disconnect. It is retained separately and is
not counted as a device transport failure. A run using standard documented
measurement sizes and normal request headers completed successfully. No cause
for the service's rejection is inferred from changing both parameters.

Three board-only pause/reselect cycles used the same saved profile. Reconnection
and an HTTPS request through en17 succeeded after **7.868 / 7.791 / 7.519 s**.
These deliberate STA disconnects are not counted as spontaneous failures.
Afterward automatic profile selection was restored, causing one additional
reconnect in **10.975 s**; it selected the original profile 1.
A final en17-bound HTTPS request returned HTTP 200.

The P4 temperature sensor reported **36.1–38.1 °C**
during the bounded run; the earlier idle sample was 31.1 °C. This is **not a C6
RF/PA temperature measurement**, and the run did not reproduce the overnight
thermal conditions. Minimum sampled internal/DMA free memory was
**65431 / 25215 bytes**; these classes overlap.
Remaining allocations after traffic do not by themselves prove a memory leak.

## Final state and limits

STA online, reason 0, same selected Wi-Fi profile, AP active with the phone still
associated, USB admin reachable; automatic selection restored, VPN disabled.
The observed channel was 4, no secondary channel, with 20 MHz interface width.
Mac Wi-Fi association, router settings and the other project's S3 were not
changed by these tests.

The observed sequence is extended power-off/pause → working connection on the
previous firmware. It does not distinguish cooling, board power/radio state,
time-dependent AP/RF state or another transient condition. The nightly RPC
fixes remain valid independent findings; recovery is **not claimed as proof**
that they or a new firmware change fixed this specific failure.

If the fault returns, capture the still-powered failing state before a reset
and compare it with this working baseline. Re-running a standalone C6 AP test
while the fault is present would then have more diagnostic value. No permanent
hardware fault or permanent software repair has been established.

## Artifacts

Ignored private directory:
`perf-results/p4-warm-link-2026-10-26-pwpviqeh/`.

- `initial.json`, `status.ndjson`, `final.json`, `summary.json`;
- `transfers.json`, `reconnects.json`, `review-summary.json`;
- `auto-profile-restored.json` includes the final automatic-selection check.

The initial service-rejection attempt is in
`perf-results/p4-warm-link-2026-10-26-st8oa5z9/`.
Earlier online baseline observations are in the overnight artifact directory as
`ap-followup-online-{status.ndjson,logs.txt,http.json}`. Raw status includes
user/device network metadata and must not be committed wholesale.
