# P4: evening recovery and bounded observation — 27 October 2026

The production path recovered before installing another firmware. This is a
state change to investigate, not a confirmed fix for the earlier STA/AP stalls.
The user confirmed both complete power removal and a changed USB connection
between morning and evening. Those changes were not isolated from each other.

## Conditions and method

P4 `E8F60AE395D0` still ran the preserved `2af50a4-dirty` production image with
factory C6. The two observation segments both recorded boot 1123, STA online,
AP active and VPN disabled. Earlier evening preflight recorded boot 1122;
the observation results below apply to boot 1123. There was no flash or reset
during either segment. Mac Wi-Fi association, router and firewall were unchanged.
No XIAO was programmed.

The initial incremental-reader control completed an 8 MiB USB download at
39.35 Mbit/s, two STA downloads at 13.35 / 14.24 Mbit/s, and a 1000000-byte STA
upload with a complete receipt at 19.33 Mbit/s. These are local HTTP results,
including connection/request/response time, not Internet or AP radio capacity.

The requested 30 minutes of observation were split into two segments. The first
ran 497.411 seconds and was deliberately interrupted to add per-transfer TCP
snapshot collection to the host runner. The second used the remaining
21.709812 minutes. The gap was approximately 11 seconds, with no board reset or
network-setting change; this is not one uninterrupted 30-minute run.

Each normal cycle uploads 1000000 bytes to STA, downloads 8 MiB from STA, and
tests a synthetic AP client through NAPT/STA using DNS and a TCP SYN. Periodic
USB uploads/downloads are controls. The AP probe intercepts its return before
AP radio delivery: it is not a phone test, complete TCP session or RF benchmark.
Upload counts require the board's complete receipt; incomplete attempts do not
contribute a throughput value. The runner does not reset or recover the board.

The second segment requests `/api/diag/sta-tcp` through USB immediately after
each STA transfer. A tuple comparison binds each file to the client's actual
source port, source address and STA destination. The last 64 packet headers and
per-flow checksum totals are retained without HTTP headers or payload. Ring
overwrite counts remain explicit. Checked-good pre-SDIO packets do not prove
C6 driver acceptance or RF delivery.

## Observation results

| Local path / direction | Complete / attempted | Mbit/s min | median | max |
|---|---:|---:|---:|---:|
| usb / down | 13 / 13 | 38.35 | 38.94 | 39.65 |
| usb / up | 13 / 13 | 58.40 | 59.03 | 60.02 |
| sta / down | 59 / 59 | 2.43 | 12.06 | 14.32 |
| sta / up | 57 / 59 | 3.09 | 7.68 | 18.24 |

Across both segments: **142/144 transfers completed**. Synthetic AP DNS/TCP
probe pairs passed **59/59**. The 586 status samples recorded no API errors,
Wi-Fi-offline samples or boot changes. All 82 TCP snapshots matched their
transfer tuples and recorded no bad checksum among validated packets. Host SDIO
I/O errors, RX allocation/input drops and staging losses did not increase.

All 59 STA downloads completed, but one took 27.645 seconds; a sustained
morning-style failure was not reproduced, and variable delays remain. STA
upload statistics exclude the two incomplete attempts. Incomplete rows have
zero confirmed bytes because there is no board receipt; this does not mean
zero bytes travelled over the network.

Sampled RSSI ranged from -66 to -50 dBm (median -58); temperature was
37.1–39.1 °C. Sampled free internal memory stayed at 61919 bytes or more and
sampled free DMA at 22203 bytes or more. These are polled values, not guaranteed
in-transfer minima or proof of leak freedom. Boot-lifetime minimum_free values
predate this window and are not per-test minima.

## Interpretation and prepared controls

One upload in each observation segment timed out without a complete receipt.
The second segment's transfer 81 now has a matching TCP trace: 572 incoming
packets / 773178 payload bytes including repeats, and 332 outgoing ACK/control
packets with valid IP/TCP checksums. The retained tail shows advancing ACKs and
an open receive window, followed by the client's FIN at about 3.136 seconds.
The next download completed, albeit slowly, and subsequent uploads continued.
This is not evidence that the entire 1 MB body reached the application.

This exposed a host-runner defect: Python `socket.sendall()` applies its timeout
to the whole buffer, even while sending is making progress. The runner passed
the entire 1 MB body with a 3-second socket timeout despite a 35-second transfer
budget. It now streams 16 KiB pieces, retains explicit Content-Length and checks
the total deadline between pieces. Ten host tests pass, including progressing
uploads longer than 3 seconds and deadline cancellation. Original failed rows
are retained; no success or throughput has been reconstructed from their traces.
This correction does not explain the morning's persistent slow downloads.

The corrected uploader then completed four hardware controls, all with matching
TCP tuples and full 1000000-byte receipts. Three unpaced controls took 1.677,
1.291 and 0.591 seconds. A deliberately paced control took **4.008 seconds**
(board receive time 3.875 seconds), confirming that the unchunked request works
and progressing uploads can exceed the old 3-second whole-buffer limit. Its
artificially limited rate is not a capacity result. Boot remained 1123.

The exact production image was slow in the morning after both normal and
calibration-record restoration, then completed bulk transfers in the evening.
A deterministic source-level regression is therefore not established; a
state-dependent software failure remains possible. Power, USB attachment and
unobserved radio conditions must not be collapsed into a single claimed cause.

A minimal P4 application using the stock pinned Hosted host data path was
built on IDF 5.5.5. It was **not flashed**, because production had recovered
before the comparison. It keeps factory C6 and is intended to remove MeshPN's
host TX wrappers during a future failing-state comparison. The saved production
image must be restored afterward. No additional C6 OTA write was performed
during this evening observation.

The generated SDIO ownership/queue and RX polling tests pass under ASan/UBSan:
copy ownership, free-on-rejection, bounded credit waits with the driver lock
released during sleep, notification timeout recovery and truncated-stream/OOM
handling. These tests do not certify the factory C6 Wi-Fi/RF path. The SDIO
counter code uses modulo arithmetic; completed 8 MiB flows traverse its 1 MiB
RX byte-counter range repeatedly. A simple first-counter-wrap explanation is
not supported by this healthy run.

An upstream [Espressif issue #184](https://github.com/espressif/esp-hosted-mcu/issues/184)
contains reports of similar bulk stalls with other P4/C6 firmware versions.
Different participants found different triggers, including radio conditions
and AX association. This is related evidence, not our root cause or a verified
patch. Our earlier b/g/n-only and buffer controls did not restore the failing
state. Do not change the router or replace the factory image on that evidence.

The HTTP generator sends chunk header/body/tail separately with NODELAY enabled.
Its throughput includes that packetization and all-packet diagnostic work.
Cached CPU samples after STA download show high CPU0 load, so these local rates
must not replace the earlier Internet forwarding figures as a hardware ceiling.
An additional per-socket NODELAY comparison is recorded separately below.

## HTTP packetization control

Four additional downloads used the existing endpoint query, in order 1/0/0/1.
Only that connection's TCP_NODELAY changed; the default and firmware stayed
unchanged. Each returned 8 MiB and reported the requested setting. All four
TCP tuples matched, boot remained 1123, and checked IP/TCP checksums were valid.

| TCP_NODELAY | Complete download seconds | Mbit/s | TX packets at host SDIO |
|---|---:|---:|---:|
| 1 | 5.760 | 11.65 | 12314 |
| 0 | 3.148 | 21.32 | 6366 |
| 0 | 3.378 | 19.87 | 6370 |
| 1 | 5.489 | 12.23 | 12304 |

Each trace counted the same 8405293 TCP payload bytes including HTTP framing.
The host sent roughly half as many packets with NODELAY off. Cached CPU0 load
samples after the four transfers were 91.96 / 56.62 / 58.08 / 86.28%; these are
individual 2-second samples, not whole-transfer CPU averages. This supports
packetization overhead in this local generator. It does not establish faster
AP transit traffic or solve the earlier failing state: the morning's NODELAY=0
control was also incomplete. The normal diagnostic default remains unchanged;
record this per-socket setting explicitly in future comparisons.

## Artifacts

Private artifact root: `device/perf-results/p4-minimal-hosted-ctlj7wtw/`.
It contains the incremental baseline, both observation directories,
`observation-segments.json`, `observation-summary.json`, source/config/image
bundles for the unflashed minimal control, preserved production images, TCP
snapshots and test logs. Raw status and firmware are not committed.
`upload-control/` retains the corrected-uploader validation and
`nodelay-control/` retains the separate four-flow packetization comparison.

The [morning A/B/A report](2026-10-27-p4-c6-aba.md) records the earlier failing
controls, C6 backup/restoration and the private-client timing caveat.
