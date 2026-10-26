# P4 AP forwarding investigation — 27 October 2026

Status: **the phone failure is not yet explained or accepted as fixed**.
VPN remained off. Mac Wi-Fi, router settings and C6 firmware were not changed.
Only bound P4 `E8F60AE395D0` was flashed automatically; the other project's S3
was neither reset nor flashed.

## Failure and controls

The phone reported **2.18 Mbit/s** in the local 8 MiB AP download diagnostic,
then no internet through AP, including `http://1.1.1.1`. That excludes a
DNS-only explanation. At the same time, USB-bound requests returned 301 from
`http://1.1.1.1` in 115 ms and 200 from `https://ifconfig.me` in 500 ms.
Fifteen DNS queries through the USB gateway (five domains, A/AAAA/HTTPS) all
returned NOERROR; an external 1.1.1.1 DNS query also succeeded.
These are USB controls, not proof that the phone's DNS or AP path works.

Before reboot, AP had one client around -30 dBm and ingress counters advanced.
No host AP/STA staging losses, SDIO I/O errors or allocation drops were recorded.
STA briefly staged 218 frames during C6 throttle, peak occupancy 26, maximum
residence 82 ms; none expired. `sent` still means host acceptance, not RF
acknowledgement. Later the phone disconnected, so no real-client trace of the
original failure was available before the commanded reboot.

## New diagnosis without changing Mac Wi-Fi

Authenticated empty POST `/api/diag/ap-forward` runs two bounded tests with VPN
off: DNS/UDP to 1.1.1.1:53 and a TCP SYN to 1.1.1.1:80, from synthetic AP
address `192.168.11.254`. Packets enter actual AP `ip4_input`, NAPT and STA.
The response is captured at AP IPv4 output after reverse NAPT, before ARP/RF.
IP and transport checksums are verified. TCP SYN-ACKs receive a cleanup RST.
The temporary tuple is random; an existing ARP entry at .254 rejects the test.
Each case allows three 1.2 s waits. Real clients retain the normal output.
The test does **not** prove RF delivery to a phone or full TCP/TLS data transfer.
Synthetic input increments device-wide AP ingress/NAPT/TX counters too.

`net.ap_tcp_flows` retains eight handshake tuples with an explicit stage mask:

| Bit | Observed stage |
|---:|---|
| 1 | SYN at AP IPv4 input |
| 2 | Translated SYN accepted into STA SDIO |
| 4 | SYN-ACK/RST at STA IPv4 input |
| 8 | Reverse-translated response at AP IPv4 output |
| 16 | Response accepted into AP SDIO |

Stage 15 is expected for the synthetic probe: it consumes the response before
AP SDIO. Stage 31 still does not prove C6 transmitted/acknowledged it over RF.
No application payload or credentials are retained. These stages describe
DIRECT routing; a VPN uses another path.

An initial diagnostic build skipped attachment because default Wi-Fi netifs
initialize their output callback after LAN registration. This diagnostic bug
was corrected and covered by a delayed-initialization test. It is not claimed
to explain the original phone failure.

## Hardware results

Installed `c6e6e00-dirty` (the repository also had concurrent native work): STA
online at 192.168.1.11, AP 192.168.11.1, both LAN NAPT flags true, VPN off.
The first hardware probe passed UDP (1240 ms, one retry) and TCP SYN-ACK (17 ms)
with correct checksums. Five subsequent pairs all passed: UDP 8–154 ms;
TCP 33–339 ms. All TCP synthetic traces reached stage 15. This confirms the
software forwarding/reverse-NAPT path **after reboot**, not its state during
the earlier failure. Internal/DMA free memory was 92343/52111 B (overlapping
classes), web task stack minimum remaining 4140 B. No inference of a leak or
RF fault follows from these snapshots.

A per-socket `?nodelay=0|1` option was added to the local download diagnostic;
default is 1. It did not eliminate the slow STA path:

| Path / TCP_NODELAY | Result |
|---|---|
| USB / 1 | Complete 8388608 B in 1.730 s, 38.80 Mbit/s |
| STA / 1 | Incomplete 1376256 B in 30.54 s |
| STA / 0 | Incomplete 262144 B in 19.40 s |
| STA / 1 repeat | Incomplete 1441792 B in 30.91 s |

These failed streams are not throughput acceptance results. A separate 1 MB
WAN USB download (2.54 s) briefly overlapped the nodelay=0 window; that row is
not an isolated speed comparison. Both isolated nodelay=1 STA attempts also
failed. Disabling Nagle is therefore not a demonstrated Wi-Fi speed fix.

## Validation and next check

ASan/UBSan tests exercise actual probe/checksum code, synthetic-only
interception, normal client pass-through, delayed netif initialization, retry,
VPN/ARP/interface guards, semaphore/pbuf ownership, cleanup RST and tuple/stage
correlation. Full host checks and P4/XIAO builds pass; XIAO was build-only.

The next check is a real phone request with this trace installed, correlating
AP input, STA response and AP handoff. The phone was asked to retry numeric
HTTP and stay associated. Do not ask for another generic DNS log or call the
stall fixed because the board was restarted. If no real-client failure is
captured, that acceptance remains pending.

Private artifacts: `perf-results/p4-apsta-queues-b_jujsu5/`, including
`ap-forward-*.json`, `ap-forward-repeat.json`, `nodelay-comparison.json`,
`phone-dns-matrix.json`, previous app backup and logs. Full diagnostics and
firmware backups are ignored, not committed.
