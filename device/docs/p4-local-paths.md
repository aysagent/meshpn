# P4 local path diagnostics

These tools do not switch Mac Wi-Fi, reset the board, modify VPN/network
settings, or flash C6. Use the board's USB admin address while the Mac stays
on its existing router network. Close the admin page during measurements:
the firmware has one HTTP worker and one admin session.

## Bounded observation and load

```
python3 device/scripts/perf-p4-paths.py --minutes 180
```

Default USB admin IP is 192.168.10.1. `--admin-ip`, `--out`, and `--cycle-gap`
can override it, the parent artifact directory, and the normal recovery gap.
`MESHPN_ADMIN_PASSWORD` supplies the admin password (default `admin`).
Duration accepts 0.1–240 minutes. Each request has a timeout; local transfers
have a 35 s client budget, plus a blocking socket operation's timeout. The
firmware upload/download generators have a separate 30 s budget between calls
and a 3 s socket timeout. A deadline-limited body is not a completed transfer.

The runner requires a Waveshare P4 and VPN disabled. It performs a small
synthetic AP NAT DNS/TCP check, local STA upload/download, periodic USB controls,
and recovery snapshots. Repeated failed STA transfers back off to a single
upload per cycle and at least 60 s idle observation. No reset is attempted.
Failures preserve status and, when available, board logs before any recovery.
SIGINT/SIGTERM save partial results. A detected reboot is recorded, not hidden.

Every run creates a new 0700 directory under `device/perf-results`, with 0600
`status.ndjson`, `measurements.ndjson`, `events.ndjson`, `result.json`, snapshots
and failure logs. Status uses an allowlist excluding passwords, session tokens
and VPN keys. Throughput is reported only for complete downloads or uploads
with a board receipt confirming every byte. Exit status 2 means the requested
observation finished with failures/warnings; 1 means failed/interrupted.

This is a USB/STA test plus **synthetic** AP forwarding, not an AP radio speed
benchmark. A phone/other AP client is still needed to exercise that final leg.

## Firmware endpoints

All endpoints require the existing admin session. Local upload/download also
require the request's local socket address to be the USB, AP or STA address,
and the peer to be in that interface's subnet.

* `POST /api/diag/link-download`: empty body, 8 MiB stream. Optional
  `?nodelay=0|1` selects TCP_NODELAY for this connection (default 1).
* `POST /api/diag/link-upload`: Content-Length 1..8388608. Discards input in
  fixed 1024 B blocks, returns `link`, confirmed `bytes`, and `receive_us`.
* `POST /api/diag/ap-forward`: empty body; the synthetic .254 AP client tests
  DNS UDP and TCP SYN through production NAPT/STA. Reply captured before AP ARP.
* `POST /api/diag/ap-echo`: P4 only, small JSON body, for a local UDP echo
  listener on the **same STA subnet**:

  ```json
  {"target":"192.168.1.4","port":55000,"packets":512,"payload":1200,"rate_kbps":5000,"source_port":55000}
  ```

Echo limits: 1..4096 packets, 32..1200 payload bytes, 64..30000 kbit/s of
requested IP packet traffic, and at most 10 s of requested send duration.
It injects at most eight packets per TCP/IP callback, then yields. Drain grace
is 2 s; total budget is 12 s. Allocations are bounded and use PSRAM. Existing
ARP occupancy of synthetic .254, enabled VPN, invalid interface state, and
foreign/broadcast/multicast/own STA targets reject the test. Source port is
optional; by default it is random. `mapped_source_port` shows actual NAPT port.

The UDP server must echo payload unchanged; packets contain `MPNE`, a random
32-bit nonce and a 32-bit sequence followed by zeros. Statistics distinguish
injection, acceptance into STA SDIO, distinct returned packets, duplicates,
checksum failures and RTT. Checksum/tuple validation prevents consuming real
client traffic. Late replies to the last diagnostic tuple are consumed for
10 s without retaining payload/timing allocations.

Validate the test server/firewall on a low-rate control **before** calling
missing replies radio loss. macOS "block all incoming" blocks a fresh UDP
listener. An outbound initiation alone did not establish a clean control on
our Mac; these trials are diagnostic, not a loss-free capacity measurement.
Do not disable the firewall automatically. Compare listener receive counts
with returned counts, and report host staging losses separately.

Radio diagnostics now include cached `wifi.radio.max_tx_power_dbm` and its
error. This is a read of the configured limit, not measured RF power or PHY
rate. Unsupported getter failures are latched; HTTP readers never issue RPCs.

The pinned Hosted power-save getter is patched in the generated build copy to
handle missing/failed RPC responses before copying output. This prevents the
`wifi_profiles` null-response panic captured after the October 27 soak. The
original callback still reports/releases the response; no synthetic success is
returned. The response regression test includes repeated timeouts and recovery.
