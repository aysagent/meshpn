# Two-P4 local test bench

`p4-dual-bench.py` uses USB for control. It never changes Mac Wi-Fi, host routes,
firewall, router settings or C6 firmware. Only the selected **client** board joins
the other board's AP. The other board keeps its home STA uplink. Both must start
online with VPN disabled. Wi-Fi selection is a one-shot preference, not a
persistent pin; restoration selects the originally connected profile.

```sh
# Stamp is DUT/AP; Waveshare is the Wi-Fi client. Start with a short control.
python3 device/scripts/p4-dual-bench.py --client waveshare --role link \
  --out device/perf-results/stamp-link-control --repeats 1
# Swap roles with --client stamp.
```

Roles and limits:

- `link`: Mac → client USB → client STA → DUT AP HTTP server, and response.
  One RF hop; includes client USB/NAPT and DUT's HTTP implementation.
- `wan`: same client path, forwarded through DUT STA to the existing public CDN
  download control. Includes ISP/CDN limits. This is not an isolated RF ceiling.
- `peer`: board-generated TCP/UDP → DUT AP → DUT STA → local Mac receiver.
  Requires `--host MAC_LAN_IPV4` and incoming connections permitted by the Mac
  firewall. The receiver checks the source is DUT's translated STA address.
- `direct`: board-generated TCP/UDP → home router → local Mac receiver, control
  for the peer path. Both radios remain on the home network.
- `radio`: board-generated TCP/UDP → second P4's AP listener. No server on the
  Mac, USB data forwarding, WAN or routing changes. Measures a local RF hop;
  the DUT's home STA stays connected, but test data does not traverse it.

```sh
python3 device/scripts/p4-dual-bench.py --client stamp --role radio \
  --protocols udp --rates 1 4 8 --seconds 5 --repeats 1 \
  --out device/perf-results/waveshare-radio-control
```

Both boards need the listener-capable firmware. `--protocols tcp udp` is the
default for `radio`; isolate UDP when TCP cannot finish. Results retain both
endpoints' intervals/counters and partial failures. The receiver is the client
for `down` and the AP board for `up`. A valid connection with zero received
bytes is not marked as a successful transfer.

`peer`/`direct`: `--seconds 1..60`, `--rates 4 8 12 16 20 24 32`,
`--repeats 1..100`, `--gap 0..60`. TCP is unpaced. UDP is paced; compare achieved
sender and receiver counts, not only the requested rate. Throughput uses the
requested duration, including startup gaps, rather than an optimistic first/last
packet interval. UDP receiver counters exclude duplicates in both directions;
`duplicates` and `reordered` are separate. `sequence_missing` counts gaps only
inside the observed sequence span, including a missing initial sequence zero.
It cannot detect an unobserved trailing receive blackout. Do not subtract total
sender/receiver counts as loss when their time windows differ. Older firmware
without `udp_sequence_available` has no unique downlink count. Client CPU/socket
costs remain in the result.

The firmware `/api/diag/net-bench` worker is authenticated, P4-only, IPv4 RFC1918,
port ≥1024, ≤60 seconds plus a five-second connect/hello deadline, one job at a
time. It binds the STA interface and source. A VPN transition or explicit
`{"cancel":true}` stops it. It does not persist benchmark settings. The peer
accepts only allowlisted source IPs, bounded requests, and one active job.

For a firmware listener, POST the same fields with `role:"server"`,
`interface:"ap"` (or `"sta"`), and `target` equal to the expected client's
on-link private IPv4. The response supplies a fresh `nonce`; pass it in the
client POST with the same protocol, direction, rate, seconds and port. The
listener binds only its selected interface/address, checks the peer IP and
exact 32-byte hello, and cannot redirect packets to another target. All ports
close on cancellation, VPN enable, error or expiry. `listening` means ready for
the initial hello; `connected` records that it matched. The orchestrator uses
port 18765, cancels owned sessions on both boards even if one API fails, and
retains cleanup errors. A crashed orchestrator leaves at most the bounded test
duration, not a permanently open listener.

For `--role link`, `--nodelay 0` allows TCP coalescing on the board's local
HTTP download socket; the default is `1`. This isolates overhead from many
small HTTP header/chunk writes. It changes neither Wi-Fi settings nor forwarded
client sockets. Each attempt records `server_tcp_nodelay`, partial received
bytes and a bounded AP TCP trace, including failed attempts before restoration.
The client now arms its existing STA trace ring for the same HTTP peer before
each link transfer. `client-trace-N-DIRECTION.json` and `ap-trace-N-DIRECTION.json`
can be matched by IP/ports and TCP sequence numbers. Their clocks are independent;
do not subtract absolute timestamps across boards. `local_port` is the NAT-side
client port in a client trace, matching `peer_port` on the AP server trace.

Authenticated empty `POST /api/diag/sta-tcp?target=IP` arms this client mode
for 120 seconds, only with VPN off and a private unicast peer on the connected
STA subnet. `target=0.0.0.0` cancels and clears the ring. It reuses the STA ring,
does not allocate packet buffers, and retains no payload. Expiry freezes the
trace until explicit cancellation/rearming. Restoration cancels it. Ordinary
GET diagnostics never enable tracing of forwarded traffic.

Profile changes have a private `restore.json` journal written **before** mutation.
Existing profiles/passwords are preserved. The temporary peer profile is removed
and the originally connected profile restored on normal completion, failure
or SIGTERM. After power/process loss, recover explicitly before another run:

```sh
python3 device/scripts/p4-dual-bench.py --restore device/perf-results/RUN/restore.json
```

Do not edit Wi-Fi profiles concurrently with this tool. A file lock prevents two
bench runs. API login sessions are shared within a run; external admin login may
invalidate them. The default development AP password is read from
`MESHPN_BENCH_AP_PASSWORD` or `meshpn-test`; it is never written to reports.

Artifacts are private files under `perf-results`, not committed or pasted into
agent context. Failed attempts remain failures even if restoration succeeds.

`wifi.hosted.dma_cache` exposes free DMA buffers retained by the SDIO pool
for reuse. Its `sta` and `ap` children report the separate transport pools;
do not interpret the parent as their total. `cached_bytes` in each pool is
the sum of requested allocation sizes, including
the pinned pool's alignment rounding, but excluding allocator overhead and
in-flight buffers. The reserved SDIO RX stream is separate. It is sampled
under the pool lock, separately from TX/RX counters; no allocation policy is
changed. A fall in heap free space followed by a rise in this cache is not
by itself a leak. Compare idle snapshots, not historical minimum-free alone.
