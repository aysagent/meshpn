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

`peer`/`direct`: `--seconds 1..60`, `--rates 4 8 12 16 20 24 32`,
`--repeats 1..100`, `--gap 0..60`. TCP is unpaced. UDP is paced; compare achieved
sender and receiver counts, not only the requested rate. Throughput uses the
requested duration, including startup gaps, rather than an optimistic first/last
packet interval. The current downlink counter includes duplicates: it is not a
UDP unique-delivery/loss estimate. Client CPU/socket costs remain in the result.

The firmware `/api/diag/net-bench` worker is authenticated, P4-only, IPv4 RFC1918,
port ≥1024, ≤60 seconds plus a five-second connect/hello deadline, one job at a
time. It binds the STA interface and source. A VPN transition or explicit
`{"cancel":true}` stops it. It does not persist benchmark settings. The peer
accepts only allowlisted source IPs, bounded requests, and one active job.

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
