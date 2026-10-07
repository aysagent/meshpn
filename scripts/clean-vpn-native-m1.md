# Native M1 — implementation notes (feature branch)

Historical M1 checkpoint. The 2026-10-07 continuation now includes a bounded
multi-peer native exit; current scope and remaining native migration work are
tracked in [native transition](clean-vpn-native-transition.md). Single-peer and
fixed-address descriptions below describe the original M1, not current capabilities.

Branch: `feat/clean-vpn-native-data-plane`, based on roadmap commit `9e64cfc`.
M1 laboratory acceptance complete; not a production replacement. No deployment or default change.

## Checkpoint: 2026-10-05

Implemented native client/exit and native DNS; the final combined VM acceptance
passed all 11 gates, including both mixed-version packet directions, the resource
comparison, independent protection after SIGKILL and process cleanup. M1 stops
here for review; M2, merge and deployment are not started. The `main`
roadmap commit was pushed before creating the feature branch. Existing production
Node path, autostart and installers are unchanged. Explicit experimental launcher:
`node scripts/clean-vpn-native.mjs --config /absolute/config.json` (requires a
provisioned TUN and separately managed protection; not a setup command).
Optional `--usb-profile` uses the existing owned route/DNS journals and uplink
watcher for the fixed reviewed Radxa topology. It requires preinstalled cvks4,
USB addressing and SNAT/MSS; it does not install or remove those protections.

For the installed Radxa use the [short automated trial](clean-vpn-native-radxa-trial.md):
`bash scripts/build-clean-vpn-native.sh` then
`node scripts/clean-vpn-native-trial.mjs --apply` from USB rescue SSH :2222.
It builds dependencies separately without a worktree, derives credentials from
the running service, runs old/native/old smoke checks and audits rollback.
Physical Radxa/ARM64 host smoke on `0325b9c` passed on 2026-10-05: old/native/
restored DNS 4/4, HTTPS 2/2, 1 MiB download and expected exit IP; rollback and
guard verified. Legacy readiness took 16.65 seconds. Native reported generic
session closures/receive errors, so this is not yet native USB, long-run, leak,
crash or performance acceptance. The enabled legacy service was restored.

Physical follow-up on `7e9c402` (2026-10-05, 120-second hold): old/native/restored
smokes and rollback passed. The hold checked process liveness only. It exposed
repeated authenticated `h2_peer_end_stream` about five seconds after readiness
without packet activity, plus a `peer_address` rejection. The old exit has an
application-idle close path; its actual deployed timeout is not independently
verified here. A valid IPv4 packet failed the fixed peer-address check; its
actual addresses were not in that report and its origin remains unresolved.

Follow-up implementation (2026-10-06, not yet retested on Radxa):

- Authenticated normal H2 closure now leaves the native client in `idle_wait`.
  It reconnects on the first valid TUN packet (retained until authenticated
  readiness), or native DNS demand. Initial connection and failure retries
  remain eager. Stop/uplink control remains responsive while idle.
- The DNS relay signals demand and waits at most three seconds for readiness
  before its normal bounded fixed-upstream logic. Unavailable/non-idle DNS
  still returns SERVFAIL; there is no direct resolver fallback.
- Peer isolation is unchanged. At most 16 rejected-address metadata records
  (source, destination, IP protocol, role; no payload or ports) are emitted.
  Full state counters survive truncation of the last-48-event history.
- A requested hold now probes actual TUN HTTPS with ten-second quiet gaps,
  checks exit IP, records timings/failures, and fails for peer-address rejection.
  Both failure and success still run the same audited rollback. No claim of
  USB, leak, long-lived-flow or performance acceptance is added.

Local follow-up validation: 234 regression tests passed without skips. After
the final wake-packet ordering correction, all 12 session cases passed again,
including repeated idle cycles, a two-packet burst with exact order, control
uplink changes, invalid IPv6 not waking the client, and stop while idle.
The final normal 180-second native/native and native/legacy runs verified
964,704 / 1,229,712 directional packets, zero drops or unexpected reconnects,
and stable FDs across 36 samples each. Peak engine RSS: 6,104 / 6,216 KiB.
The final ASan/UBSan selection passed 22 tests including both 180-second runs:
357,944 / 602,776 packets, zero drops/reconnects, peak RSS 50,016 / 50,196 KiB
with the 16 MiB ASan quarantine. Dependencies are not sanitizer-instrumented.
CTest protocol/DNS-wire passed 2/2 in each build. These are bounded local
fixture observations, not internet-speed or physical Radxa acceptance.

Physical USB follow-up `684d2e6`, 2026-10-06 (`run-IV703a`): baseline/native/
blocked/recovered/restored peer probes all passed, as did all host smokes and
audited legacy rollback. Actual networkctl wlan0 down was verified; first HTTPS
in the Mac recovered phase took 2279 ms (not DHCP-to-VPN latency). Overall trial
failed on six `peer_address` session errors before stop. Their metadata identifies
IP protocol 2 traffic from `10.99.0.1` to `224.0.0.22`, consistent with IGMPv3
reports ([RFC 3376, section 4.2.14](https://www.rfc-editor.org/rfc/inline-errata/rfc3376.html)).
This identifies the packets in this run, not necessarily every older rejection.

The client now discards validated inbound IPv4 multicast (`224.0.0.0/4`) and
counts it as dropped without terminating the authenticated session. Framing,
IPv4 size/header/checksum validation precede this decision. No multicast packet
is injected into TUN; wrong unicast destinations and exit-side spoofed sources
still fail the session. Trial acceptance still rejects any `peer_address` event.
This engine change requires rebuilding on Radxa and repeating the physical trial.
Local validation of the multicast fix: 270 regression tests passed without skips;
21 session/interop/data-plane tests passed with ASan/UBSan, and CTest passed 2/2
in each build. The authenticated legacy fixture sent 2054 multicast frames,
including IGMP with IPv4 options, multicast range endpoints and UDP multicast,
split framing and a burst exceeding the initial H2 flow-control window. All were
counted as dropped, none reached the packet device, and two following unicast
packets arrived in order on the same connection. Corrupt multicast IPv4 checksum,
wrong client unicast destination and spoofed multicast source at the exit remain
session failures. No physical rerun of this rebuilt engine is claimed yet.

Verified on x86_64 Linux:

- Native client↔exit: 2026 packets total including 28..65535-byte test
  packets across the full run's scenarios, control
  reconnect, PING timeout and subsequent recovery, five further reconnects with
  stable descriptor counts, normal stop. The sustained
  loop itself is 1000 packets per direction (2000 total).
- Certificate hostname, wrong CA and wrong PSK are rejected; neither endpoint
  reports authenticated readiness and no packet is injected at the test exit.
- ASan/UBSan on engine and C++ protocol/integration driver: passed, no reported
  memory/undefined-behaviour errors. BoringSSL/nghttp2 dependencies were **not**
  sanitizer-instrumented in this build.
- Native DNS UDP/TCP relay: randomized upstream IDs, response identity/envelope
  checks, fallback to the second in-tunnel resolver, SERVFAIL without readiness,
  EDNS BADVERS/truncation, 100 sequential queries, 24 slow TCP clients against
  the 16-job limit, prompt thread cancellation and exact FD cleanup. The C++
  fixture runs in an isolated unprivileged network namespace, also under ASan/UBSan.
- Backpressure fixture: receiver deliberately stops draining, native queues stay
  bounded, status/stop remain responsive, RSS is checked below 128 MiB/process.
- Actual old CLI TLS/H2/auth functions, extracted by the existing reference
  fixture: native client→old exit and old client→native exit handshakes passed.
  The reference also sends an invalid frame length after authentication; the
  native exit rejects it before packet injection. Missing auth and excessive
  H2 headers are also rejected without authenticated readiness or injection.
  Full mixed-version TUN traffic passed in both directions in the final VM.
- NIC-less VM, real kernel TUN: UDP payloads 28/1300/2000/8192/60000 bytes,
  fragmentation, DNS UDP request/response, TCP 1 MiB roundtrip, reconnect, engine
  SIGKILL with failed subsequent application probe; Node control-only launcher
  repeats the same successful packet tests. No host network/shared filesystem.

Deterministic packet count before the additional backpressure flood: each direction sends 6 size probes +
1000 loop packets + 1 uplink-reconnect probe + 1 blackhole-recovery probe +
5 repeated-reconnect probes = 1013; 2026 is the total for both directions.

Final evidence: [machine-readable VM report](fixtures/clean-vpn-native-m1-report.json).
Full local artifacts: `/var/tmp/meshpn-native-lab-SAFXRo/report.json`, `serial.log`
and `initrd.gz`. The report contains engine/helper/kernel/fixture hashes and all
six benchmark rounds. No production credentials are included in the report.
Engine SHA256: `1dac0da172c5087188431ffceac36ad0a5572bec40d79c020be3b31ac3af7252`.

Earlier failed runs are not acceptance evidence. The final harness waits for
authenticated old-endpoint readiness instead of a fixed startup sleep, and
releases the disconnected persistent client TUN before running the legacy CLI
(which allocates a free name rather than attaching it). This keeps both clients
on `tun0`, under the same unchanged guard/SNAT/MSS policy. It recreates the
provisioned TUN before returning to native. No guard exemption was added to make
compatibility pass.

## Ownership and protocol

| Resource | Current Node path | Native M1 owner |
|---|---|---|
| TUN read/write, packet buffers, framing | addon → JS bridge | C++ engine only |
| TCP, TLS, HTTP/2 and HPACK | helper/Node socket + Node H2 | BoringSSL + nghttp2 inside C++ |
| PSK/exporter auth, PING/ACK health, reconnect | `clean-vpn.js` | C++ session |
| Queues/backpressure, packet validation | JS/native split | bounded C++ queues |
| UI, config and profile repository | Node | Node |
| System routes/DNS/guard and uplink notifications | Node/system services | control coordinator; not packet IPC |
| DNS packet handling | Node forwarder in current mode | C++ bounded UDP/TCP relay inside engine |

Initial wire profile: TLS 1.3, h2 only; `POST /clean-vpn`, `https` scheme,
exporter label `EXPORTER-clean-vpn-bind` (32 bytes), HMAC-SHA256 of
`clean-vpn-tls-v2:` + **raw exporter bytes** + `:` + 15-minute window,
first 16 bytes in lowercase hex. Exit accepts current ±1 windows, never v1.
Response must be 200/application/octet-stream. Body is uint32 BE length + IP.
IPv4 only; 20..65535 bytes, valid IPv4 header/length/checksum. No IPv6 capability
advertised. Fixed authenticated peer address 10.99.0.2; enforce source on exit,
destination on client before writing TUN. Fragmented IPv4 remains packet data.

This is deliberately not a new crypto protocol. H1, browser-profile fidelity,
Date clock correction, transparent relay and multi-peer exit are not implemented
by this first engine. Unsupported features cannot silently fall back to Node.

## Process/control boundary

`clean-vpn-engine --config /absolute/file.json` reads a bounded local configuration.
PSK is read from a 32-byte owner-only file (no key in argv or status). Client
requires numeric endpoint IPv4, CA and verified server name; SNI is separate.
Exit loads its own cert/key. Caller provisions the persistent TUN before startup;
engine attaches and does not execute iptables/ip/sysctl or change host routing.

stdin: bounded newline JSON commands `status`, `stop`, `uplink` with boolean
`ready`. stdout: versioned metadata states, packet counters and bounded
rejected-address diagnostics, **no packet bytes, raw headers, frames or TLS
exporter**. EOF/malformed control stops the engine.
Backed-up status output also stops it instead of unbounded allocation.
`NativeEngineController` is an internal Node supervisor, not an HTTP API, and
has no sendPacket/data-plane interface. Guard must outlive both processes.

C++ handles connect deadline (3 s), total initial TLS/auth deadline (10 s),
PING interval/deadline (2/5 s), bounded queues (1 MiB each), bounded work per tick
and cancellation. Session queues are discarded on reconnect; preservation of
existing application TCP sessions is not promised. Exit currently accepts one
connection at a time: this is **not a hardened public listener**.

`clean-vpn-engine --capabilities` returns the explicit supported mode and does
not open TUN/network sockets. DNS is enabled only with client config `dns: true`:
stub `10.99.0.2:1053`, upstream `1.1.1.1` then `8.8.8.8`, each bound to the TUN
device and source address, 1.2 s per upstream, at most 16 jobs, 10 s TCP lifetime.
There is no system/LAN/direct resolver fallback. UDP truncation invites the
requester's TCP retry; unsupported query envelopes are refused. This is envelope
validation, not DNSSEC validation or a general recursive resolver.

Minimal configurations (operator-owned files; PSK is exactly 32 raw bytes,
mode 0600, owned by the engine UID):

```json
{"version":1,"role":"client","address":"154.62.226.216","port":443,"tun":"tun0","secret_path":"/secure/psk","server_name":"clean-vpn","sni":"www.trustpilot.com","ca":"/secure/ca.pem","dns":true}
```

```json
{"version":1,"role":"exit","address":"0.0.0.0","port":443,"tun":"tun0","secret_path":"/secure/psk","cert":"/secure/cert.pem","key":"/secure/key.pem"}
```

These are schema examples, **not deployment commands**. Client TUN address is
10.99.0.2, exit peer 10.99.0.1; provision MTU/routes/exit forwarding separately.
Never run the native and old client concurrently on the same TUN.

Managed USB lifecycle: preflight guard → start native TUN/listeners → install
owned routes/DNS guard → authenticate → activate DNS interception. Graceful stop
restores owned rules/routes while native still holds TUN, then stops the child.
The independent cvks4 guard stays. Crash/fault retains ownership journals and
protection for explicit review/recovery, not an automatic direct fallback.
The inherited journal implementation uses synchronous bounded system commands;
profile setup/cleanup is slower than native session reconnect (especially under
TCG). This is not a new asynchronous UI/control-service implementation.

## Build and tests

Existing pinned patched BoringSSL source and JSON headers are reused from the
helper dependency directory, but compiled in a separate engine build tree.
For a fresh checkout, first build the existing helper as described in
[boring-tls-plan.md](boring-tls-plan.md) (`npm run build:boring-tls-helper`).
nghttp2 is fetched at commit `534b74b72524e962c18c7146470914632ca7eb2d` (v1.68.0).
Its [I/O-independent API](https://nghttp2.org/documentation/programmers-guide.html)
lets C++ own TLS/socket I/O; no Node HTTP/2 bridge is involved.

```bash
cmake -S native/clean_vpn -B native/clean_vpn/build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build native/clean_vpn/build --target clean-vpn-engine clean-vpn-engine-fixture protocol-test dns-wire-test dns-relay-test integration-test socket-test -j 4
ctest --test-dir native/clean_vpn/build --output-on-failure
node --test scripts/test-native-data-plane.mjs scripts/test-native-dns.mjs scripts/test-native-engine-controller.mjs scripts/test-native-wire-interop.mjs scripts/test-native-tls-identity.mjs
node --test scripts/test-native-session-events.mjs
CVPN_SOAK_SECONDS=180 node --test scripts/test-native-soak.mjs
```

`clean-vpn-engine-fixture` is a **separate test binary** accepting an inherited
AF_UNIX datagram fd in place of TUN. Production binary rejects this mode.
The C++ integration driver creates, sends and verifies packets; Node only
provisions temporary test PKI/configuration and invokes the driver. This test
does not prove real kernel routing, NAT, DNS interception or kill-switch safety.

TLS identity regression tests reproduce the old CN-only `clean-vpn` certificate
against the real legacy TLS/H2 endpoint. Compatibility fallback is restricted to
that identity; DNS SAN overrides CN, other names require DNS SAN, and wrong CA,
wrong name, expired and future-dated certificates are rejected with fixed error
codes. This lab reproduction does not identify the certificate on a physical
exit that has not been inspected.

Session fault tests distinguish VPN frame length, IPv4 validation, peer address,
peer END_STREAM/GOAWAY/RST, TLS close-notify and local H2 protocol termination.
The first fixed callback error survives nghttp2's generic callback-failure
return; debug strings and packet bodies never enter the control protocol.
An invalid-size PING can cause nghttp2 to queue GOAWAY without its invalid-frame
callback. The engine now handles that local termination instead of reporting a
later PING timeout. No relaxing of packet validation or authentication is used.

The endurance test runs native-client/native-exit and native-client/legacy-H2
reference sessions concurrently (180 seconds each by default, configurable
10..600). C++ generates/checks 64/1400/8192/65535-byte packets; the reference
legacy stream only echoes opaque framed bytes. Any unexpected session event,
packet mismatch/drop, FD growth, RSS >=128 MiB or RSS growth >=32 MiB fails.
This is loopback fixture-fd evidence, **not real TUN/USB/routing or an Internet
benchmark**. The reference does not emulate the production exit's idle bridge.
For sanitizer endurance use `ASAN_OPTIONS=quarantine_size_mb=16` to bound the
intentional ASan quarantine separately from the engine's memory limits.

2026-10-06 session follow-up (local x86_64, no deployment): all 224 regression
tests passed with no skips, plus the two concurrent 180-second endurance cases.
Native/native verified 955,312 directional packets; native/legacy reference
verified 1,244,834. Both had zero drops/unexpected reconnects and stable engine
FD counts (36 resource samples each). Peak engine RSS was 6,020/6,092 KiB;
maximum growth from the first ready snapshot was 1,184/1,160 KiB. These are
bounded endurance observations, not a leak-freedom or throughput claim.
ASan/UBSan rerun passed all 21 selected session/data-plane/DNS/interop/endurance
tests without skips or reported sanitizer errors (`quarantine_size_mb=16`).
The two 180-second sanitizer sessions verified 355,948/606,378 directional
packets with zero drops/reconnects; peak engine RSS 49,556/49,504 KiB, maximum
growth 28,476/28,384 KiB. CTest protocol/DNS-wire passed 2/2 in both builds.
The subsequent physical trial distinguished normal H2 endings and a peer-address
rejection (see the follow-up above). Earlier generic events cannot be classified
retroactively. No production server policy or idle timer was changed here.

Sanitizers: configure a separate `build-asan` with `-DCVPN_SANITIZE=ON` and
`-DCMAKE_BUILD_TYPE=Debug`; build the same targets, run CTest there, then set
`CVPN_BUILD=native/clean_vpn/build-asan` for the Node test wrappers. Only engine
and protocol/DNS/integration targets are instrumented by that option.
The DNS fixture requires Linux user/network namespaces and iproute2; it never
changes host interfaces or firewall. BoringSSL/nghttp2 remain uninstrumented.

Real-TUN VM (requires an already verified host-boot fixture and QEMU tools):

```bash
node scripts/clean-vpn-native-lab.mjs /absolute/HOST_BOOT_BASE /absolute/QEMU_TOOLS_ROOT
```

`HOST_BOOT_BASE` is an artifact directory produced by
`clean-vpn-host-boot-lab.mjs`, containing a passed NIC-less `report.json`,
`guest/` and `guest-kernel`. QEMU tools are the extracted package root from the
existing [DNS VM lab setup](dns-vm-lab.md). The native runner validates the
base report/kernel hash and copies the image; it never boots against host paths.

The current VM runner uses the actual cvks4 rules, current DNS ownership planner,
SNAT/MSS rules and native control coordinator. Positive direct-route controls
precede protection. It exercises USB/host DNS, native relay fallback, private/IPv6
USB blocking, local uplink DNS capture, authenticated SSH on 2222, uplink-route
loss/repair, normal stop and client-engine SIGKILL, both mixed-version packet
directions, and a resource comparison. This is runtime policy acceptance, **not**
systemd installer/boot acceptance or physical Radxa testing. No external NIC,
host shared filesystem, production endpoint or user credential is used.

Benchmark: one TCG vCPU, 1536 MiB guest RAM, real kernel TUN MTU 1400, same USB
peer/origin/guard/SNAT/MSS. Three rounds per implementation, each 16 MiB in each
direction plus 100 small TCP echo RTTs. Numeric origins; legacy DNS disabled only
for this comparison. Observer samples root process trees every 100 ms: CPU ticks,
summed RSS (not PSS), FDs/processes; transient processes can be missed. Native
includes its Node control process and DNS threads; legacy includes Node and TLS
helper. Guest CPU/throughput/latency numbers under emulation do not predict Radxa
or VPS performance. Every byte is generated/verified by the C++ application
fixture; the Node observer reads only process metadata and fixture summaries.

Build types used for comparison: native `RelWithDebInfo` (no sanitizers), existing
TLS helper `Release`. BoringSSL source is the repository's patched pinned
`a7481f34712bc056a47ab91015536166b3a6cebb`; the engine links it statically along
with nghttp2. Binary hashes in the VM report identify the actual measured builds.

Final host-side checks (2026-10-05):

- CTest: protocol and DNS-wire tests, 2/2 passed in both normal and ASan builds.
- Normal Node harnesses listed above: 12/12 passed, no skips.
- The same data-plane, DNS and wire-interop harnesses with `CVPN_BUILD` pointing
  to the ASan/UBSan build: 7/7 passed, no skips. Controller-only JavaScript cases
  are covered by the normal run, not counted as sanitizer tests.
- Existing regressions: 156 passed across `test-vpn-host-routes.mjs`,
  `test-dns-tunnel-plan.mjs`, `test-usb-snat.mjs`, `test-dns-wire.mjs`,
  `test-usb-client-recovery.mjs` and `test-vpn-transport-recovery.mjs`.

## Resource comparison (2026-10-05)

Medians of three sequential rounds in the final VM scenario; these are **TCG
emulator measurements**, not claims about physical Radxa/VPS throughput.

| Measurement | Native | Existing Node/helper |
|---|---:|---:|
| 16 MiB each direction, application seconds | 19.665 | 42.690 |
| Aggregate verified payload throughput, Mbit/s | 13.65 | 6.29 |
| Sampled CPU seconds, process trees | 13.23 | 32.44 |
| Sum-of-process peak RSS, MiB | 82.5 | 240.1 |
| Small echo RTT median, ms | 2.527 | 8.565 |
| Median of per-round RTT p95, ms | 5.965 | 18.653 |

Transfer-time ranges: native 19.452–22.554 s, existing 41.501–50.145 s.
In this workload the native median payload rate is 2.17× the existing path.
CPU and RSS include the Node control process, native client/exit and observed
descendants, not only the C++ worker. CPU observation includes the 100 RTT probes;
the transfer timer/throughput excludes them. Summed RSS double-counts shared pages
and is not physical-memory savings. Runs are sequential, not randomized; host
load, emulation and warm-up can affect the comparison. Hardware measurement and
long-duration load testing remain separate from M1.

## M1 acceptance gates — completed in the lab

- [x] Real native TLS/H2 bidirectional packet exchange and reconnect.
- [x] Initial negative certificate/auth/frame/control tests and sanitizer run.
- [x] Handshake/auth interoperability with the existing Node wire endpoint.
- [x] Real TUN in an isolated VM: initial TCP/UDP/DNS/fragmentation/crash checks.
- [x] Broader adversarial H2/framing/backpressure and mixed-version packet tests.
- [x] Production-profile guard, USB admin and DNS interception acceptance in VM.
- [x] Native DNS path and control-plane ownership integration in the final combined VM.
- [x] Resource/throughput comparison under the same workload.
- [x] Report limitations and stop for review before merge/deployment.

This closes the agreed M1, not a production-readiness or security-audit claim.
Physical arm64/Radxa acceptance, systemd/installer integration for the new engine,
clock recovery, public-listener hardening, browser-profile fidelity and broader
transport support remain outside this result. The old production path remains
unchanged and available; the new path never silently delegates payload to it.
