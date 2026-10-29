# Isolated transparent relay WAN fixture

`clean-vpn-native-relay-wan-lab.py` is a bounded test fixture for an existing
native engine. It does not install or replace a VPN service. Both endpoints run
native transparent-tls in newly created, loopback-only network namespaces.
Only the fixture's TCP socket crosses the physical host boundary.

```text
verified TLS request → private OUTPUT REDIRECT → native relay client
  → TCP/Unix byte bridges → host TCP test-port → TCP/Unix byte bridges
  → native relay exit → private verified TLS origin
```

The bridge preserves TLS bytes but changes TCP timing and buffering. This is a
correctness/fingerprint test, **not a throughput benchmark**. It does not prove
full browser indistinguishability or test the boring branch of combo.

## Boundaries

- Linux/root, `ip`, `iptables`, `unshare`, Python 3, `tcpdump`, an existing engine.
- Each role gets a new root-owned mode-0700 directory, a private raw 32-byte `psk`;
  exit also gets `cert.pem`/`key.pem`, client gets `ca.pem` (all mode 0600).
- The test certificate must cover `wan-relay.test`. Client verifies CA and name.
- Synthetic destination `11.22.33.44:443` is assigned only inside fresh namespaces;
  it never leaves the host. Client intercepts only that destination there.
- No host TUN, route, forwarding, firewall, resolver or production-service changes.
- Host exit binds the specified IPv4 and test port (default 3443); it must be free.
  Existing host firewall may block it. Do not open/change firewall automatically.
- There are at most eight concurrent fixture handlers, bounded queues and 30-second
  connection lifetimes. Trial duration is 15–300 seconds.
- For physical hosts, run under a uniquely named transient systemd unit with
  `RuntimeMaxSec` and `KillMode=control-group`. Killing only an outer Python PID
  with SIGKILL is not a substitute for whole-cgroup cleanup.
- Client runs eight controlled requests, alternating TLS 1.2/1.3, checking all
  163840 response bytes and their SHA256. Capture only the private relay port.
- The tool never generates, prints or imports production credentials.

Example arguments after separate provisioning, inside that transient unit:

```sh
python3 scripts/clean-vpn-native-relay-wan-lab.py \
  --role exit --engine /absolute/path/to/clean-vpn-engine \
  --directory /run/private-unique-exit-trial \
  --exit-address EXIT_IPV4 --port 3443 --seconds 120
```

Client uses `--role client`, its own private directory and the same exit address.
Prepare/start exit first; wait for `wan-exit-ready`. Retain exit replay state
through this one trial. Afterwards stop both transient units, verify port release
and unchanged production PIDs, then remove only the exact trial-owned paths.
Raw pcaps and temporary credentials stay out of Git.

## Reproducible local verification

Run inside an isolated privileged Linux laboratory container; this opt-in test
refuses the normal unit-test path without `CVPN_WAN_FIXTURE_TEST=1`:

```sh
CVPN_BUILD=/build CVPN_WAN_FIXTURE_TEST=1 \
  node --test scripts/test-native-relay-wan-fixture.mjs
```

The test generates fresh credentials, starts separate native namespaces, captures
both original and bridged ClientHello, and uses the existing offline observer
without engine logs. It checks eight JA3/JA4 pairs, encrypted replacement SNI,
verified TLS responses, wrong-key rejection with exit surviving, termination,
port release and byte-identical host network/iptables snapshots.

The observer shares the project's JA3/JA4 parser; it is independent of engine
telemetry, not an independent fingerprint algorithm. Local loopback results are
not evidence of a completed Radxa↔VPS WAN run.
