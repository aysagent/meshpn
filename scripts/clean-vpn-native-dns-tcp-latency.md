# Native DNS TCP framing regression

The production resolver previously sent the DNS two-byte length and payload with
separate `write_all` calls, in both its upstream request and downstream response.
A small prefix can leave the socket while Nagle holds the following payload until
a delayed ACK arrives. This is the framing interaction described in
[RFC 7766 section 8](https://www.rfc-editor.org/rfc/rfc7766.html#section-8).

`dns-tcp-latency-test` links the actual `DnsRelay` class to independent real TCP
client and registry sockets. All addresses live in a fresh namespace within a
NIC-less disposable lab. Test-only linker `--wrap=send` instrumentation records
standalone two-byte sends and introduces a two-millisecond scheduling gap after
such a prefix. Receivers use `TCP_QUICKACK=0` only in the fixture. This deliberately
exercises a possible preemption point rather than waiting for incidental timing;
neither instrumentation nor TCP_QUICKACK is enabled in production.

The fix offers one contiguous length+payload buffer to the existing partial-write
loop. It preserves deadlines, cancellation checks and nonblocking I/O. The test's
fixed-mode assertion is structural (no isolated prefix for these small frames),
rather than a flaky wall-clock latency threshold. Measured timings remain
diagnostics. Baseline/candidate measurements and their limits are recorded in the
[dated report](clean-vpn-native-dns-tcp-20261030.md) and the
[machine-readable receipt](../fixtures/clean-vpn-native-dns-tcp-latency-20261030.json).

Additional regression scenarios verify exact bytes and IDs for small replies,
a 60 KB reply with deliberately short writes, EINTR and EAGAIN, byte-fragmented
client requests, two queries on one persistent connection, and bounded shutdown
while reading a partial client prefix, blocked on an outgoing write, or reading
a partial upstream response. The independent origin receives randomized IDs;
the client receives its original ID and exact expected payload.

Build the `dns-tcp-latency-test` CMake target, then run only inside the explicitly
marked disposable NIC-less Linux lab:

```sh
CVPN_DNS_TCP_LATENCY_TEST=1 CVPN_BUILD=/build \
  node --test scripts/test-native-dns-tcp-latency.mjs
```

For the separately preserved pre-fix executable, add `CVPN_DNS_TCP_BASELINE=1`.
The runner creates and destroys its own namespace and checks that host link,
address, route and rule snapshots remain unchanged. It is intentionally not an
ordinary CTest entry: it requires root and namespace privileges.

This is evidence of a reproducible TCP framing latency defect. It does **not**
prove the cause of the earlier sporadic physical combo SERVFAIL; that failure
still needs its own DNS packet/timestamp evidence. No Radxa/VPS or Mac network
settings were changed by this regression.
