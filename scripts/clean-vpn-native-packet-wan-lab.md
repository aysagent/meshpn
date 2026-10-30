# Bounded packet/DNS WAN trial

`clean-vpn-native-packet-wan-lab.py` is an explicit test fixture, not an installer.
It starts the production native engine with a real TUN inside a fresh anonymous
network namespace. Host networking is unchanged: the only host network operation
is a bounded TCP listener on the exit, or an outbound TCP connection on the client.
TCP/Unix byte bridges connect the isolated namespaces across the WAN. These bridges
change TCP timing; results do not establish throughput or transparent branch health.

Run each role in a new private root-owned directory, within a bounded transient
unit whose `KillMode=control-group` cleans descendants. No daily service is stopped.
The directory must contain a valid, private `engine.json` and referenced credentials.
Exit configuration is never rewritten by this fixture, so the client manager may
atomically replace its peers and deliver SIGHUP to the PID recorded in `engine.pid`.

Both packet configurations must use `address: "127.0.0.2"`, `port: 33443`,
`tun: "cvpw0"`; combo's transparent endpoint must agree. The exit requires
`private_peer_dns: true`, a separately initialized replay directory for combo,
and an existing private registry file. The client requires `dns: true`,
`address_assignment: "v1"`, and no `peer_ipv4`. Successful native authenticated
address discovery precedes TUN creation. Its result is saved as `assignment.json`;
the effective client configuration is saved as `engine-effective.json`.

```sh
python3 scripts/clean-vpn-native-packet-wan-lab.py \
  --role exit --engine /absolute/clean-vpn-engine --directory /run/PRIVATE/exit \
  --exit-address EXIT_IPV4 --port 3443 --seconds 180 \
  --node /absolute/node \
  --registry-script /absolute/scripts/clean-vpn-native-peer-dns.mjs \
  --registry-file /run/PRIVATE/state/registry.json

python3 scripts/clean-vpn-native-packet-wan-lab.py \
  --role client --engine /absolute/clean-vpn-engine --directory /run/PRIVATE/laptop \
  --exit-address EXIT_IPV4 --port 3443 --seconds 160 --peer-name laptop.mpn
```

Readiness JSON events are `packet_wan_exit_listening` (host listener ready) and
`packet_wan_ready` with `role: "client"` (native session ready). The fixture writes
`namespace.pid`, `namespace.id`, `engine.pid`, and `native.log`; exit also writes
`resolver.pid` and `resolver.log`. The temporary `bridge.sock` is removed at exit.
The parent trial controller should verify recorded PIDs belong to its transient
unit before signalling or entering their namespace.

The client emits sequenced `packet_wan_probe` results every second. Each successful
probe resolves its assigned `<name>.mpn` through the native stub over both UDP and
TCP, then verifies a 3584-byte echo through the native packet tunnel. The synthetic
origin `11.22.33.44:18080` exists only on the isolated exit loopback. Probe failures
remain explicit but do not stop the fixture, permitting intentional DNS outage
and recovery checks; native engine or registry process exit is fatal. A ready
message alone is not a successful probe.

```sh
nsenter -t "$(cat /run/PRIVATE/laptop/namespace.pid)" -n \
  python3 scripts/clean-vpn-native-packet-wan-lab.py probe \
  --address 10.99.0.3 --name laptop.mpn
```

Use an unchanged saved Chromium subset profile for both HTTP versions. For H2 use
client `http_version: "2"` and exit `"auto"`; for H1 use client `"auto"` and exit
`"1.1"`. The exit restricts ALPN selection to H1, preserving the client's original
ClientHello profile. A client forced to H1 with a saved H2+H1/ALPS profile is
correctly rejected. Native state logs currently do not report negotiated ALPN;
the forced exit selection and successful authenticated exchange establish this
fixture's H1 branch, rather than an invented log field.

Local gate (explicit NIC-less disposable Linux lab only):

```sh
CVPN_PACKET_WAN_FIXTURE_TEST=1 CVPN_BUILD=/build \
  node --test scripts/test-native-packet-wan-fixture.mjs
```

On 2026-10-30 all four cases passed: boring/combo × H2/H1, production engine,
real TUN, verified address discovery, private DNS UDP/TCP, synthetic TCP payload,
SIGHUP removal of an unrelated peer without disrupting the retained session,
registry transaction SERVFAIL and recovery, process cleanup, released host port,
and byte-identical host link/address/route/rule/firewall/DNS snapshots. The saved
profile was unchanged. This is a short local gate, not a completed physical WAN
trial, multi-hour stability result, or transparent branch traffic test.
