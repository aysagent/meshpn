# Experimental address discovery in an isolated runtime

Status: the native H1/H2 discovery and session proof are implemented. This
owner adapter is opt-in; its real isolated Linux integration passed eight checks.
It is not an upgrade of the running Radxa/VPS pair or the existing-host owner.

An isolated client source configuration uses `address_assignment: "v1"` and
omits `peer_ipv4`. For combo these fields belong inside `boring`. The source
must be a private root-owned regular file, mode 0600. Runtime additionally
requires `CVPN_ADDRESS_DISCOVERY=1`; neither flag silently enables the other.

Before discovery the owner journals intent and installs private IPv4/IPv6
bootstrap chains. Only loopback and the exact numeric exit TCP endpoint are
allowed; forwarding and other outbound traffic are dropped. Native
`--discover-address` performs the ordinary certificate/name/profile and PSK
authentication without opening TUN or DNS. The owner accepts only a bounded
verified version-1 response with an address in `10.99.0.2..254`.

The source configuration remains unchanged. The verified address is added to
the private runtime snapshot, then the ordinary runtime owns TUN, routes, DNS
and guard rules for that address. The full native session separately confirms
the address with a purpose-bound proof before readiness or packet traffic.
The initial proof cannot be replayed as a full-session proof.

On engine restart, the source and guard ownership are checked and discovery is
repeated. The same address can reuse the existing TUN. A different assignment,
source edit, interrupted transaction, missing guard or replaced namespace is a
conflict: the runtime refuses to proceed and keeps its rules. Recreate the
owned namespace/container to adopt a changed assignment. There is no automatic
live route replacement, stale cached address or `.2` fallback.

The extra bootstrap chains remain underneath the normal runtime chains. The
engine never removes either guard on shutdown. Cleanup is destruction of the
owned namespace/container, not flushing host tables. DNS/route settings of the
Mac and physical hosts are outside this adapter's scope.

To export an existing named identity without a fixed client address:

```sh
sudo node scripts/clean-vpn-native-clients.mjs export laptop \
  --address-discovery --output=/root/laptop-discovery.bundle
```

Import uses the ordinary `import` command and an engine supporting discovery.
The bundle's top-level `ipv4` is registration metadata only. It is not copied to
the runtime client config and is never a fallback if authentication fails.
For a new offline pair, `clean-vpn-native-runtime-config.mjs create` accepts
`--address-discovery` in either standalone or container mode; exit reservations
and independent per-client keys remain explicit. Standalone here means a
dedicated Linux namespace, not installing this mode on the host network.

The narrow `clean-vpn-native-container.mjs start` launcher additionally needs
`--address-discovery`; it refuses a mismatch with the source configuration.
The environment flag is needed by runtime launched through other mechanisms.
Default exports, generators and launchers keep fixed enrollment behavior.
The current host/systemd installers and admin export remain fixed-address;
do not enable discovery in those owners without a separate integration.

Six unit scenarios cover strict discovery output, guard-before-query ordering,
effective config, restart, changed address, interrupted setup, changed source,
foreign rules, replaced namespace and explicit opt-in. The real kernel gate
`test-native-runtime-address-linux.mjs` covers discovery to `.17`, TUN packet
traffic and NSS/private DNS, same-address restart, exit reassignment rejection,
wrong-key failure with no TUN, IPv4/IPv6 bootstrap blocking and fresh namespace
adoption of `.23`. All eight passed with each of nft and legacy backends;
parent DNS/firewall were unchanged. Select the test backend using
`CVPN_IPTABLES_BACKEND=nft|legacy` in the explicitly marked disposable lab.
Container packaging has its own separate acceptance gate.

The guard confines IP traffic in its own network namespace. It does not isolate
host IPC: an application using NSS `resolve` can ask a host `systemd-resolved`
through a shared Unix socket/system bus, and that host process can query DNS
outside the namespace. Use a container with no host resolver/system-bus socket
mounts, or an explicitly configured namespace-local DNS/NSS owner. Merely
entering a network namespace while sharing the host `/run` is not proof of
DNS confinement. The native address bootstrap itself uses a numeric endpoint
and does not perform DNS resolution.
