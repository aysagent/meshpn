# Experimental address discovery in an isolated runtime

Status: the native H1/H2 discovery and session proof are implemented. This
owner adapter is opt-in; real kernel integration is being verified separately.
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

Six unit scenarios cover strict discovery output, guard-before-query ordering,
effective config, restart, changed address, interrupted setup, changed source,
foreign rules, replaced namespace and explicit opt-in. Actual native/kernel
gates and container packaging must pass before treating this as a usable mode.
