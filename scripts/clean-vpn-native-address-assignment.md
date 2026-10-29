# Native runtime address assignment: wire primitive and remaining gates

Status: the native offer codec, no-TUN discovery CLI and full-session address
proof are implemented behind explicit opt-in. Existing fixed-address clients
continue unchanged. Runtime owner integration is a separate gate; this document
does not claim automatic assignment on daily physical installations.

## Authority and compatibility

The managed exit registry allocates a stable address when an identity is
registered. The native exit maps the successfully authenticated PSK to that
registry peer's address. A client must not choose its address by a request
header, packet source, display name or previous local cache.

This remains one identity per key: duplicate devices sharing a packet key share
one address and cannot acquire independent leases. Full packet session ownership
continues to reject an already active identity. Rotating/revoking that identity
uses the existing atomic peer reload and disconnect behavior.

Runtime discovery should be additive and opt-in for both H1/H2 and combo's
packet branch. Legacy fixed-address clients continue unchanged. Transparent
relay has no packet TUN address to negotiate.

## Implemented primitive

`native/clean_vpn/address_offer.hpp` encodes one canonical value:

```text
v1:10.99.0.N:64-lowercase-hex-HMAC
```

Only N=2..254 is allowed. No leading zeroes, whitespace, extra fields, alternate
IP syntax, gateway override or caller-selected subnet. HMAC-SHA256 uses the
identity's raw 32-byte packet PSK and this exact byte string:

```text
"clean-vpn-address-offer-v1" || NUL || purpose:u8 || TLS-exporter:32 || IPv4:4
purpose = 1 (discovery), 2 (full packet session)
IPv4 bytes are in network order.
```

The exporter is the existing 32-byte `EXPORTER-clean-vpn-bind` output for the
current TLS connection. Domain, purpose, key, address and connection are bound;
a discovery proof cannot authenticate a full session and a proof copied to
another TLS connection fails. Comparison is constant-time for the MAC. This
proof supplements, and never replaces, certificate/name verification and the
existing exporter-bound client authentication/time-window checks.

Independent Python `hmac`/`hashlib` vectors, byte-by-byte mutation rejection,
wrong key/exporter/purpose, all truncations, invalid address spellings and the
entire allowed address pool are tested by `address-offer-test`. The codec cannot
prove the caller supplied an authenticated peer; the engine must enforce that
boundary before calling `encode`.

## Native protocol and CLI

Client requests `x-clean-vpn-address-mode: discover-v1` or `session-v1` in
its ordinary authenticated H1/H2 request. Exit replies with the same mode and
`x-clean-vpn-address-offer` only after matching the PSK to a configured peer.
Unknown modes are refused. An absent response mode/proof from an old exit is
rejected by a new opt-in client.

```sh
/path/to/clean-vpn-engine --discover-address /private/client.json
```

This command is client-only, also accepts the boring branch of combo, and uses
the existing CA/hostname, TLS profile, exporter-bound auth and clock checks.
It does not open TUN, start DNS or bind a transparent listener. The `tun` config
field remains syntactically required but need not exist. `dns: true` is ignored
for discovery only. Connect/auth are bounded by the existing 3/10-second budgets;
there is no automatic retry or readiness notification. Success prints exactly:

```json
{"version":1,"event":"address_discovery","status":"verified","assignment":"v1","ipv4":"10.99.0.3"}
```

Property order is unspecified. Failure/cancellation exits nonzero without a
verified stdout record. Error diagnostics use the fixed internal vocabulary;
no keys, MACs or untrusted response text are printed.

Discovery emits an authenticated response without packet ownership and ends it
(H2 HEADERS+END_STREAM; H1 zero chunk). No tunnel payload is accepted. A currently
connected identity can discover its assignment without evicting its session.
Partial responses, extra payload and missing stream termination are rejected.
Current pending-connection, admission-rate and deadline budgets still apply.

For the following full packet connection, set `address_assignment: "v1"` and
an explicit `peer_ipv4` obtained from discovery in the effective config. Before
ready or TUN packet I/O, the client requires the purpose-separated proof to
match that exact address. A missing `peer_ipv4` in normal run is refused; no
silent default .2 is used for this mode. Reassignment between discovery and
connect fails closed. The server independently continues to enforce packet
source and session ownership, so the offer cannot authorize a different address.

Invalid reload retains the mapping. Valid rotation/revoke cancels affected
sessions; pending discoveries are discarded with the old generation. Relay
replay state is unaffected. Native integration tests check two identities,
active-session discovery, ignored locally claimed IP, valid bidirectional packet
traffic, mismatch rejection and revoke while an unrelated peer remains active.

An independent Node TLS issuer verifies the client's auth and supplies valid or
mutated offers for H1/H2: old exit, absent proof, wrong mode/key/exporter/purpose,
changed IPv4, noncanonical hex, payload and incomplete responses. This does not
reuse the native offer encoder.

## Required owner transaction

Today the owner configures TUN, routes and DNS before engine handshake; native
DNS also binds the configured client address. Therefore a response header alone
cannot implement working dynamic assignment.

The owner must first keep the guard closed, perform the no-TUN discovery and
journal the proposed runtime address. It then installs only owned TUN/address/
route/DNS changes using that verified value, starts the full session and opens
readiness only after address confirmation. A config/key/lease change between
steps is a conflict, not permission to use a stale cached address. Failure,
SIGKILL, reboot or reassignment follows the existing fail-closed ownership
journal and restores only previously owned state.

The exported client bundle can then omit a concrete IPv4 and request discovery;
its persistent identity and endpoint remain unchanged. Runtime config files are
private, atomic and disposable; the registry remains the persistent allocator.
There is no independent DHCP allocator inside the native reactor.

## Acceptance gates before enabling

- Keep native H1/H2 discovery/full-session and legacy-client regressions green;
  add explicit time-skew/profile and concurrent discovery/reassignment coverage
  before enabling broadly.
- Wrong/missing/mutated/replayed offers, wrong-purpose proofs, explicit requested
  IP, pre-auth DATA, reused key collision, concurrent discoveries and revoke/
  rotation/reassignment races, bounded CPU/memory/connection lifetime.
- Real TUN+DNS+routes ownership lifecycle in Linux VM: start, reconnect, conflict,
  SIGKILL and boot recovery, while an unrelated peer remains connected.
- `.mpn` uses the same active registry mapping. Discovery failure never permits
  direct DNS or direct internet fallback.
- Only then a bounded physical trial; existing daily installations stay fixed
  until explicitly upgraded. Codec tests alone do not satisfy these gates.

## Native validation, 2026-10-30

```sh
CVPN_BUILD=/absolute/build node --test --test-concurrency=1 \
  scripts/test-native-address-assignment.mjs
```

Thirty assignment cases passed: four real native boring/combo × H2/H1 tests and
26 independent issuer cases, including ten-second deadline and SIGTERM refusal.
The H2 native cases also run the saved `synthetic-cold-h2` profile during discovery
and the full session. These are in an unprivileged Linux lab with an absent TUN;
production discovery succeeds despite `dns: true`, confirming that discovery
opens neither TUN nor the DNS listener. Packet testing uses only the dedicated
C++ fixture packet boundary; discovery uses the production binary.

Twenty-three existing HTTP1/multi-peer/reload/WAN-fixture cases and two complete
H1/H2 data-plane cases passed too, covering fixed-address interoperability,
reconnect, blackhole, backpressure and wrong CA/name/PSK. Offer codec tests passed
normally and under ASAN/UBSAN with leak detection; dependency libraries in that
codec sanitizer run were not instrumented. No physical deployment was performed
for address assignment. Runtime owner validation is tracked separately.
