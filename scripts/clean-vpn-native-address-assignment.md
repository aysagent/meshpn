# Native runtime address assignment: wire primitive and remaining gates

Status: the native offer codec, no-TUN discovery CLI and full-session address
proof are implemented behind explicit opt-in. Existing fixed-address clients
continue unchanged. The isolated runtime owner passed its separate real TUN/DNS
gate; see [runtime owner](clean-vpn-native-runtime-address.md). Daily physical
installations are not automatically migrated.

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

The fixed-address owner configures TUN, routes and DNS before engine handshake;
native DNS also binds the configured client address. Therefore a response header
alone cannot implement working dynamic assignment. The opt-in isolated owner
implements the transaction below; host owners remain a separate gate.

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
  broaden time-skew/profile and discovery/reassignment fault coverage before
  enabling broadly (saved H2 profile and concurrent reload cases now pass).
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

### Concurrent reload and full engine sanitizer follow-up

Four additional real native tests cover boring/combo × H2/H1 with four parallel
discoveries during each of seven exit reloads. Six rounds reassign the second
identity between .3 and .4; the final round revokes it. Completed pre-publication
offers may contain the previous valid mapping, while pending requests may be
refused. After publication a fresh discovery must return the current assignment;
after revoke it must fail. The unrelated .2 session and bidirectional packet
traffic survive with unchanged process IDs. Exit descriptor counts return to
baseline and production RSS growth stays below the 8-MiB test budget. These are
bounded race regressions, not a long-running assignment soak.

The assignment suite now has 34 cases (59 unique JS cases including the existing
23 interoperability and two data-plane cases). All 34 also passed with the full
engine and packet fixture compiled using ASAN/UBSAN, leak detection enabled, and
explicit rejection of sanitizer diagnostics even in expected-failure tests.
Static dependency libraries were not instrumented. The instrumented resource
check uses a separate 32-MiB RSS budget: the original production 8-MiB assertion
failed on roughly 10 MiB of instrumented growth without a sanitizer finding.
The production budget and descriptor checks were not relaxed.

The independent isolated Linux owner gate separately passed eight checks:
verified .17 assignment through TUN/DNS/NSS/ping, same-interface restart, refusal
of reassignment in an existing namespace, wrong-PSK guard containment, and .23
adoption in a fresh namespace. Details and limitations are in the linked runtime
owner document. No address-assignment deployment to Radxa/VPS was performed.

### Discovery clocks and independent profile observation

Discovery uses the ordinary TLS certificate validity checks and authenticated
clock-window rejection. It does not set the system clock, invoke SSH bootstrap,
retry after clock failure, or emit an address from a failed handshake. Its fixed
error vocabulary retains `tls_verify_expired`, `tls_verify_not_yet_valid`,
`tls_verify_name`, `tls_verify_untrusted` and `tls_verify_failed`; arbitrary
exception text remains suppressed. Certificate date errors alone do not prove
that the local clock is wrong.

The isolated address owner currently reports discovery failure and leaves the
bootstrap guard closed. It has no automatic clock-recovery/retry integration.
The separate physical boring client clock lifecycle must not be inferred to
apply to this owner. Establish correct time independently before restarting the
isolated runtime; certificate verification is never disabled.

The boundary suite issues expired/future certificates without changing any
clock, checks authenticated clock-skew responses, and checks both boring/combo
and H1/H2 discovery. The source config stays unchanged, there is no TUN, and
exactly one TLS connection is attempted. Saved-profile comparison uses a separate
TCP byte proxy and the standalone offline observer to capture discovery and the
subsequent full session. The profile is the synthetic saved H2 fixture; this is
not evidence of a complete browser network profile or HTTP-level equivalence.

```sh
CVPN_BUILD=/absolute/build node --test --test-concurrency=1 \
  scripts/test-native-address-discovery-boundaries.mjs
```

All fourteen new boundary cases passed together with the 34 assignment cases
(48/48, no skips). Twelve cover certificate dates/clock rejection and two cover
external discovery/full-session profile observation (four captured ClientHellos).
JA3 was `1486e97570653f52b603bf93abaffe92`; JA4 was
`t13d0307h2_55b375c5d22e_70c6d19c6451`, with distinct handshake randoms.
The earlier full-engine sanitizer run predates the five-error-code diagnostic
patch; no new sanitizer coverage is claimed for that rebuild.

The observer matrix additionally covers the saved
`chromium-156-bounded-cold-v1` profile on boring and combo. Its explicit reviewed
subset and deviations remain documented in the profile provenance; this does
not make it equivalent to stock Chromium. Discovery and full-session captures
match that saved subset. Extension permutation intentionally changes raw JA3,
so these cases compare sorted JA3 `9fc752c58190630c49e1812906b40077` and
JA4 `t13d0915h2_f91f431d341e_54d72502093d`, while checking each complete capture
against the profile. The boundary suite now has 16 passing cases, including
four observer cases/eight captured ClientHellos.

### Final interaction review and operational boundaries

Discovery returns an authenticated snapshot, not a reserved lease: a completed
offer can precede an immediately following key/address change. Full-session
proof and the owner transaction must therefore remain mandatory. Pending
authentications are closed on every successful peer reload; only sessions with
exactly unchanged key and address survive. A rejected reload preserves the
previous packet/relay mapping. Private DNS admission receives the same committed
peer address set, and unchanged relay identities retain their replay windows.

New packet handshakes/discoveries share the existing global limits (16 pending,
32 admitted per second). These bound resources but do not guarantee new-client
availability under an unauthenticated connection flood. Established sessions
have separate per-tick processing budgets. Reload revocation prevents further
use of the removed key; it cannot retract traffic already forwarded to a
destination or a completed discovery result delivered before publication.

The reload ACK hashes the JSON document, not referenced key-file contents.
Manager verification must retain its process/invocation and revision/event
checks; do not treat an unchanged document hash as proof that key bytes stayed
unchanged. These are boundaries of the current contract, not a promise of
zero-packet rollback or distributed lease consensus.
