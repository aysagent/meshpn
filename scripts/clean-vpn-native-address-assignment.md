# Native runtime address assignment: wire primitive and remaining gates

Status: the standalone offer codec and its tests exist. **Runtime address
discovery and owner integration are not implemented/enabled yet.** Current
client bundles still carry their assigned IPv4 from enrollment.

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

## Required native integration

1. Add explicit version/purpose negotiation to the encrypted HTTP headers. New
   discovery must fail on absent/unknown version; do not silently fall back to a
   fixed local address when an old exit ignores the negotiation request.
2. Authenticate the request first, then construct the offer from that matched
   peer's address. Never reflect a requested address. Duplicate headers, DATA
   before auth and malformed offers are rejected by both H1/H2 paths.
3. Discovery is bounded, carries no tunnel payload, does not claim or evict a
   live packet owner, and terminates after its authenticated response. Add
   native `--discover-address` without opening TUN or starting DNS. It must use
   the normal CA/hostname checks and saved TLS profile, and output only the
   verified address plus negotiation metadata, not keys or raw MACs.
4. Full packet session repeats the purpose-separated proof and requires the
   exact discovered address before reading/writing any TUN packet. Reassignment
   between discovery and connect fails closed and triggers bounded rediscovery;
   the server's source-address enforcement remains authoritative.
5. Discovery and full-session connections use the current peer generation.
   Invalid reload retains the old mapping; valid reassignment cancels old
   sessions. Deleted/revoked keys receive no offer. Never reset relay replay.

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

- Real H1/H2 native discovery and full-session tests, two different PSKs returning
  different registry addresses, old clients interoperating, old exit rejecting
  new discovery safely, certificate/name/wrong-key/time failures rejected.
- Wrong/missing/mutated/replayed offers, wrong-purpose proofs, explicit requested
  IP, pre-auth DATA, reused key collision, concurrent discoveries and revoke/
  rotation/reassignment races, bounded CPU/memory/connection lifetime.
- Real TUN+DNS+routes ownership lifecycle in Linux VM: start, reconnect, conflict,
  SIGKILL and boot recovery, while an unrelated peer remains connected.
- `.mpn` uses the same active registry mapping. Discovery failure never permits
  direct DNS or direct internet fallback.
- Only then a bounded physical trial; existing daily installations stay fixed
  until explicitly upgraded. Codec tests alone do not satisfy these gates.
