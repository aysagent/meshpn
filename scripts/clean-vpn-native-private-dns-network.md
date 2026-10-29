# Network ownership for private client names

Private `.mpn` resolution is opt-in on the exit. The native packet configuration
uses `private_peer_dns: true`; for combo this field belongs inside `boring`.
It enables the native bridge on `10.99.0.1:1055`, bound to the exit TUN. The
registry resolver remains a separate process on `127.0.0.1:1055`. Neither the
flag nor the network owner starts that registry resolver automatically.

Client native DNS reserves `.mpn` and `0.99.10.in-addr.arpa` for this path.
When the private service is unavailable these queries fail; they must not be
forwarded to public upstreams. Public DNS continues through the normal tunnel.
Client-to-client packet forwarding is a separate policy; resolving a name does
not itself grant connectivity to that client's services.

Supported control-plane paths:

- `clean-vpn-native-runtime-config.mjs create --private-peer-dns` generates the
  exit flag. The standalone/container runtime derives its private firewall
  rules from that same engine configuration.
- The offline client manifest accepts `private_peer_dns: true` and propagates it
  to the exit engine and dedicated site profile, never to client configuration.
- A manually constructed site profile must match the exit engine flag. Site
  planning also requires the native `private_peer_dns.exit_opt_in` capability.
- The scoped existing-host exit owner derives the flag from its engine config,
  journals four additional owned rules and removes only those rules on recovery.

Rules allow UDP/TCP destination 1055 only on the selected exit TUN, from the
`10.99.0.0/24` subnet to `10.99.0.1`. Replies use that TUN, source port 1055 and
the conntrack reply direction. No uplink INPUT allowance, default route, system
resolver or global firewall policy is added by this option. Native admission
additionally checks active peer identities. Combo's restricted OUTPUT rules
preserve this private reply path.

This is a startup option: changing it on a running installation requires the
engine and its network owner to be reconfigured together. Peer enrollment itself
uses hot reload; it does not require rebuilding these subnet-scoped rules.
An existing installation's files are not rewritten by the generators.

Validation: 75 related planning/provisioning checks; real isolated Linux
TUN/iptables owner tests, 31 checks with private DNS and 23 with default settings.
The 31-check run interrupts every journalled rule step, verifies foreign-rule
preservation and restores the exact original state. Its systemd status is
injected; end-to-end native DNS and systemd resolver tests are separate evidence.
No physical Radxa/VPS activation is implied by these results.
