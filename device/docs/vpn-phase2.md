# VPN phase 2 — planned, not implemented

The current `meshvpn_vpn` component is a stub, including when its Kconfig option is enabled.
The current firmware always forwards internet traffic directly over WiFi; saved historical routing rules are not enforced.

The next phase will investigate compatibility with `scripts/clean-vpn.js`, primarily boring-tls,
and additionally transparent-tls/combo-tls, plus a client for ordinary WireGuard servers.
The transport choice and feasibility are not settled by the existing TLS placeholder.

Re-derive framing, exporter/HMAC and relay behavior from the current clean-vpn code before implementation.
The previous device document's exporter_hex formula was not an authoritative wire specification.
No VPN throughput has been measured on this board.

See [plan.md](../plan.md) and [current implementation](current-improvements.md).
