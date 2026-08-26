# clean-vpn TLS client protocol (device phase 2)

Implemented in `components/meshvpn_vpn/` when `CONFIG_MESHVPN_VPN_ENABLE=y`.

## Supported transports (admin: Protocol dropdown)

| Transport | Wire | Exit type |
|-----------|------|-----------|
| `tls` | TLS 1.3 → exporter → Bearer → HTTP/2 POST `/clean-vpn` → `[u32 BE][IPv4]` | `--type=tls` |
| `transparent-tls` | Plain TCP IPv4-mux + inline :443 enc-SNI intercept | `--type=transparent-tls` |
| `boring-tls` | Profile-aware TLS + same HTTP/2 VPN layer as `tls` | `--type=tls` |

## Wire protocol (`tls` / `boring-tls`)

1. TCP `server:443`
2. TLS 1.3, verify `ca.pem` (SPIFFS `/storage/ca.pem`)
3. TLS exporter: label `EXPORTER-clean-vpn-bind`, 32 bytes
4. Bearer: `HMAC-SHA256(PSK, "clean-vpn-tls-v2:" + exporter + ":" + window)`
5. HTTP/2 `POST /clean-vpn` with `Authorization: Bearer ...`
6. Duplex stream: `[uint32 BE length][IPv4 packet]`

## transparent-tls

- **IPv4 mux:** plain TCP framing (same as `--type=socket`)
- **HTTPS:** LAN TCP/443 redirected to local `:8443`, ClientHello SNI replaced with enc-SNI v2 relay hostname (`--tls-public-name` required)

## Storage (SPIFFS `/storage`)

- `ca.pem` — upload via admin
- `clean-vpn-hmac.key` — HMAC PSK
- `profiles/*.json` — boring-tls ClientHello profiles (schema v1)

## Admin API

- `GET/POST /api/vpn/config`
- `POST /api/vpn/certs/ca`, `/api/vpn/certs/psk`
- `GET/POST /api/vpn/profiles`

## Integration

`meshvpn_routing` + lwIP hook → `meshvpn_datapath` → `meshvpn_vpn_send_ipv4()`.
Replies: `meshvpn_net_inject_ipv4_to_lan()`.

## Dependencies

- mbedTLS / esp-tls, nghttp2 (`espressif/nghttp`), SPIFFS
