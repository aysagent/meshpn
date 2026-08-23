# clean-vpn TLS client protocol (device phase 2)

Implemented in `components/meshvpn_vpn/` when `CONFIG_MESHVPN_VPN_ENABLE=y`.

## Wire protocol (`--type=tls`)

1. TCP `server:443`
2. TLS 1.3, verify `ca.pem`, optional SNI mask
3. TLS exporter: label `EXPORTER-clean-vpn-bind`, 32 bytes
4. Bearer: `HMAC-SHA256(PSK, "clean-vpn-tls-v2:" + exporter_hex + ":" + window)`
5. HTTP/2 `POST /clean-vpn` with `Authorization: Bearer ...`
6. Duplex stream: `[uint32 BE length][IPv4 packet]`

## Not supported on ESP32-S3

- `boring-tls`, `transparent-tls`, `combo-tls`, enc-SNI relay

## Dependencies (planned)

- mbedTLS / esp-tls (TLS 1.3 + exporter)
- nghttp2 (HTTP/2 client)
- Certs in LittleFS: `ca.pem`, `clean-vpn-hmac.key`

## Integration

`meshvpn_routing` sends packets with action `vpn` to `meshvpn_vpn_send_ipv4()`.
Replies injected back to USB netif.
