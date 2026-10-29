# Experimental device VPN

## Plain clean-vpn transports

The firmware implements `tcp` (formerly `socket`): TCP carrying `[uint32 big-endian length][IPv4]`.
It also implements `udp`: one UDP datagram carries exactly one IPv4 packet, with
no length prefix or handshake. Neither transport has authentication or encryption.
Use a dedicated test exit restricted
by firewall to your trusted client address/network. Never expose an unrestricted
plain exit on the public Internet. No server protocol changes are required.

Contract checked against `scripts/clean-vpn.js` at
`a49b0baf56db7804b34b6126d8614cecb7050466`: client `10.99.0.2`, peer `10.99.0.1`,
MTU 1400; no handshake or HTTP preamble. The firmware accepts only IPv4
TCP/UDP/ICMP, limits each framed packet to 1400 bytes and closes malformed streams.
Future TLS/profile/auth vectors in plan stage 0 remain deferred, not claimed tested.

On the **dedicated, firewall-restricted exit**, from the project directory:

```sh
sudo env PATH="$PATH" node scripts/clean-vpn.js --role=exit --type=tcp --server=0.0.0.0:8765 --keep-alive=0
```

For UDP, stop the TCP exit and run:

```sh
sudo env PATH="$PATH" node scripts/clean-vpn.js --role=exit --type=udp --server=0.0.0.0:8765
```

The current clean-vpn UDP exit tracks one peer. UDP can lose or reorder packets;
it is intended for transport comparison, not as a secure or reliable VPN protocol.

The exit installs address-scoped `10.99.0.2/32` forwarding and masquerade rules
at the head of their iptables chains. This is intentional: appending after an
existing ufw/firewalld terminal `REJECT` makes the tunnel TCP connection look
healthy while forwarded client SYN packets receive immediate synthetic resets.
The rules are removed on normal shutdown.

In the device admin VPN section select tcp or udp to match the exit, enter its
**numeric IPv4:port**,
acknowledge plaintext, enable and save. Changes apply without reboot and persist.
Disable VPN to return to DIRECT. Experimental raw TLS is described below.

All forwarded Internet traffic from both USB and AP goes through a virtual lwIP
interface and existing NAPT. LAN-local traffic/admin/DHCP remain local. The outer
TCP/UDP socket binds the STA address, avoiding tunnel recursion. While enabled but
disconnected, the default **Kill switch ON** keeps the virtual route selected and
drops packets. Turning kill switch OFF explicitly permits DIRECT fallback while
disconnected, for both plain transports and WireGuard. Turning **Enable VPN OFF** always
restores DIRECT; saving a profile alone does not enable it. IPv6 remains blocked
by the existing ingress policy.
DNS proxy uses 1.1.1.1 through the VPN (numeric exit eliminates bootstrap DNS).
Applying settings clears DNS cache and NAPT mappings: restart existing client
connections. Independently initiated device services other than this DNS proxy
are not full-tunnelled.

## Admin status and controls

- **Save and apply** persists and immediately applies the selected enable flag,
  transport and kill switch. No board reboot is needed; success is not proof of
  connection. The header shows the currently applied state, not unsaved edits.
- **Reconnect VPN** reapplies the saved enabled profile, flushing old NAT mappings
  and reconnecting without reboot. Save unsaved edits first.
- **Check internet via VPN** performs a TCP connection to `1.1.1.1:443` with a
  five-second timeout in a single background worker, bound to the virtual VPN interface and source address. The API returns immediately and status exposes `internet_probe.running`. It
  never uses DIRECT fallback, even with kill switch OFF. This is a manual,
  point-in-time reachability test, not a DNS, TLS, exit-IP or continuous health
  check. Failure does not prove the entire Internet is down. The last result and
  its age are shown; after 60 seconds it is labelled outdated. Config changes and
  disconnects invalidate the result. Probe failure does not change routing.
- Kill switch defaults ON, including migration of existing profiles. It applies
  only while VPN is enabled and only to traffic through the device, not to other
  laptop interfaces. OFF allows direct forwarding/DNS while the tunnel reports
  disconnected; NAT mappings are cleared when switching egress. WireGuard valid
  session keys are not an immediate liveness detector; outages may take time to
  be reported as disconnected. Unsupported/misconfigured profiles are not proof
  of a working VPN; inspect the status/error and perform a reachability test.

TCP, UDP and WireGuard internet forwarding were exercised by the user on XIAO,
including throughput runs. This is historical hardware evidence for those builds;
it does not certify every later change or P4 VPN operation. Current host tests
execute the route selector, DNS policy, queues, actual API/config handlers and UI.
The [night report](reports/2026-10-25-night.md) records current build/hardware evidence.

The TX queue holds 256 packets in PSRAM, drops entries older than 1 second, and
cannot grow with traffic. Dedicated RX and TX tasks share the full-duplex outer
socket, so lwIP injection does not block queue draining. TCP sends up to 32 queued
frames per batch; UDP sends one packet per datagram without a writable `select`
before each send. UDP RX drains up to 32 available datagrams or 4 ms before one
lwIP injection callback. Diagnostics `socket.rx_inject_exec_us` is the cumulative
callback round-trip time (including scheduler wait); `rx_inject_exec_max_us` is
the lifetime maximum, not a per-test sample. Partial TCP frame/write
deadlines are 5 seconds. TCP connect timeout is 5 seconds, reconnect backoff is
1–16 seconds and TCP keepalive detects idle failures. For socket, `connected`
means **outer TCP established**. For UDP it means the local connected UDP socket
is ready; UDP has no handshake and only the internet probe or actual traffic can
confirm the exit path. TX counts successful socket writes, not destination delivery.
MSS options in SYN packets are clamped to `1400 - IP header length - 20`
(1360 without IP options). Fragmented IPv4 is reassembled before NAPT. Oversized
DF packets receive pre-NAT ICMP fragmentation-needed feedback with MTU 1400 and
the original LAN tuple. The generated NAPT patch translates ICMP destination
unreachable/time exceeded/parameter problem quotations for TCP, UDP and echo,
including short/chained quotations and checksum updates. Other upstream NAPT
limitations still apply; host tests do not replace end-to-end packet capture.

## Verification status / hardware acceptance

Automated: firmware build for XIAO; host sanitizers; all frame split boundaries,
coalescing/bad lengths/truncation; real clean-vpn JS ↔ C framing; MSS checksum
changes with odd/even option alignment; production routing selector tests; UI
save/disable/plaintext confirmation/poll edit preservation. These are not a
substitute for running the worker and NAPT on the board.

**Regression checklist for the current build, requires a real exit/TUN:**

1. Enable socket; ping `10.99.0.1` from USB client. Observe both directions on exit
   TUN. This, not TCP echo, proves stage 1.
2. From USB, then AP, then both: DNS, HTTP/HTTPS, external exit address, TCP/UDP
   upload/download. Check NAPT return delivery and independent simultaneous flows.
3. Capture STA/uplink: only outer exit TCP should carry forwarded Internet traffic;
   DNS must not appear as direct UDP/TCP 53.
4. Stop exit / disconnect STA during traffic. Confirm no direct fallback, local
   admin remains usable, reconnect discards unfinished frames. Test endpoint
   changes and reboot with saved enable; no initial DIRECT forwarding window.
5. MTU tests: SYN MSS, large UDP, fragmented replies, DF/ICMP behavior, malformed
   lengths, partial frame timeout, 30-minute memory/load run and DIRECT regression.

Current Mac lab: P4 is connected and local USB stress is available. A synthetic
TCP/UDP/TLS peer can run on an existing Mac LAN address without changing Wi-Fi or
host routes. macOS "Block all incoming connections" currently prevents the board
from reaching that peer. Tests under that condition are recorded as blocked,
not hardware VPN passes. Real mbedTLS I/O can still be tested over loopback.

Run host checks with `bash device/scripts/test-host.sh`; standard board build/flash
uses the project's existing device scripts. Use a freshly generated sdkconfig:
VPN and IPv4 reassembly are now enabled in defaults (runtime VPN defaults OFF).

## WireGuard (experimental, one peer)

Second backend: `wireguard`, standard encrypted UDP, **not** compatible with a
clean-vpn socket server. Uses pinned `esphome/wireguard` 0.4.6 and its libsodium
dependency (exact transitive versions/hashes in the per-target lockfiles).
No custom cryptographic protocol or JA3/JA4 emulation is involved.

Admin fields follow the WireGuard profile order and names:

```ini
[Interface]
PrivateKey = <device private key>
Address = 10.0.0.7/24,fd42:42:42::7/64
DNS = 1.1.1.1

[Peer]
PublicKey = <server public key>
Endpoint = <numeric server IPv4>:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Paste the original Address value, including CIDR and comma-separated IPv6:
`10.0.0.7/24,fd42:42:42::7/64`. Plain `10.0.0.7` and `10.0.0.7/24` also work.
The original value is saved and restored in the UI; `/api/status` exposes it as
`wireguard.address_input`, while `wireguard.address` contains the effective IPv4.
Exactly one IPv4 is required; prefixes are validated (IPv4 0–32, IPv6 0–128).
IPv6 entries are accepted but **not used**; the UI warns about this explicitly.
IPv6-only profiles and multiple IPv4 addresses are rejected rather than silently
selecting an arbitrary address. The backend still uses /32 internally and full
IPv4 routing; the pasted prefix does not create a directly connected subnet.
`AllowedIPs` is read-only; `::/0` is not used. Optional `PresharedKey` controls
follow the main peer fields. Existing stored profiles migrate without losing keys
or changing the kill switch setting.

Field details:

- Server: numeric IPv4 and UDP port, e.g. `192.0.2.1:51820`.
- Device tunnel address: paste Address from the WireGuard profile, optionally
  including CIDR and IPv6 entries. This version uses the IPv4 with /32 internally.
  The effective IPv4 must not overlap the USB/AP or uplink subnet.
- Server public key, device private key, optional preshared key: standard
  44-character base64 WireGuard keys. Provision the matching device **public**
  key on the server; the UI does not generate/import wg-quick files yet.
- DNS resolver reached **inside** the tunnel; persistent keepalive 0–65535 sec.
- AllowedIPs is fixed to `0.0.0.0/0` (full IPv4 tunnel), MTU fixed at 1400.

Server peer AllowedIPs should contain the **device tunnel address /32**, because
USB/AP traffic is SNATed to that address. Configure forwarding and egress NAT on
the WireGuard server, as for an ordinary VPN client. Do not deploy/configure a
server merely by flashing this firmware.

Blank private-key/PSK fields preserve saved values. An explicit checkbox removes
the PSK. Only presence booleans, the **public** key and handshake age are exposed
in `/api/status`; private/PSK input fields clear after a successful save. The
API is authenticated. Provision over trusted USB or HTTPS. NVS is not encrypted
at rest unless the device's flash/NVS encryption is separately configured.

The backend never changes the default STA route; WireGuard's outer UDP is bound
to STA by the pinned library. The shared persistent virtual netif applies NAPT,
MSS clamping and disconnected blackholing. On config changes, the old peer/timers/
UDP PCB are removed and the library's device key context is wiped before freeing.
No simultaneous socket and WireGuard connection is maintained.

Decrypted WireGuard IPv4 packets are validated and re-injected through the stable
`vp` interface **before NAPT**, rather than delivered to sockets on the backend
`wg` interface. This is required for the interface-bound DNS/probe sockets:
lwIP rejects a reply arriving on a different interface from the socket binding.
A regression test models this TCP/UDP interface filter, single-pass NAT/packet
ownership and rejection of unexpected inner destinations. It is not an on-board
or server forwarding test.

Boot/recovery states: `wait_time`, `wait_uplink`, `handshake`, `up`, `wg_error`.
SNTP to numeric `162.159.200.1` intentionally uses STA directly, including
periodic updates, so handshake replay timestamps survive reboot. The numeric
[Cloudflare anycast NTP address](https://developers.cloudflare.com/time-services/ntp/usage/)
avoids a direct DNS bootstrap while the kill switch blocks direct DNS.
If time cannot be synchronised, no new WireGuard tunnel starts. This control
traffic is an explicit exception to the forwarded-client full-tunnel policy.
Handshake age and `connected` indicate valid session keys, **not** a continuous
Internet reachability probe. WireGuard timers handle handshakes/rekey/retries;
the socket reconnect/queue counters do not describe WireGuard retries.

Verification: XIAO and Waveshare P4 compile checks, existing host suite, actual
HTTP handler/config validators (auth, bad/missing/zero keys, overlap, keepalive,
preserve/clear, storage failure), UI transport selection and secret clearing.
The user previously confirmed WireGuard connectivity and measured speed on XIAO.
Those results do not establish P4 support or acceptance of all subsequent fixes.
Repeat the current-build hardware checklist with a real WireGuard server; additionally check reboot
without a saved clock, wrong key/PSK, rekey and STA disconnect/reconnect. Measure
internal RAM and stack minima under concurrent USB/AP traffic before relying on
this backend for sustained use. Speed/security audit are not inferred from a
successful build.

## Experimental raw TLS

The `tls` transport uses ESP-IDF esp-tls/mbedTLS TLS 1.2, then the same framed
IPv4 stream as TCP. The matching test exit command is:

```sh
sudo env PATH="$PATH" node scripts/clean-vpn.js --role=exit --type=tls --tls-raw --server=0.0.0.0:8765
```

The board now requires verification of the exit certificate chain, DNS name and
validity dates. There is no insecure switch. An existing TLS profile without a
CA/name stops connecting after this update until those fields are provisioned.
The wire protocol remains raw TLS 1.2: no normal clean-vpn HTTP/exporter/Bearer
handshake or browser JA3/JA4 emulation. Optional client authentication is described
below. Without it, restrict access to the raw exit on the server;
certificate validation authenticates the exit, not its
clients.

In **VPN → TLS**:

1. Keep **Server IPv4:port** as the actual server address.
2. Paste the exit's trusted `ca.pem` into **Trusted exit CA**, then click **Save CA
   and reconnect TLS**. The default JS exit uses `certs/ca.pem`; with
   `--tls-cert-dir`, use that directory. Copy only the public CA certificate over
   a trusted channel, never `key.pem` or a CA private key. For a publicly issued
   server certificate, import its issuing root CA, not the server fullchain.
3. Set **TLS server name** to the DNS identity in the actual server certificate.
   It is also sent as SNI. Inspect the certificate on the exit:

   ```sh
   openssl x509 -in certs/cert.pem -noout -subject -ext subjectAltName
   ```

   A legacy generated certificate without DNS SAN uses CN `clean-vpn`; if DNS SAN
   is present, select a matching DNS SAN instead. `--tls-public-name` does not
   regenerate an existing certificate. Use the actual certificate identity, not
   an unrelated browser/public website name.
4. Enable VPN, keep the kill switch enabled, **Save and apply**, and check status.

The CA accepts certificate-only PEM bundles up to 8192 bytes, with CA basic
constraints. Invalid or partially parsed bundles, private keys and server leaf
certificates are rejected. `POST /api/vpn/tls-ca` accepts `{ "ca_pem": "..." }`
under the normal admin authentication; an empty string explicitly removes trust.
CA replacement/removal restarts an enabled TLS session. The CA is stored as one
NVS blob (`meshvpn/vpn_tls_ca`, separate from `vpn_cfg5`); using a blob avoids
NVS's 4000-byte string limit. It survives transport changes and reboots, and is
removed by factory reset. The periodic status never contains the PEM.

`vpn.tls` reports `ca_configured`, `clock_ready`, `last_handshake`, `sdk_error`,
`mbedtls_error` and `verify_flags`. `last_handshake` is the last attempt, not a
live internet test; use `vpn.connected` for the current connection. Reasons
include `certificate_name_mismatch`, `certificate_untrusted`,
`certificate_expired`, `certificate_not_yet_valid`, `handshake_failed`, and
`ca_missing_or_unreadable`. A failed validation prevents tunnel establishment;
the existing kill switch/fallback policy still applies.

TLS uses the existing board SNTP bootstrap (`162.159.200.1:123`, also used by
WireGuard). With no initialized clock, VPN stays in `wait_time`; certificate
validation is not bypassed. SDK certificate time checks are enabled explicitly
(`CONFIG_MBEDTLS_HAVE_TIME_DATE=y`) and insecure verification fallback is disabled.
This is ordinary SNTP, not an authenticated time source.

RX/TX share a mutex around the mbedTLS context, the socket is nonblocking after
the handshake, and WANT_READ/WANT_WRITE are retry conditions. Host acceptance
uses the production trust-store/connection code with a real host-mbedTLS adapter
at the ESP-TLS boundary: three fresh handshakes each for trusted CA/name,
wrong name, wrong CA, expired and future certificates. No-CA and unset-clock
preflight, CA persistence/errors, API authentication/restart, and UI edits are
covered. The real-mbedTLS duplex/framing test verifies its peer and exchanges
128 packets with fragmented TLS records. Board TLS memory peaks, throughput,
and compatibility with a running exit still require hardware acceptance.

## Configuration preservation and diagnostics

NVS `vpn_cfg5` stores the endpoint for TCP, UDP, TLS and WireGuard separately.
Versions 1–4 migrate with the active endpoint retained; endpoints overwritten by
older firmware cannot be recovered. Changing transport preserves WireGuard keys,
Address, DNS and keepalive. Private keys and PSK are never returned by status.
The API accepts optional `saved_servers` for restoring the nonsecret endpoint
map; the selected transport's `server` is authoritative. Save/apply still acts on
one selected transport. Configuration changes invalidate NAT and DNS state.

DNS cache entries and in-flight replies carry a VPN policy epoch, including
DIRECT fallback transitions. Stale replies are discarded. Final STA transmit
hooks reject direct UDP/TCP port 53 while tunnel policy is active, including
requests queued before a configuration change. An explicitly configured outer
VPN endpoint on port 53 remains allowed. DNS local names continue to resolve to
the receiving LAN gateway. IPv6 is blocked by the ingress hook; IPv6 addresses
pasted into a WireGuard profile are retained as input but are not routed.

`vpn.socket.timings` reports cumulative wall time since boot for TCP/UDP/TLS:
TX queue residence before dequeue, transport read/write calls (including would
block calls), RX callback execution, scheduler/dispatch wait before that callback,
and TLS mutex wait. Buckets are disjoint and maxima are lifetime values. These
are stage timings, not additive CPU utilization. WireGuard crypto has its own
measurements. `socket.rx_inject_exec_us` remains the total callback round-trip,
including dispatch wait; do not add it to the new component timings.

Radio status is cached by the Wi-Fi manager at most every five seconds outside
association/scans; status includes collection time, age and per-getter errors.
Reading `/api/status` does not issue Wi-Fi RPCs. AP capability flags and the
configured width do not prove the negotiated PHY mode; the explicit negotiated
mode is available only when the native/remote API supports it. The installed Waveshare C6 firmware did not answer the newer getter RPC (5-second
timeouts). P4 therefore reports NOT_SUPPORTED without issuing that request; native
XIAO still calls the getter. SDIO diagnostics distinguish
completed read/write block/register calls and driver drops from packet allocation failure,
oversized/malformed streams and payload allocation failure. Streaming RX packet
copies and delivered Wi-Fi payloads use PSRAM; the reserved stream read buffer
and SDIO TX buffers remain DMA-capable internal memory. `wifi.tx.*.netif_tx_failed` separates error 0x500e from unknown errors; in the
pinned Hosted STA path this is C6-requested TX throttling, not an SDIO I/O failure.
The existing throttle remains enabled. SDIO byte counts
include padding and control traffic; they are not internet bytes or RF retries.

Diagnostics can be paused and downloaded as JSON. A visible banner marks paused
status so a frozen "connected" label is not mistaken for a live check. Opening
the admin page reads cached scan results; a new radio scan requires the Scan button.

P4's USB TX queue uses 128 PSRAM frame slots to absorb SDIO streaming bursts;
XIAO retains eight. Both retain 50 ms pre-send expiry. These are separate from
the 256-slot VPN queue and NCM NTB pool.

Local tools, from the repository root:

```sh
IDF_PATH=~/esp/esp-idf-meshpn-v5.5.5 bash device/scripts/test-host.sh
node device/scripts/perf-stability.mjs --minutes 15 --out device/perf-results/stability-NEW
node device/scripts/vpn-local-lab.mjs --without-peer --host MAC_EXISTING_LAN_IPV4 --out device/perf-results/no-exit-NEW
node device/scripts/vpn-local-lab.mjs --host MAC_EXISTING_LAN_IPV4 --cert /tmp/lab.crt --key /tmp/lab.key --out device/perf-results/local-vpn-NEW
```

The local peer is synthetic and forwards no internet traffic. Its successful
HTTP/DNS responses cannot establish WAN performance or the public exit address.
The lab restores VPN settings in `finally`; avoid simultaneous manual edits or
another login during a test (the firmware has one active admin session).


## Optional raw TLS client authentication (mTLS)

The **JavaScript exit** supports a dedicated client CA. Existing raw TLS commands
without the flag keep their previous behavior. This is not the native exit's
configuration and is not the profiled TLS/Bearer protocol.

```sh
sudo env PATH="$PATH" node scripts/clean-vpn.js --role=exit --type=tls \
  --tls-raw --server=0.0.0.0:8765 --tls-raw-client-ca=/secure/client-ca.pem
```

The file must contain CA certificates only (up to 32 KiB). When enabled, the exit
requires a currently valid client certificate signed by this CA before attaching
the connection to the tunnel. Missing, expired and untrusted certificates are
rejected. Use a dedicated client CA: every valid client certificate it issues is
eligible; there is no per-device ACL or revocation service in this implementation.
The existing single-peer tunnel/address model is unchanged.

Example credentials, generated in a private directory on a trusted computer:

```sh
umask 077
mkdir client-credentials
cd client-credentials
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout client-ca.key -out client-ca.pem -days 3650 -subj /CN=MeshPN-client-CA \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout device.key -out device.csr -subj /CN=MeshPN-device
cat > client.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in device.csr -CA client-ca.pem -CAkey client-ca.key \
  -CAcreateserial -out device.pem -days 365 -sha256 -extfile client.ext
```

In **VPN → TLS → Client authentication**, paste `device.pem` and `device.key`,
then save. Use HTTPS admin when importing the private key. Keep `client-ca.key`
off the board and exit; the exit needs only `client-ca.pem`. Server trust remains
separate: the board still needs its exit CA, correct TLS server name and clock.

The board checks the certificate/key pair, certificate purpose and bounded PEM
format, stores the pair in one NVS blob, and reconnects active TLS. Certificate
chain limit: 8192 bytes; unencrypted private key: 4096 bytes. Client identity
persists across transport changes. Explicit removal clears both fields. A saved
but unreadable/corrupt identity fails the connection instead of falling back to
anonymous TLS. API status exposes only whether a pair is saved, never the key.
This change does not enable flash/NVS encryption; physical flash protection is a
separate deployment requirement. Temporary key buffers are wiped before freeing.

Authenticated API: `POST /api/vpn/tls-client-identity` with
`certificate_pem` and `private_key_pem`; both empty means explicit removal.
Tests cover real loopback mTLS and production storage/connection code. Memory
peaks and use on each physical board still require acceptance.
