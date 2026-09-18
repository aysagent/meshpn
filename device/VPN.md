# Experimental device VPN

## socket (clean-vpn)

The firmware implements `socket`: TCP carrying `[uint32 big-endian length][IPv4]`.
There is **no authentication or encryption**. Use a dedicated test exit restricted
by firewall to your trusted client address/network. Never expose an unrestricted
socket exit on the public Internet. No server protocol changes are required.

Contract checked against `scripts/clean-vpn.js` at
`a49b0baf56db7804b34b6126d8614cecb7050466`: client `10.99.0.2`, peer `10.99.0.1`,
MTU 1400; no handshake or HTTP preamble. The firmware accepts only IPv4
TCP/UDP/ICMP, limits each framed packet to 1400 bytes and closes malformed streams.
Future TLS/profile/auth vectors in plan stage 0 remain deferred, not claimed tested.

On the **dedicated, firewall-restricted exit**, from the project directory:

```sh
sudo env PATH="$PATH" node scripts/clean-vpn.js --role=exit --type=socket --server=0.0.0.0:8765 --keep-alive=0
```

In the device admin VPN section select socket, enter the exit's **numeric IPv4:port**,
acknowledge plaintext, enable and save. Changes apply without reboot and persist.
Disable VPN to return to DIRECT. TLS transports are not implemented here yet.

All forwarded Internet traffic from both USB and AP goes through a virtual lwIP
interface and existing NAPT. LAN-local traffic/admin/DHCP remain local. The outer
TCP socket binds the STA address, avoiding tunnel recursion. While enabled but
disconnected, the default **Kill switch ON** keeps the virtual route selected and
drops packets. Turning kill switch OFF explicitly permits DIRECT fallback while
disconnected, for both socket and WireGuard. Turning **Enable VPN OFF** always
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
  five-second timeout, bound to the virtual VPN interface and source address. It
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

These behaviours are host-tested and compile-tested; packet capture on real
hardware is still required to verify both transports and kill switch transitions.

The queue holds 16 packets in PSRAM, drops entries older than 1 second, and cannot
grow with traffic. Partial frame/write deadlines are 5 seconds. Connect timeout
is 5 seconds, reconnect backoff 1–16 seconds; TCP keepalive detects idle failures.
`connected` means **outer TCP established**, not a verified working Internet exit.
TX counts complete writes to TCP, not delivery to the destination application.
MSS options in SYN packets are clamped to 1360; fragmented IPv4 is reassembled
before NAPT. Native lwIP NAPT limitations (including ICMP error translation)
still apply. Packet capture is required for the acceptance checks below.

## Verification status / hardware acceptance

Automated: firmware build for XIAO; host sanitizers; all frame split boundaries,
coalescing/bad lengths/truncation; real clean-vpn JS ↔ C framing; MSS checksum
changes with odd/even option alignment; production routing selector tests; UI
save/disable/plaintext confirmation/poll edit preservation. These are not a
substitute for running the worker and NAPT on the board.

**Pending, requires connected hardware and a real exit/TUN:**

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

At implementation time the Linux workspace has no board/remote configuration and
no `/dev/net/tun`; stages 1–2 hardware acceptance remains **unverified**.

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
Address = 10.0.0.7
DNS = 1.1.1.1

[Peer]
PublicKey = <server public key>
Endpoint = <numeric server IPv4>:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

For a source profile with `Address = 10.0.0.7/24,fd42:42:42::7/64`, enter
only `10.0.0.7` in this UI. Do not change the original profile: the device backend
uses /32 internally and does not support IPv6. `AllowedIPs` is read-only; `::/0`
is not used. Optional `PresharedKey` controls follow the main peer fields.

Field details:

- Server: numeric IPv4 and UDP port, e.g. `192.0.2.1:51820`.
- Device tunnel address: the IPv4 from its WireGuard profile, without CIDR suffix;
  this version installs a /32. It must not overlap the USB/AP or uplink subnet.
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

Boot/recovery states: `wait_time`, `wait_uplink`, `handshake`, `up`, `wg_error`.
SNTP to `pool.ntp.org` (and its bootstrap DNS) intentionally uses STA directly,
including periodic time updates, so handshake replay timestamps survive reboot.
If time cannot be synchronised, no new WireGuard tunnel starts. This control
traffic is an explicit exception to the forwarded-client full-tunnel policy.
Handshake age and `connected` indicate valid session keys, **not** a continuous
Internet reachability probe. WireGuard timers handle handshakes/rekey/retries;
the socket reconnect/queue counters do not describe WireGuard retries.

Verification: XIAO and Waveshare P4 compile checks, existing host suite, actual
HTTP handler/config validators (auth, bad/missing/zero keys, overlap, keepalive,
preserve/clear, storage failure), UI transport selection and secret clearing.
**No hardware handshake/throughput claim yet.** Repeat the socket hardware
acceptance checklist with a real WireGuard server; additionally check reboot
without a saved clock, wrong key/PSK, rekey and STA disconnect/reconnect. Measure
internal RAM and stack minima under concurrent USB/AP traffic before relying on
this backend for sustained use. Speed/security audit are not inferred from a
successful build.
