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
disconnected, the virtual route remains selected and drops packets; it never
falls back to STA. IPv6 remains blocked by the existing ingress policy.
DNS proxy uses 1.1.1.1 through the VPN (numeric exit eliminates bootstrap DNS).
Applying settings clears DNS cache and NAPT mappings: restart existing client
connections. Independently initiated device services other than this DNS proxy
are not full-tunnelled.

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
