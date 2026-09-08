# Current improvements and acceptance checks

Revision: 2026-09-08. Implementation is in the tree; this environment has no attached board.
The historical 8.13/6.5 Mbps result is **not** a measurement of this revision.
USB compatibility expansion and VPN/WireGuard implementation are deferred.

## Implemented

- Up to 16 versioned NVS WiFi profiles, migration from the old single network, secret-free saved-network list,
  add/edit/delete/select, priorities, enabled/hidden flags and open/WPA2/WPA3 Personal.
  Automatic selection retains a working connection; failures fall through to other candidates with bounded backoff.
- Opening the admin page starts a scan automatically. The button repeats it; scans wait for association/DHCP to complete.
- Two-second visible-page status polling: temperature, internal/DMA/PSRAM free/minimum/largest blocks,
  flash/PSRAM size, stack high-water mark, build ID, USB/DNS counters and certificate fingerprint.
- HTTPS-only login and management API, persistent per-device EC identity, authenticated certificate import,
  USB-only mDNS and management ingress filter. Plain HTTP only redirects; IPv6 is disabled.
- Non-empty expiring sessions, logout/password-change revocation, login throttling and bounded request parsing.
  `CONFIG_MESHVPN_WEB_REQUIRE_PASSWORD_CHANGE` defaults to **n** for testing. Set it to **y** to require changing the configured initial password before configuration mutations.
- UDP/TCP DNS proxy with response correlation, uplink resolver, TCP fallback and bounded positive TTL cache.
  No connectivity-domain hijacking or captive-portal advertisement.
- USB subnet conflict detection and reassignment; DHCP renewal/replug may be required on the host.
- Offline IPv4 range compiler and temporary synthetic PSRAM lookup benchmark, **not routing enforcement**.
- Pinned dependency lock and separate profile/defaults build directories. The manager applies iot_bridge lwIP patches to the IDF checkout.

## Software checks

```bash
bash device/scripts/test-host.sh
# Include identity generation/persistence/import against IDF's mbedTLS:
IDF_PATH=/path/to/esp-idf-v5.4.1 bash device/scripts/test-host.sh
```

Requires C compiler with ASan/UBSan, Node.js and bash; the TLS test additionally requires CMake and OpenSSL 3.
Tests cover DNS name/bounds/compression/TTL handling, binary-search boundaries, CIDR compilation,
actual ingress hook with chained pbufs/fragments, session validation, UI JavaScript syntax and DOM references,
TLS identity persistence, matching-key validation and personal-CA certificate import.
The TLS test uses an in-memory NVS stub, not actual flash/power-loss tests.

The ESP-IDF 5.4.1 NCM firmware builds with the locked dependencies, with mandatory password change both enabled and disabled.
The image is approximately 1.1 MiB in a 3 MiB app partition.
The generated lwIP customer hook and linked image include the management filter.
Build success and unit tests do not establish radio/USB timing, handshake stack headroom, runtime RAM or throughput.
The previously flashed board's resolved dependency versions are unknown; preserve its working image/configuration before comparison.

## Hardware acceptance

1. **First boot and recovery:** USB DHCP and HTTPS login work with no saved network or uplink.
   Verify the unique fingerprint using a trusted connection; reboot preserves it. Hold BOOT for five seconds to reset NVS and identity.
   Confirm recovery if HTTPS startup fails. See [HTTPS setup](admin-https.md).
2. **WiFi profiles:** migrate an existing SSID; list shows no passwords; edit priority without changing the password;
   add/delete/disable profiles, reboot and verify persistence. Test both visible networks, only the lower-priority network,
   neither network, bad password at higher priority, hidden SSID and WPA3. A working network is not pre-empted by a better priority.
3. **Scan and reconnect:** open the admin page while offline, online and associating; automatic scan produces a list;
   the button repeats it. Pause prevents reconnect, resume re-enables it. Reboot the router and change its DNS server.
4. **Telemetry and load:** status refreshes every two seconds without resetting form input. Record temperature,
   internal/DMA/PSRAM minimum free and largest blocks during NAT, scanning and multiple HTTPS tabs. Run for 30–60 minutes.
5. **Authentication:** empty/malformed/expired Bearer fails; logout and password change revoke the token;
   repeated bad logins are delayed. Check mandatory-change option both disabled and enabled. A new login replaces the previous session.
6. **Network isolation:** from a separate WiFi client probe the dongle's STA IP on TCP 80/443/53 and UDP 53/5353/32768/32769;
   management must not answer. Repeat with a route to the USB IP through STA. On USB, HTTPS/DNS must work.
   Capture uplink multicast: no dongle mDNS announcements on STA. Repeat after reconnect and address changes.
7. **Names and trust:** test `meshpn.local` on iPhone/macOS and `meshpn.home.arpa` via the supplied DNS.
   Import a personal-CA leaf/key, reboot, verify browser trust and fingerprint. With multiple dongles, check mDNS name conflicts;
   hostname/certificate collision handling beyond a single dongle is not implemented.
8. **Subnet collision:** place uplink in 192.168.7.0/24. Check reassignment, renew host DHCP/replug, resolve the name and verify NAT.
   The new IP is not necessarily covered by the certificate; use the DNS name. Subnet selection is recalculated after reboot.
9. **DNS:** test UDP/TCP queries, repeated cache hits with decreasing TTL, large EDNS responses, upstream failure and recovery.
   Confirm normal connectivity checks; this is not an uplink captive-portal login implementation.
10. **Memory and speed:** run UI benchmark at 10k/100k/500k, verify memory returns after completion.
    Repeat [baseline throughput/stability checks](benchmark-gonogo.md) with HTTPS polling. Record IDF, lockfile, profile and binary.

## Limits and next decisions

Only IPv4 NAT is implemented. VPN and policy-editing endpoints report unsupported rather than silently claiming enforcement.
The list compiler produces membership ranges (8 bytes each), not action/priority rules; 100k ranges need about 0.763 MiB,
500k about 3.815 MiB, plus replacement/index/cache overhead. Runtime feasibility depends on measured memory reserves.
The benchmark reserves at least 2 MiB PSRAM at allocation time, runs synthetic lookups and frees its buffer; it neither installs a list nor benchmarks VPN.

Flash has a 1 MiB unused storage partition and 3.875 MiB unpartitioned space. No filesystem mounting or OTA is implemented.
NVS stores passwords/private keys without at-rest encryption; secure boot/flash encryption are a separate deployment choice.
The self-signed first connection is not automatically trusted. HTTP redirects alone do not authenticate it.
Three HTTPS clients and one active admin session are intentional resource limits; verify browser socket behaviour on hardware.
WiFi is 2.4 GHz Personal/open only, not Enterprise. No universal OS compatibility, encrypted-DNS domain routing or VPN leak prevention is claimed.
