# Device name and offline setup portal — 28 October 2026

Implemented, committed and installed on bound P4 **E8F60AE395D0**. Final firmware
reports **7551a3d-dirty**, boot 1126, `dongle.local`, STA connected, AP active,
VPN off and `captive_portal=false`. No Mac Wi-Fi association, router, firewall,
C6 firmware or Camic/XIAO programming was changed.

## Changes

The default name is now `dongle.local`, including upgrades without a saved name.
Admin → Device name supports immediate mDNS/DNS updates and NVS persistence.
Status, UI links, HTTPS redirects and generated/imported certificate checks use
the configured name. Input accepts a single ASCII DNS label or its `.local`
form. Existing certificates remain loadable and are preserved on rename; a
name mismatch is shown in the admin. Long DNS names use correct DER SAN lengths.
The CA-generation helper accepts a custom name, and performance tooling learns
the name from discovery/status rather than assuming the old default.

Without STA IPv4, the LAN DNS proxy returns its ingress gateway with TTL zero
for A questions, bypassing its cache. Other query types get no fabricated IPv4
answer. Unknown HTTP GETs redirect to the gateway login page. Successful STA
IPv4 acquisition disables setup DNS and redirects. VPN failure alone does not
trigger the setup portal. Admin authentication and kill-switch rules remain.

This is legacy DNS/HTTP captive detection. No plaintext DHCP option 114 CAPPORT
endpoint is advertised, and external HTTPS is not intercepted. Phone popup
behavior was **not physically verified**; OS policy still controls presentation.
See [setup behavior and HTTPS limitations](../docs/admin-name-and-setup.md).

## Verification

* Full host suite passed, including ASan/UBSan checks for hostname validation,
  persistence/error handling, captive DNS gateway/TTL/AAAA/online behavior,
  setup-only HTTP redirects and UI edit/save behavior. TLS tests cover name
  mismatch after rename, identity preservation and a 63-character label SAN.
* Performance runner/local tests: **41 passed** after the default/SNI changes.
* P4 and XIAO cross-builds passed on ESP-IDF 5.5.5. XIAO was build-only.
* Both P4 flashes entered ROM, wrote/verified images and returned to application
  USB on their first attempt, with no buttons or unplugging. The first refreshed
  existing code (`fe98061`); the second installed this feature.
* Hardware admin: the hostname endpoint rejected unauthenticated changes with
  401 and invalid names with 400. The new UI was served successfully.
* UDP and TCP local DNS returned `192.168.10.1` for `dongle.local`. macOS system
  mDNS resolved the board; direct USB unicast mDNS on UDP 5353 also returned its
  USB address. Renaming to `Dongle-Test.local` normalized to `dongle-test.local`
  and worked via DNS/mDNS without reboot.
* A software reboot advanced boot 1125 → 1126 and retained the custom name.
  The test then restored and saved `dongle`.
* The test paused only the board's STA manager. Setup mode activated; Apple DNS
  queries over UDP/TCP returned the USB gateway with TTL 0, and AAAA had no
  fabricated answer. `/hotspot-detect.html`, `/generate_204` and `/connecttest.txt`
  each returned 302 / `http://192.168.10.1/login` with no-store. Login returned 200.
* Automatic STA selection was restored in cleanup. Uplink reconnected and
  `captive_portal` became false. A direct local `/generate_204` returned 404,
  and an external DNS query was forwarded without a gateway substitution.
* Final `http://dongle.local/login` returned 200 via `192.168.10.1`. A separate
  HTTPS request to example.com bound to USB source `192.168.10.2` returned 200.

The private test harness needed two corrections before completing: a helper
name initially shadowed Python's HTTP module, and an assertion incorrectly
expected macOS to return every interface address for one system mDNS lookup.
The corrected checks accept a valid board address and separately verify USB
unicast mDNS. A raw USB multicast probe timed out; it is not counted as a pass
or used to diagnose the firmware. No firewall change was made.

Private artifacts: `device/perf-results/p4-name-setup-nwomaxut/`, including frozen
images, build/flash logs, `verification.json`, per-state snapshots and harness
logs. The earlier refresh is in `p4-refresh-zbzybz5x/`. Keys, session tokens and
raw status are not committed. Real phone AP/USB captive-window acceptance and
the earlier intermittent AP/STA throughput regression remain separate work.
