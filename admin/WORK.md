# Radxa administration / overnight work 2026-10-28

Requested: (1) integrate conditional native clock with existing Radxa route/DNS owners and bounded physical check with rollback; (2) read-only dnsmasq → systemd assessment; (3) USB-only Node API + UI, systemd and containers, password admin/change, Wi-Fi profiles, VPN/guard/settings, metrics/logs/probes, browser profile/capture and independent wire observer. Do not change Mac networking. Commit on Mac, transfer via Git. No permanent native VPN migration tonight. DNS migration is research only.

Baseline: Radxa 192.168.7.1 rescue SSH 2222, root, existing native trial/legacy/guard/USB owners. VPS 154.62.226.216, root, no running clean-vpn exit. Radxa networkd/netplan + netplan-wpa-wlan0, resolved disabled, dnsmasq USB and pan0, Avahi active. Broken resolv.conf symlink. 2 duplicate DHCP DNS options. Current clock good. Password SSH uses private ControlMaster /private/tmp/cvpn-admin-night-20261028.sock. No credentials in repository.

Implementation direction: separate unprivileged HTTP UI/API and restricted local broker for system actions. Explicit USB address/interface, host/origin validation, password hashes, revocable sessions/CSRF, bounded operations, no shell commands or arbitrary paths in API. Reuse native profile/observer parsers. Systemd socket can bind to USB device; container uses host broker, no Docker socket or privileged container. Preserve unsupported features as explicit capabilities. Keep UI distinct from ESP firmware.

Outstanding:
- [ ] physical existing-owner clock integration + smoke/rollback
- [ ] DNS/DHCP migration assessment only
- [ ] backend and authentication
- [ ] bounded host actions/Wi-Fi owner integration
- [ ] UI metrics/settings/profiles/capture/observer
- [ ] systemd and container packaging
- [ ] API/security/integration/browser/lab checks
- [ ] temporary Radxa admin smoke, rollback, report
- [ ] commits/push and final report
