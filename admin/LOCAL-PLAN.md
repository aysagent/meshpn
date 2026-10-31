# Native continuation, 2026-10-28

Current continuation, **2026-10-31**: the dated checkpoints below are historical.
Native combo autostart is installed on the personal Radxa/VPS pair; see the
[current physical state](../scripts/clean-vpn-native-combo-daily-20261031.md).
The later [broker sandbox repair](../scripts/clean-vpn-native-admin-repair-20261031.md)
is installed and physically checked: save/stop/start and guard off/direct USB
DNS/HTTPS work. Transport switching in the UI remains unimplemented; the label
now reflects the actual configuration. New native/profile/UI work is tracked in
[the 31 October queue](../scripts/clean-vpn-native-night-20261031.md) and
[its report](../scripts/clean-vpn-native-night-20261031-report.md), with separate
artifact hashes and lab/physical boundaries. Follow those links for the current
step; do not restart the old legacy-migration work from this historical list.

The user subsequently made Radxa available and authorized physical checks.
Temporary checks on Radxa/VPS are recorded in the
[binary-update acceptance report](../scripts/clean-vpn-native-update-report.md).
No Mac network/clock/trust changes. dnsmasq migration remains research-only.
Permanent native deployment and physical boot are separate acceptance steps.

Latest checkpoint: [installed clock/update with existing Radxa owners](../scripts/clean-vpn-native-installed-lifecycle.md).
Both physical smoke runs passed, including binary updates and rollback with
DNS/HTTPS; native SNAT readiness is explicit. The combined installed clock/update
boot matrix passed 49 gates across three kernels. The network owner used in the
physical pilot is still temporary. Next: package its persistent lifecycle,
journal the legacy/native activation and SNAT switch, then test migration and
physical boot. Do not describe this checkpoint as completed native autostart.

OpenWrt research is recorded in [the OpenWrt integration plan](../scripts/clean-vpn-openwrt.md).
Scope: locally installed native client/exit packages and LuCI feature parity,
including browser capture, profile selection and independent pcap observation.
No public feed submission; no OpenWrt implementation or acceptance claimed yet.
This is an additional platform track, not completion of the checkpoints below.

## Order and acceptance

1. Durable native settings apply: validate before changing live files; journal
   old/new config and UI settings; preserve stopped VPN; require a ready native
   notify service and active guard; restore after failure or interrupted broker;
   refuse to overwrite concurrent/manual edits. Test write boundaries and failed
   rollback. Recovery must complete before accepting broker requests.
2. Real systemd lab: frontend → UNIX broker → native client/exit and guard;
   successful profile change, bad TLS identity rollback, broker crash recovery,
   stopped-service preservation. Extend to container frontend and USB-like socket
   binding; report mock versus real components explicitly.
3. Native installation/update and legacy-owner migration: review ownership,
   immutable releases, durable activation/rollback, secrets/replay retention;
   interrupted update and cold-boot checks in VM before physical instructions.
   Binary-only updates for a fresh named boring-tls installation are now checked;
   existing-host legacy-owner migration is still outstanding.
4. Configurable native DNS upstreams, validation and no direct fallback.
5. Wi-Fi profile recovery/failure matrix, followed by capture/profile/independent
   observer workflow. Radio/real WAN acceptance remains physical.

Each completed checkpoint records actual commands, results and limitations here
or in a linked report. Earlier NIGHT-REPORT.md is historical evidence, not proof
of new changes. No claim of production migration until its own gates pass.

## Checkpoint

- Durable settings transaction implemented; 38/38 API/profile/lab-parser and
  transaction regressions pass, including abrupt process death at five durable
  boundaries and rollback failure with its journal retained.
- Real ARM64 Podman frontend/broker/native matrix: 9/9, including USB-like
  device binding and SIGKILL during TLS activation. See
  [container evidence](test/last-container-report.json).
- NIC-less QEMU standalone API/broker/native acceptance: 8/8, including SIGKILL,
  native recovery and renewed login after frontend restart. See
  [QEMU evidence](test/last-qemu-report.json). Native binary CTest: 10/10.
- Existing-host legacy migration remains outstanding; config rollback must not
  be described as binary-update rollback. The separate
  binary-update checkpoint passed 21 local tests, 18 regressions and 8 real
  isolated checks per device, plus 46 gates across three QEMU boots. Full
  Radxa/VPS profile smoke and legacy restoration passed on repeat; the first
  restored-legacy download timeout remains recorded. See the linked report.
