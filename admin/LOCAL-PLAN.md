# Native continuation, 2026-10-28

The user subsequently made Radxa available and authorized physical checks.
Temporary checks on Radxa/VPS are recorded in the
[binary-update acceptance report](../scripts/clean-vpn-native-update-report.md).
No Mac network/clock/trust changes. dnsmasq migration remains research-only.
Permanent native deployment and physical boot are separate acceptance steps.

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
