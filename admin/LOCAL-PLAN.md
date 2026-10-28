# Local-only continuation, 2026-10-28

No SSH to Radxa/VPS, no Mac network/clock/trust changes. Linux tests run only
in the dedicated Podman/QEMU lab. dnsmasq migration remains research-only.
Physical deployment is a separate acceptance step.

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
- Installer/release updates and legacy migration are still separate work;
  config rollback must not be described as binary-update rollback.
