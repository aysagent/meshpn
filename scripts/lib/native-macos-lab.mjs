import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export const nativeMacLabModes = Object.freeze([
  '--native-only', '--native-systemd', '--native-boot', '--native-routes',
  '--native-network', '--native-site-boot', '--native-transparent-boot',
  '--native-combo-network', '--native-combo-boot', '--native-combo-load',
  '--native-combo-benchmark',
]);

const machinePattern = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/;

export function parseNativeMacLabArgs(argv, env = process.env) {
  const value = {
    action: null,
    machine: env.CVPN_PODMAN_MACHINE || 'meshpn-clean-vpn-lab',
    rebuildImage: false,
    refreshBase: false,
  };
  for (const arg of argv) {
    if (arg === '--prepare' || arg === '--multi-clients' || arg === '--tls-profiles' || arg === '--status' || arg === '--stop' || arg === '--help' || nativeMacLabModes.includes(arg)) {
      assert.equal(value.action, null, 'choose exactly one lab action');
      value.action = arg;
      continue;
    }
    if (arg === '--rebuild-image') { assert.equal(value.rebuildImage, false, 'duplicate --rebuild-image'); value.rebuildImage = true; continue; }
    if (arg === '--refresh-base') { assert.equal(value.refreshBase, false, 'duplicate --refresh-base'); value.refreshBase = true; continue; }
    const machine = /^--machine=(.+)$/.exec(arg);
    if (machine) { assert.match(machine[1], machinePattern, 'invalid Podman machine name'); value.machine = machine[1]; continue; }
    throw new Error(`unknown lab option: ${arg}`);
  }
  value.action ??= '--status';
  assert.match(value.machine, machinePattern, 'invalid Podman machine name');
  assert.ok(!value.refreshBase || value.action === '--prepare' || nativeMacLabModes.includes(value.action), '--refresh-base requires prepare or a VM mode');
  assert.ok(!value.rebuildImage || value.action !== '--stop', '--rebuild-image is incompatible with --stop');
  return value;
}

export function nativeMacLabImageTag(containerfile) {
  const digest = createHash('sha256').update(containerfile).digest('hex').slice(0, 16);
  return `localhost/meshpn-clean-vpn-lab:${digest}`;
}

export function nativeMacLabContainerAction(action) {
  if (action === '--tls-profiles') return ['tls-profiles'];
  if (action === '--multi-clients') return ['multi-clients'];
  if (action === '--prepare') return ['prepare'];
  if (action === '--status') return ['status'];
  assert.ok(nativeMacLabModes.includes(action), 'VM mode required');
  return ['run', action];
}

export function nativeMacLabMachineInitArgs(machine) {
  assert.match(machine, machinePattern);
  return ['machine', 'init', '--provider=applehv', '--cpus=6', '--memory=6144', '--disk-size=100', '--rootful', machine];
}
