/** Metadata-only preflight. Never starts a VM or uses the host's initramfs/disks. */
import { access, lstat, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { isAbsolute } from 'node:path';
import assert from 'node:assert/strict';

export function dnsVmPreflightOptions(args) {
  const options = { qemu: '/usr/bin/qemu-system-x86_64', kernel: '/boot/vmlinuz' }, seen = new Set();
  for (const arg of args) {
    const match = /^--(qemu|kernel|initrd|disk)=(.+)$/.exec(arg);
    assert.ok(match && !seen.has(match[1]), 'invalid or duplicate preflight argument');
    assert.ok(isAbsolute(match[2]) && match[2].length <= 4096 && !/[\x00-\x1f]/.test(match[2]), 'absolute local path required');
    seen.add(match[1]); options[match[1]] = match[2];
  }
  return options;
}
export async function dnsVmPreflight(options = dnsVmPreflightOptions([])) {
  const artifacts = {};
  for (const name of ['qemu', 'kernel', 'initrd', 'disk']) {
    const path = options[name];
    if (!path) { artifacts[name] = { status: 'not-supplied' }; continue; }
    assert.ok(isAbsolute(path));
    try {
      const metadata = await lstat(path);
      // Never accept a writable guest disk alias or an arbitrary host block device.
      if (name === 'disk' && !metadata.isFile()) { artifacts[name] = { status: 'unsafe-type' }; continue; }
      const target = await stat(path);
      if (!target.isFile() || target.size === 0) { artifacts[name] = { status: 'invalid-file' }; continue; }
      await access(path, constants.R_OK | (name === 'qemu' ? constants.X_OK : 0));
      artifacts[name] = { status: 'present', bytes: target.size };
    } catch (error) { artifacts[name] = { status: error.code === 'ENOENT' ? 'missing' : 'unavailable' }; }
  }
  const missing = Object.entries(artifacts).filter(([, value]) => value.status !== 'present').map(([name]) => `${name}-required`);
  let kvmPresent = false;
  try { kvmPresent = (await lstat('/dev/kvm')).isCharacterDevice(); } catch { /* TCG does not require KVM. */ }
  return { schema: 1, kind: 'dns-vm-preflight', mode: 'read-only', systemDnsChanged: false, vmStarted: false,
    artifacts, kvmPresent, plannedAcceleration: 'tcg', blockers: missing,
    // File existence never attests origin, guest contents, ownership or safe QEMU arguments.
    launchAuthorized: false, artifactVerificationRequired: true,
    requiredIsolation: ['no-network-device', 'no-host-shared-filesystem', 'no-host-block-device', 'private-copy-of-guest-disk', 'bounded-runtime'],
    limitations: ['metadata-only', 'no-signature-or-hash-verification', 'no-guest-boot', 'no-systemd-ordering-test', 'no-reboot-or-power-loss-test'] };
}
