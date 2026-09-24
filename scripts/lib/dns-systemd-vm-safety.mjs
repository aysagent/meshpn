/** VM-only authority gate. This is not a live-client opt-in switch. */
import assert from 'node:assert/strict';
import { readFile, readlink, readdir } from 'node:fs/promises';
import { vmBootOptions } from './dns-vm-protocol.mjs';

export async function assertSystemdDnsVm() {
  const options = vmBootOptions(await readFile('/proc/cmdline', 'utf8'));
  assert.equal(options.phase, 'systemd'); assert.equal(options.point, 'lifecycle');
  assert.match(await readFile('/sys/class/dmi/id/sys_vendor', 'utf8'), /^QEMU\s*$/);
  assert.equal((await readFile('/proc/1/comm', 'utf8')).trim(), 'systemd');
  assert.equal(process.getuid(), 0);
  assert.ok((await readdir('/sys/class/net')).every((name) => ['lo', 'dnsfixture'].includes(name)), 'unexpected guest NIC');
  for (const namespace of ['net', 'mnt', 'pid']) {
    assert.equal(await readlink(`/proc/self/ns/${namespace}`), await readlink(`/proc/1/ns/${namespace}`));
  }
  return options;
}
