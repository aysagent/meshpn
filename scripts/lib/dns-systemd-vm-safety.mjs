/** VM-only authority gate. This is not a live-client opt-in switch. */
import assert from 'node:assert/strict';
import { readFile, readlink, readdir } from 'node:fs/promises';
import { vmBootOptions } from './dns-vm-protocol.mjs';

export async function assertSystemdDnsVm() {
  const options = vmBootOptions(await readFile('/proc/cmdline', 'utf8'));
  const coupled = ['coupled', 'coupled-cut', 'coupled-inspect'].includes(options.phase);
  assert.ok(coupled || options.phase === 'systemd');
  assert.match(await readFile('/sys/class/dmi/id/sys_vendor', 'utf8'), /^QEMU\s*$/);
  assert.equal((await readFile('/proc/1/comm', 'utf8')).trim(), 'systemd');
  assert.equal(process.getuid(), 0);
  assert.ok((await readdir('/sys/class/net')).every((name) => ['lo', 'dnsfixture'].includes(name)
    || (coupled && /^cvdns[a-f0-9]{8}$/.test(name))), 'unexpected guest NIC');
  for (const namespace of ['net', 'mnt', 'pid']) {
    assert.equal(await readlink(`/proc/self/ns/${namespace}`), await readlink(`/proc/1/ns/${namespace}`));
  }
  return options;
}

export async function assertCoupledDnsVm() {
  const options = await assertSystemdDnsVm();
  assert.ok(['coupled', 'coupled-cut', 'coupled-inspect'].includes(options.phase));
  return options;
}
