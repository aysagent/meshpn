/** Read-only collector worker after the REAL installed controller lifecycle.
 * No synthetic journal creation. Only the explicit NIC-less VM may run it. */
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { assertCoupledDnsVm } from './dns-systemd-vm-safety.mjs';
import { createDnsSystemCommands } from './dns-system-command.mjs';
import { inspectReleasedDnsDeployment } from './dns-deployment-inactive.mjs';

export async function inspectReleasedDnsVm() {
  const gate = async () => {
    const options = await assertCoupledDnsVm();
    assert.equal(options.phase, 'coupled'); assert.equal(options.point, 'installed-released');
  };
  await gate();
  const commands = await createDnsSystemCommands({ assertAuthority: gate,
    required: ['ip', 'busctl', 'systemctl', 'iptables', 'ip6tables'] });
  return inspectReleasedDnsDeployment({ commands,
    input: { schema: 1, client: 'vps2', id: 'b'.repeat(32) }, firewallBackend: 'legacy' });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length, 2);
  inspectReleasedDnsVm().then((v) => console.log(JSON.stringify(v))).catch((e) => { console.error(e.stack); process.exitCode = 1; });
}
