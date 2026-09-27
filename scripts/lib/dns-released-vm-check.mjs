/** Read-only collector worker after the REAL installed controller lifecycle.
 * No synthetic journal creation. Only the explicit NIC-less VM may run it. */
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { assertCoupledDnsVm } from './dns-systemd-vm-safety.mjs';
import { createDnsSystemCommands } from './dns-system-command.mjs';
import { inspectReleasedDnsDeployment, inspectQuiescentDnsDeployment } from './dns-deployment-inactive.mjs';

export async function inspectReleasedDnsVm({ quiescent = false } = {}) {
  const gate = async () => {
    const options = await assertCoupledDnsVm();
    assert.equal(options.phase, 'coupled'); assert.ok(['installed-released', 'installed-quiescent'].includes(options.point));
    assert.equal(typeof quiescent, 'boolean'); if (quiescent) assert.equal(options.point, 'installed-quiescent');
  };
  await gate();
  const commands = await createDnsSystemCommands({ assertAuthority: gate,
    required: ['ip', 'busctl', 'systemctl', 'iptables', 'ip6tables'] });
  return (quiescent ? inspectQuiescentDnsDeployment : inspectReleasedDnsDeployment)({ commands,
    input: { schema: 1, client: 'vps2', id: 'b'.repeat(32) }, firewallBackend: 'legacy' });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  assert.ok(process.argv.length === 2 || process.argv.length === 3 && process.argv[2] === '--quiescent');
  inspectReleasedDnsVm({ quiescent: process.argv.length === 3 }).then((v) => console.log(JSON.stringify(v))).catch((e) => { console.error(e.stack); process.exitCode = 1; });
}
