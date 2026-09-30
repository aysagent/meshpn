import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readlink } from 'node:fs/promises';
import { namespaceArgs } from './lib/browser-soak.mjs';
import { runCommand } from './lib/transparent-acceptance.mjs';

test('real TLS IPv6 over IPv4: NAT66, fallback, cleanup and crash guard', { timeout: 1500000 }, async () => {
  const directory = await mkdtemp('/tmp/meshpn-ipv6-lab-');
  const r = await runCommand('unshare', [...namespaceArgs.map(a => a === '--map-current-user' ? '--map-root-user' : a), process.execPath,
    '--input-type=module', '-e', `import {runIpv6Lab} from './scripts/lib/vpn-ipv6-lab.mjs'; console.log(JSON.stringify(await runIpv6Lab(${JSON.stringify(directory)}, {resilience:${process.env.MESHPN_HOST_RESILIENCE === '1'},joint:${process.env.MESHPN_HOST_JOINT === '1'}})));`],
  { timeoutMs: 1490000, maxBytes: 256 * 1024,
    onStderr: text => process.stderr.write(text), env: { ...process.env,
    MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'), MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid') } });
  if (r.code !== 0 || r.reason) console.error(`INGRESS_VM_ERROR ${JSON.stringify(r)}`);
  assert.equal(r.reason, null); assert.equal(r.code, 0, r.stderr);
  const report = JSON.parse(r.stdout); assert.equal(report.status, 'passed'); console.log(JSON.stringify(report));
});
