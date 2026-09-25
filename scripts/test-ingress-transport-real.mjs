import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { namespaceArgs } from './lib/browser-soak.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';

const transports = process.env.MESHPN_INGRESS_TEST_TRANSPORTS?.split(',') ?? ['tls', 'boring-tls', 'transparent-tls', 'combo-tls'];
const timeoutMs = process.env.MESHPN_INGRESS_VM === '1' ? 180000 : 50000;
for (const transport of transports) test(`real clean-vpn --from-tun: ${transport}`, { timeout: timeoutMs + 10000 }, async (t) => {
  if (process.env.MESHPN_INGRESS_VM === '1') console.error(`INGRESS_VM_START ${transport}`);
  assert.ok(['tls', 'boring-tls', 'transparent-tls', 'combo-tls'].includes(transport));
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-ingress-cli-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const result = await runCommand('unshare', [...namespaceArgs.map((a) => a === '--map-current-user' ? '--map-root-user' : a),
    process.execPath, '--input-type=module', '-e', `
      import {runIngressRoutingLab} from './scripts/lib/ingress-routing-lab.mjs';
      console.log(JSON.stringify(await runIngressRoutingLab({transport:${JSON.stringify(transport)},directory:${JSON.stringify(directory)}})));
    `], { timeoutMs, env: { ...cleanEnvironment(process.env),
      MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'), MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid') } });
  assert.equal(result.reason, null, result.stderr); assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'passed'); assert.equal(report.actualTransportTested, transport);
  assert.equal(report.hostNetworkChanged, false); assert.ok(report.checks.length >= 12);
  console.log(JSON.stringify(report));
});
