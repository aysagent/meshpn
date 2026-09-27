import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { namespaceArgs } from './lib/browser-soak.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';

const cases = [['tls', 'host'], ['tls', 'ingress'], ['tls', 'lan'], ['boring-tls', 'ingress'], ['combo-tls', 'ingress']]
  .filter(([, scope]) => process.env.MESHPN_DNS_CLI_INGRESS_ONLY !== '1' || scope === 'ingress');
// Includes real rollback under TCG plus gateway DNS and continuous stop probes.
// This is a harness budget, not a change to client DNS/socket deadlines.
for (const [transport, dnsScope] of cases) test(`default tunnel DNS CLI: ${transport}/${dnsScope}`, { timeout: 510000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-dns-cli-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  console.error(`INGRESS_VM_START DNS ${transport}/${dnsScope}`);
  const result = await runCommand('unshare', [...namespaceArgs.map(a => a === '--map-current-user' ? '--map-root-user' : a),
    process.execPath, '--input-type=module', '-e', `
      import {runIngressRoutingLab} from './scripts/lib/ingress-routing-lab.mjs';
      console.log(JSON.stringify(await runIngressRoutingLab(${JSON.stringify({ transport, dnsScope, directory })})));
    `], { timeoutMs: 500000, env: { ...cleanEnvironment(process.env),
      MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'), MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid') } });
  if (result.reason !== null || result.code !== 0)
    console.error(`INGRESS_VM_ERROR ${JSON.stringify({ transport, dnsScope, reason: result.reason, code: result.code, stderr: result.stderr.slice(-96000) })}`);
  assert.equal(result.reason, null, result.stderr); assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'passed'); assert.equal(report.actualTransportTested, transport);
  assert.equal(report.actualDnsDefaultTested, true); assert.equal(report.scope, dnsScope);
  assert.equal(report.hostNetworkChanged, false); assert.ok(report.checks.length >= 16);
  console.log(JSON.stringify(report));
});
