import assert from 'node:assert/strict';
import test from 'node:test';
import { readlink } from 'node:fs/promises';
import { namespaceArgs } from './lib/browser-soak.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';

for (const journaled of [false, true]) for (const scope of ['host', 'ingress', 'lan']) test(`isolated tunnel DNS ${scope}${journaled ? ' journaled' : ''}: primary/backup, outage and cleanup`, { timeout: 60000 }, async () => {
  const result = await runCommand('unshare', [...namespaceArgs.map((a) => a === '--map-current-user' ? '--map-root-user' : a),
    process.execPath, '--input-type=module', '-e', `
      import {runTunnelDnsRoutingLab} from './scripts/lib/dns-tunnel-routing-lab.mjs';
      console.log(JSON.stringify(await runTunnelDnsRoutingLab({ingress:${scope === 'ingress'},lan:${scope === 'lan'},journaled:${journaled}})));
    `], { timeoutMs: 50000, env: { ...cleanEnvironment(process.env),
    MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'), MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid') } });
  assert.equal(result.reason, null, result.stderr); assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout); assert.equal(report.status, 'passed');
  assert.equal(report.hostNetworkChanged, false); assert.equal(report.transportEncryptionTested, false);
  assert.equal(report.scope, scope); assert.equal(report.checks.length, (scope === 'host' ? 8 : 9) + (journaled ? 3 : 0)); console.log(JSON.stringify(report));
});
