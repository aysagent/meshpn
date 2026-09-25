import assert from 'node:assert/strict';
import test from 'node:test';
import { readlink } from 'node:fs/promises';
import { namespaceArgs } from './lib/browser-soak.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';

test('isolated routing: ingress, host, other interface, DNS/IPv6, HTTPS scope, cleanup and crash', { timeout: 60000 }, async () => {
  const result = await runCommand('unshare', [...namespaceArgs.map((a) => a === '--map-current-user' ? '--map-root-user' : a), process.execPath, '--input-type=module', '-e', `
    import {runIngressRoutingLab} from './scripts/lib/ingress-routing-lab.mjs';
    console.log(JSON.stringify(await runIngressRoutingLab()));
  `], { timeoutMs: 50000, env: { ...cleanEnvironment(process.env),
    MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'), MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid') } });
  assert.equal(result.reason, null, result.stderr); assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'passed'); assert.equal(report.hostNetworkChanged, false);
  assert.ok(report.checks.length >= 23); console.log(JSON.stringify(report));
});
