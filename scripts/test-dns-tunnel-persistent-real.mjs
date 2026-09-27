import assert from 'node:assert/strict';
import test from 'node:test';
import { readlink } from 'node:fs/promises';
import { namespaceArgs } from './lib/browser-soak.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';

for (const journaled of [false, true]) for (const scope of ['host', 'ingress', 'lan']) test(`persistent UDP DNS survives enable/disable: ${scope}${journaled ? ' journaled' : ''}`, { timeout: 60000 }, async () => {
  const result = await runCommand('unshare', [...namespaceArgs.map((a) => a === '--map-current-user' ? '--map-root-user' : a),
    process.execPath, '--input-type=module', '-e', `
      import {runTunnelDnsRoutingLab} from './scripts/lib/dns-tunnel-routing-lab.mjs';
      console.log(JSON.stringify(await runTunnelDnsRoutingLab({ingress:${scope === 'ingress'},lan:${scope === 'lan'},journaled:${journaled},persistent:true})));
    `], { timeoutMs: 50000, env: { ...cleanEnvironment(process.env),
    MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'), MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid') } });
  assert.equal(result.reason, null, result.stderr); assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout); console.log(JSON.stringify(report.persistentFlows));
  assert.equal(report.persistentFlows.existingAtEnable.answer, 10, 'old UDP socket must switch into tunnel');
  assert.equal(report.persistentFlows.existingAfterDisable.answer, 30);
  assert.equal(report.persistentFlows.tunneledAfterDisable.answer, 30, 'same UDP socket must return to baseline');
});
