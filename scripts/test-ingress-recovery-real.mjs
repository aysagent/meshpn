import assert from 'node:assert/strict';
import test from 'node:test';
import { readlink } from 'node:fs/promises';
import { namespaceArgs } from './lib/browser-soak.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';

test('isolated ingress journal: crash recovery, locks, foreign state, atomic writes', { timeout: 180000 }, async () => {
  const result = await runCommand('unshare', [...namespaceArgs.map((a) => a === '--map-current-user' ? '--map-root-user' : a),
    process.execPath, '--input-type=module', '-e', `
      import {runIngressRecoveryLab} from './scripts/lib/ingress-recovery-lab.mjs';
      console.log(JSON.stringify(runIngressRecoveryLab()));
    `], { timeoutMs: 170000, env: { ...cleanEnvironment(process.env),
    MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'), MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid') } });
  assert.equal(result.reason, null, result.stderr); assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout); assert.equal(report.status, 'passed');
  assert.equal(report.hostNetworkChanged, false); assert.equal(report.faultPoints, 24);
  console.log(JSON.stringify(report));
});
