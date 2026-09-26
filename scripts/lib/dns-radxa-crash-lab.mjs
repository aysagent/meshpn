import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { controller } from './dns-lifecycle-crash-lab.mjs';
import { pairRadxaBackends, inspectRadxaTransaction } from './dns-radxa-journal.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
export const RADXA_APPLY_CUTS = ['dnsmasq', 'dnsmasq:apply:config:intent', 'dnsmasq:apply:config:set',
  'dnsmasq:apply:daemon:set', 'resolver', 'resolver:apply-intent', 'resolver:apply:set', 'active'];
export const RADXA_RESTORE_CUTS = ['restore-resolver', 'resolver:restore-intent', 'resolver:restore:set',
  'restore-dnsmasq', 'dnsmasq:restore:config:set', 'dnsmasq:restore:daemon:set', 'restored'];
export async function radxaCrashLab(directory, scope, dnsmasq, resolver) {
  await assertDnsMountNamespace(); await mkdir(join(directory, 'radxa'), { mode: 0o700 });
  const backend = pairRadxaBackends(dnsmasq, resolver), evidence = { controllerSigkills: 0, lockConflicts: 0, checkpoints: [], protectionRetained: false };
  const raw = (op, pause) => controller(directory, op, backend, pause, 'radxa');
  const run = async (op, pause) => {
    const worker = raw(op, pause);
    if (!pause) { const r = await worker.done; assert.equal(r.code, 0, r.stderr); return r.result; }
    try {
      await worker.reached;
      if (pause === 'dnsmasq') {
        assert.equal((await raw('recover').done).code, 75); evidence.lockConflicts++;
        const before = await readFile(join(directory, 'radxa', 'journal.json'));
        assert.equal((await inspectRadxaTransaction({ directory, scope, backend })).readinessVerified, false);
        assert.deepEqual(await readFile(join(directory, 'radxa', 'journal.json')), before);
      }
    } finally { worker.kill(); }
    assert.equal((await worker.done).signal, 'SIGKILL'); evidence.controllerSigkills++; evidence.checkpoints.push(pause);
  };
  return { evidence, raw, recover: () => run('recover'),
    async enable() {
      for (const [i, point] of RADXA_APPLY_CUTS.entries()) await run(i ? 'recover' : 'enable', point);
      assert.equal((await run('recover')).status, 'active');
    },
    async restore() {
      for (const [i, point] of RADXA_RESTORE_CUTS.entries()) await run(i ? 'recover' : 'disable', point);
      const r = await run('recover'); assert.equal(r.status, 'restored'); assert.equal(r.protectionRetained, true);
      evidence.protectionRetained = true;
    },
  };
}
