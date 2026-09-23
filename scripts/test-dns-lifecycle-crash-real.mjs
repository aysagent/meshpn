import assert from 'node:assert/strict';
import test from 'node:test';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

for (const family of [4, 6]) test(`DNS journal IPv${family}: real controller SIGKILL, lock, recovery, conflict`,
  { timeout: 135000 }, async () => {
    const result = await runCommand(process.execPath, ['scripts/dns-lifecycle-lab.mjs', `--family=${family}`, '--crash'],
      { env: cleanEnvironment(process.env), timeoutMs: 130000 });
    assert.equal(result.reason, null); assert.equal(result.code, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, 'passed'); assert.equal(report.family, family); assert.equal(report.hostDnsChanged, false);
    assert.equal(report.crash.status, 'passed'); assert.equal(report.crash.controllerSigkills, 13);
    assert.equal(report.crash.lockConflicts, 1); assert.equal(report.crash.cases.length, 12);
    assert.equal(report.crash.journalRecoveryTested, true);
    assert.deepEqual(report.crash.refused, ['missing-journal', 'corrupt-journal', 'same-content-foreign-inode',
      'foreign-config', 'stale-scope', 'changed-snapshot', 'exit-down']);
    assert.equal(report.crash.rebootTested, false); assert.equal(report.crash.adapterSigkillTested, false);
    assert.equal(report.dnsCalls, 0); assert.equal(report.final.resources.tree.live, 1);
    assert.equal(report.final.resources.tree.zombies, 0);
  });
