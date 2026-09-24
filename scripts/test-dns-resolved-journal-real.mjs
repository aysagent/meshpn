import assert from 'node:assert/strict';
import test from 'node:test';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

for (const family of [4, 6]) test(`real resolved journal IPv${family}: controller SIGKILL between setters and durable writes`,
  { timeout: 255000 }, async () => {
    const result = await runCommand(process.execPath, ['scripts/dns-lifecycle-lab.mjs', `--family=${family}`, '--resolved-journal'],
      { env: cleanEnvironment(process.env), timeoutMs: 250000 });
    assert.equal(result.reason, null); assert.equal(result.code, 0, result.stderr);
    const report = JSON.parse(result.stdout), journal = report.resolved.journal;
    assert.equal(report.status, 'passed'); assert.equal(report.family, family); assert.equal(report.hostDnsChanged, false);
    assert.equal(report.resolved.privateBus, true); assert.equal(report.resolved.resolvConfRewrittenByBackend, false);
    assert.equal(report.resolved.durableResolvedRecoveryImplemented, true);
    assert.equal(report.resolved.baselineQueriesDuringProtection, 0);
    assert.equal(journal.status, 'passed'); assert.equal(journal.controllerSigkills, 31); assert.equal(journal.lockConflicts, 1);
    assert.equal(journal.cases.length, 27); assert.equal(new Set(journal.cases.map((c) => c.point)).size, 27);
    assert.deepEqual(journal.refused, ['missing', 'corrupt', 'foreign-pending-state', 'stale-scope', 'bus-id-mismatch', 'exit-down', 'daemon-owner-changed']);
    assert.equal(journal.partialApplyDisabled, true); assert.equal(journal.journalRecoveryTested, true);
    assert.equal(journal.rebootTested, false); assert.equal(journal.adapterSigkillTested, false);
    assert.equal(report.dnsCalls, 0); assert.equal(report.final.resources.tree.live, 1); assert.equal(report.final.resources.tree.zombies, 0);
  });
