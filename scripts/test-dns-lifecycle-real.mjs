import assert from 'node:assert/strict';
import test from 'node:test';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

for (const family of [4, 6]) test(`system DNS lifecycle IPv${family}/combo: readiness, fail-closed, conflict, explicit restoration`,
  { timeout: 55000 }, async () => {
    const result = await runCommand(process.execPath, ['scripts/dns-lifecycle-lab.mjs', `--family=${family}`],
      { env: cleanEnvironment(process.env), timeoutMs: 50000 });
    assert.equal(result.reason, null); assert.equal(result.code, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, 'passed'); assert.equal(report.family, family);
    assert.equal(report.hostDnsChanged, false); assert.equal(report.persistentRecoveryImplemented, false);
    assert.equal(report.baselineQueriesDuringProtection, 0); assert.equal(report.dnsCalls, 0);
    assert.equal(report.checks.length, 23); assert.equal(new Set(report.checks).size, 23);
    assert.equal(report.final.state, 'idle'); assert.equal(report.final.resources.tree.live, 1);
    assert.equal(report.final.resources.tree.zombies, 0);
  });
