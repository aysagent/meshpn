import assert from 'node:assert/strict';
import test from 'node:test';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

for (const family of [4, 6]) test(`real systemd-resolved IPv${family}: D-Bus apply/restore, conflict, exit outage, daemon SIGKILL`,
  { timeout: 135000 }, async () => {
    const result = await runCommand(process.execPath, ['scripts/dns-lifecycle-lab.mjs', `--family=${family}`, '--resolved'],
      { env: cleanEnvironment(process.env), timeoutMs: 130000 });
    assert.equal(result.reason, null); assert.equal(result.code, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, 'passed'); assert.equal(report.family, family); assert.equal(report.hostDnsChanged, false);
    assert.equal(report.resolved.status, 'passed'); assert.match(report.resolved.version, /^systemd \d+/);
    assert.equal(report.resolved.privateBus, true); assert.equal(report.resolved.resolvConfRewrittenByBackend, false);
    assert.equal(report.resolved.daemonSigkill, true); assert.equal(report.resolved.ownerChangeRefused, true);
    assert.equal(report.resolved.runtimeSettingsSurvivedRestart, true);
    assert.equal(report.resolved.baselineQueriesDuringProtection, 0); assert.equal(report.resolved.durableResolvedRecoveryImplemented, false);
    assert.equal(report.checks.length, 32); assert.equal(report.dnsCalls, 0);
    assert.equal(report.final.resources.tree.live, 1); assert.equal(report.final.resources.tree.zombies, 0);
  });
