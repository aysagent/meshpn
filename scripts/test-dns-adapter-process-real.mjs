import assert from 'node:assert/strict';
import test from 'node:test';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

for (const family of [4, 6]) test(`real DNS adapter process IPv${family}: SIGKILL, same-port restart, readiness, port conflict`,
  { timeout: 135000 }, async () => {
    const result = await runCommand(process.execPath, ['scripts/dns-lifecycle-lab.mjs', `--family=${family}`, '--resolved-adapter'],
      { env: cleanEnvironment(process.env), timeoutMs: 130000 });
    assert.equal(result.reason, null); assert.equal(result.code, 0, result.stderr);
    const report = JSON.parse(result.stdout), adapter = report.resolved.adapterProcess;
    assert.equal(report.status, 'passed'); assert.equal(report.family, family); assert.equal(report.hostDnsChanged, false);
    assert.equal(report.resolved.privateBus, true); assert.equal(report.resolved.resolvConfRewrittenByBackend, false);
    assert.equal(report.resolved.durableResolvedRecoveryImplemented, true);
    assert.deepEqual(adapter, { status: 'passed', adapterSigkills: 4, starts: 5, startupFailures: 2, refusedOperations: 10,
      inFlightQueries: 2, stableEndpoint: true, baselineQueriesDuringProtection: 0,
      gracefulShutdown: true, disableWhileAdapterDown: true, rebootTested: false, automaticRestart: false });
    assert.equal(report.checks.length, 62); assert.equal(report.dnsCalls, 0);
    assert.equal(report.final.resources.tree.live, 1); assert.equal(report.final.resources.tree.zombies, 0);
    for (const key of ['TCPSocketWrap', 'TCPServerWrap', 'UDPWrap', 'ProcessWrap', 'Timeout']) assert.equal(report.final.resources.worker.active[key] ?? 0, 0);
  });
