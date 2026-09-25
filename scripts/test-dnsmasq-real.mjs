import assert from 'node:assert/strict';
import test from 'node:test';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

test('actual dnsmasq: baseline, protected UDP/TCP A/AAAA, faults, restart and explicit restore', { timeout: 65000 }, async () => {
  const result = await runCommand(process.execPath, ['scripts/dnsmasq-lab.mjs'],
    { timeoutMs: 62000, env: cleanEnvironment(process.env) });
  assert.equal(result.reason, null); assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'passed'); assert.equal(report.hostDnsChanged, false);
  assert.equal(report.baselineQueriesDuringProtection, 0); assert.equal(report.exactFixtureBaselineRestored, true);
  assert.equal(report.checks.length, 14); assert.equal(new Set(report.checks).size, 14);
  assert.equal(report.durableRecoveryImplemented, false); assert.equal(report.dhcpLeaseExchangeTested, false);
  assert.equal(report.final.processes, 1); assert.equal(report.final.zombies, 0);
});
