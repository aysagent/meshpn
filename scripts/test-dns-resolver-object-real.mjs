import assert from 'node:assert/strict';
import test from 'node:test';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';
import { RESOLVER_CRASH_POINTS } from './lib/dns-resolver-object-lab.mjs';

test('Radxa resolver object: synthetic /etc, real NSS/dnsmasq, USB DHCP and controller SIGKILL', { timeout: 185000 }, async () => {
  const r = await runCommand(process.execPath, ['scripts/dnsmasq-lab.mjs', '--resolver-object'],
    { env: cleanEnvironment(process.env), timeoutMs: 182000, maxBytes: 128 * 1024 });
  assert.equal(r.reason, null); assert.equal(r.code, 0, r.stderr);
  const report = JSON.parse(r.stdout), evidence = report.resolverObject;
  assert.equal(report.status, 'passed'); assert.equal(report.hostDnsFilesUnchanged, true); assert.equal(report.hostForwardingUnchanged, true);
  assert.equal(report.systemResolverTakeoverTested, false); assert.equal(report.systemResolverFixtureTested, true);
  assert.equal(evidence.controllerSigkills, 7); assert.equal(evidence.lockConflicts, 1); assert.deepEqual(evidence.checkpoints, RESOLVER_CRASH_POINTS);
  assert.equal(evidence.exactSymlinkTextRestored, true); assert.equal(evidence.protectionRetainedAfterRestore, true);
  assert.equal(evidence.fixtureOnly, true); assert.equal(evidence.rebootTested, false);
  assert.deepEqual(evidence.refusals, ['same-content-foreign-inode', 'resolver-mountpoint', 'resolved-target-appeared']);
  assert.deepEqual(evidence.checks, ['system-managed-4-udp', 'system-managed-4-tcp', 'system-managed-6-udp', 'system-managed-6-tcp',
    'system-exit-down-udp', 'system-exit-down-tcp', 'system-dnsmasq-restarted', 'system-adapter-down-udp', 'system-adapter-down-tcp']);
  assert.equal(report.journal.controllerSigkills, 7); assert.equal(report.checks.length, 61); assert.equal(report.dhcp.length, 6);
  assert.equal(report.baselineQueriesDuringProtection, 0); assert.equal(report.forwardedQueriesDuringProtection, 0);
  assert.equal(report.exactFixtureBaselineRestored, true); assert.equal(report.final.processes, 1); assert.equal(report.final.zombies, 0);
});
