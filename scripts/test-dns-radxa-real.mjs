import assert from 'node:assert/strict';
import test from 'node:test';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';
import { RADXA_APPLY_CUTS, RADXA_RESTORE_CUTS } from './lib/dns-radxa-crash-lab.mjs';
for (const localhost of [false, true]) test(`paired Radxa (${localhost ? 'localhost file' : 'dangling link'}): SIGKILL, NSS/USB DNS, offline rollback and DHCP recovery`, { timeout: 185000 }, async () => {
  const r = await runCommand(process.execPath, ['scripts/dnsmasq-lab.mjs', '--radxa-journal', ...(localhost ? ['--localhost-baseline'] : [])],
    { env: cleanEnvironment(process.env), timeoutMs: 182000, maxBytes: 128 * 1024 });
  assert.equal(r.reason, null); assert.equal(r.code, 0, r.stderr);
  const report = JSON.parse(r.stdout), object = report.resolverObject, paired = object.paired;
  assert.equal(report.status, 'passed'); assert.equal(report.hostDnsFilesUnchanged, true); assert.equal(report.hostForwardingUnchanged, true);
  assert.equal(report.systemResolverTakeoverTested, false); assert.equal(report.rebootTested, false);
  assert.equal(paired.controllerSigkills, 15); assert.equal(paired.lockConflicts, 1);
  assert.deepEqual(paired.checkpoints, [...RADXA_APPLY_CUTS, ...RADXA_RESTORE_CUTS]);
  assert.equal(paired.protectionRetained, true); assert.equal(paired.restoredDaemonReconciled, true);
  assert.equal(paired.fixtureGuardReleaseAfterChecks, true); assert.equal(object.exactSymlinkTextRestored, !localhost);
  assert.equal(object.exactLocalhostFileRestored, localhost);
  assert.equal(object.baseline, localhost ? 'localhost-file' : 'dangling-stub');
  assert.equal(object.checks.length, localhost ? 13 : 9); assert.equal(object.refusals.length, 3);
  assert.ok(object.boundedBlockedLookups.every((name) => localhost && /^system-restored-guarded-(udp|tcp)$/.test(name)));
  assert.equal(report.journal.exitDownRecoveryRefused, true); assert.equal(report.journal.baselineDaemonBlockedBeforeRelease, true);
  assert.equal(report.checks.length, 62); assert.equal(report.dhcp.length, 7);
  assert.equal(report.baselineQueriesDuringProtection, 0); assert.equal(report.forwardedQueriesDuringProtection, 0);
  assert.equal(report.exactFixtureBaselineRestored, true); assert.deepEqual(report.final, { processes: 1, zombies: 0 });
});
