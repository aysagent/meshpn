import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile, rm, symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { dnsBootInitial, dnsBootStep as step, dnsBootDryRun, DNS_BOOT_SCENARIOS } from './lib/dns-boot.mjs';
import { dnsVmPreflight, dnsVmPreflightOptions } from './lib/dns-vm-preflight.mjs';
import { runCommand } from './lib/transparent-acceptance.mjs';

const id = '11111111-1111-1111-1111-111111111111', other = '22222222-2222-2222-2222-222222222222';
function reviewed() {
  const guarding = step(dnsBootInitial(id), 'start', { optIn: true }).state;
  return step(guarding, 'guard-confirmed', { guardVerified: true }).state;
}
const current = (direction = 'apply') => ({ status: 'valid', journalBootId: id, contextMatches: true, released: false, direction });
for (const scenario of DNS_BOOT_SCENARIOS) test(`boot scenario ${scenario} is deterministic, offline and conservative`, () => {
  const report = dnsBootDryRun(scenario); assert.deepEqual(report, dnsBootDryRun(scenario));
  for (const key of ['systemDnsChanged', 'vmStarted', 'rebootTested', 'powerLossTested']) assert.equal(report[key], false);
  for (const { state, actions } of report.steps) {
    if (state.admitted) assert.ok(state.phase === 'disabled' || (state.phase === 'active' && state.guardVerified));
    if (actions.includes('remove-guard')) assert.equal(state.phase, 'releasing');
  }
  const last = report.steps.at(-1).state;
  assert.equal(last.admitted, ['fresh', 'same-boot', 'disable'].includes(scenario));
});
test('boot opt-in and guard acknowledgement are strictly boolean', () => {
  for (const value of [undefined, false, 1, 'true']) {
    assert.throws(() => step(dnsBootInitial(id), 'start', { optIn: value }));
    const guarding = step(dnsBootInitial(id), 'start', { optIn: true }).state;
    assert.throws(() => step(guarding, 'guard-confirmed', { guardVerified: value }));
  }
});
test('guard-loss event cannot bypass opt-in or reactivate an explicitly disabled policy', () => {
  assert.throws(() => step(dnsBootInitial(id), 'guard-lost'));
  assert.throws(() => step(dnsBootDryRun('disable').steps.at(-1).state, 'guard-lost'));
});
test('failed guard installation never claims a guard exists and still awaits its acknowledgement', () => {
  const guarding = step(dnsBootInitial(id), 'start', { optIn: true }).state;
  const failed = step(guarding, 'failure'); assert.equal(failed.state.guardVerified, false); assert.equal(failed.state.admitted, false);
  assert.ok(failed.actions.includes('install-boot-guard')); assert.ok(!failed.actions.includes('retain-guard'));
  assert.equal(step(failed.state, 'guard-confirmed', { guardVerified: true }).state.phase, 'review');
});
for (const scenario of DNS_BOOT_SCENARIOS) test(`new boot erases runtime evidence after ${scenario}`, () => {
  const last = dnsBootDryRun(scenario).steps.at(-1).state;
  const result = step(last, 'new-boot', { bootId: last.bootId === id ? other : id });
  assert.equal(result.state.phase, 'cold'); assert.equal(result.state.guardVerified, false); assert.equal(result.state.admitted, false);
  assert.equal(result.state.journal, 'unchecked'); assert.throws(() => step(result.state, 'selected'));
});
for (const mismatch of ['boot', 'context']) test(`journal ${mismatch} mismatch cannot authorize restore or takeover`, () => {
  const evidence = current(); if (mismatch === 'boot') evidence.journalBootId = other; else evidence.contextMatches = false;
  const result = step(reviewed(), 'journal-inspected', evidence);
  assert.equal(result.state.journal, 'stale'); assert.equal(result.state.admitted, false);
  assert.deepEqual(result.actions, ['preserve-journal', 'manual-review']);
  assert.throws(() => step(result.state, 'disable', { operatorApproved: true, contextMatches: true }));
  assert.throws(() => step(result.state, 'authorize-new-epoch', { operatorApproved: true, ownedLink: true, baselineVerified: true }));
  const next = step(result.state, 'authorize-new-epoch', { operatorApproved: true, ownedLink: true, baselineVerified: true, oldJournalPreserved: true });
  assert.equal(next.state.phase, 'preparing'); assert.equal(next.state.admitted, false);
  assert.deepEqual(next.actions, ['snapshot-current-boot-baseline', 'persist-new-epoch-intent']);
});
test('durable restore intent in the same context is not converted to apply', () => {
  const result = step(reviewed(), 'journal-inspected', current('restore'));
  assert.equal(result.state.phase, 'restoring'); assert.deepEqual(result.actions, ['resume-current-boot-restore']);
  assert.equal(result.state.admitted, false); assert.ok(result.state.guardVerified);
});
test('corrupt and released journals never implicitly release guard', () => {
  for (const evidence of [{ status: 'corrupt' }, { ...current(), released: true }]) {
    const result = step(reviewed(), 'journal-inspected', evidence);
    assert.equal(result.state.admitted, false); assert.ok(result.state.guardVerified);
    assert.ok(!result.actions.includes('remove-guard'));
  }
});
test('UDP-only readiness, binding and non-durable readback cannot admit traffic', () => {
  const starting = step(reviewed(), 'journal-inspected', current()).state;
  const probing = step(starting, 'adapter-bound').state; assert.equal(probing.admitted, false);
  for (const key of ['udpReady', 'tcpReady', 'contextMatches']) {
    const evidence = { udpReady: true, tcpReady: true, contextMatches: true }; evidence[key] = false;
    assert.throws(() => step(probing, 'ready', evidence));
  }
  const selecting = step(probing, 'ready', { udpReady: true, tcpReady: true, contextMatches: true }).state;
  for (const key of ['readBackMatches', 'contextMatches', 'durable']) {
    const evidence = { readBackMatches: true, contextMatches: true, durable: true }; evidence[key] = false;
    assert.throws(() => step(selecting, 'selected', evidence));
  }
});
for (const { state } of dnsBootDryRun('disable').steps.filter(({ state }) => state.guardVerified)) {
  test(`failure/guard loss at ${state.phase} cannot restore or admit baseline automatically`, () => {
    const failed = step(state, 'failure'); assert.equal(failed.state.admitted, false);
    assert.ok(!failed.actions.some((a) => a.includes('restore') || a === 'remove-guard'));
    const lost = step(state, 'guard-lost'); assert.equal(lost.state.guardVerified, false); assert.equal(lost.state.admitted, false);
    assert.equal(lost.state.phase, 'guarding');
  });
}
test('boot proposal never accepts unknown states/events or malformed boot IDs', () => {
  for (const invalid of ['host', '', '__proto__']) assert.throws(() => dnsBootInitial(invalid));
  assert.throws(() => dnsBootDryRun('toString')); assert.throws(() => step(reviewed(), 'apply'));
  assert.throws(() => step(reviewed(), 'new-boot', { bootId: id }));
});
for (const args of [['--apply'], ['--scenario=fresh', '--scenario=disable'], ['--scenario=unknown'], ['--help', '--apply']]) {
  test(`offline boot CLI refuses ${args.join(' ')}`, async () => {
    const r = await runCommand(process.execPath, ['scripts/dns-boot.mjs', ...args]); assert.equal(r.code, 1); assert.equal(r.stdout, '');
  });
}
test('boot CLI default models a previous boot without touching host DNS', async () => {
  const r = await runCommand(process.execPath, ['scripts/dns-boot.mjs']); assert.equal(r.code, 0);
  assert.deepEqual(JSON.parse(r.stdout), dnsBootDryRun());
});
for (const args of [['--apply'], ['--qemu=relative'], ['--disk=/dev/a', '--disk=/dev/b'], ['--initrd=/tmp/a\n']]) {
  test(`VM preflight rejects arguments ${JSON.stringify(args)}`, () => assert.throws(() => dnsVmPreflightOptions(args)));
}
test('VM preflight is metadata only and never considers artifact existence launch permission', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-vm-preflight-test-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const file = join(directory, 'artifact'); await writeFile(file, 'not an executable or image', { mode: 0o700 });
  const options = { qemu: file, kernel: file, initrd: file, disk: file }, result = await dnsVmPreflight(options);
  assert.equal(result.vmStarted, false); assert.equal(result.launchAuthorized, false); assert.equal(result.artifactVerificationRequired, true);
  assert.deepEqual(result.blockers, []); assert.equal(result.plannedAcceleration, 'tcg');
  await chmod(file, 0o600); assert.equal((await dnsVmPreflight(options)).artifacts.qemu.status, 'unavailable');
  const alias = join(directory, 'alias'); await symlink(file, alias);
  assert.equal((await dnsVmPreflight({ ...options, disk: alias })).artifacts.disk.status, 'unsafe-type');
  const absent = await dnsVmPreflight({ qemu: join(directory, 'absent'), kernel: directory });
  assert.equal(absent.artifacts.qemu.status, 'missing'); assert.equal(absent.artifacts.kernel.status, 'invalid-file');
  assert.equal(absent.artifacts.initrd.status, 'not-supplied'); assert.equal(absent.artifacts.disk.status, 'not-supplied');
  assert.ok(!JSON.stringify(result).includes(directory));
});
