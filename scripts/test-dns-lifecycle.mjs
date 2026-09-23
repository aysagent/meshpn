import assert from 'node:assert/strict';
import test from 'node:test';
import { dnsLifecycle as step, dnsLifecycleDryRun, DNS_SCENARIOS } from './lib/dns-lifecycle.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

test('DNS opt-in is explicit and strictly boolean', () => {
  for (const optIn of [undefined, false, 1, 'true']) assert.throws(() => step('idle', 'enable', { optIn }));
  assert.deepEqual(step('idle', 'enable', { optIn: true }).actions,
    ['install-guard', 'snapshot', 'start-adapter', 'probe-protected-dns']);
});
test('DNS readiness is distinct from listening and selection acknowledgement', () => {
  assert.throws(() => step('preparing', 'selected'));
  assert.equal(step('preparing', 'ready', { owned: true }).state, 'selecting');
  assert.equal(step('selecting', 'selected').state, 'active');
  assert.equal(step('preparing', 'ready').state, 'conflict');
});
for (const state of ['preparing', 'selecting', 'active', 'blocked', 'conflict', 'restoring', 'releasing']) {
  test(`failure at ${state} never restores DNS or releases guard`, () => {
    assert.deepEqual(step(state, 'failure'), { state: 'blocked', actions: ['retain-guard-and-snapshot'] });
  });
}
test('restart does not replace original snapshot and requires ownership', () => {
  assert.equal(step('blocked', 'recover').state, 'conflict');
  assert.deepEqual(step('blocked', 'recover', { owned: true }).actions,
    ['install-guard', 'start-adapter', 'probe-protected-dns']);
});
test('foreign changes are not overwritten during disable', () => {
  assert.deepEqual(step('active', 'disable', { owned: false }),
    { state: 'conflict', actions: ['retain-guard-and-snapshot'] });
  assert.equal(step('conflict', 'disable', { owned: 1 }).state, 'conflict');
});
test('explicit disable acknowledges restore before guard removal and snapshot disposal', () => {
  assert.deepEqual(step('active', 'disable', { owned: true }), { state: 'restoring', actions: ['restore-snapshot'] });
  assert.throws(() => step('restoring', 'released'));
  assert.deepEqual(step('restoring', 'restored'), { state: 'releasing', actions: ['remove-guard'] });
  assert.deepEqual(step('releasing', 'released'), { state: 'idle', actions: ['stop-adapter', 'forget-snapshot'] });
  assert.deepEqual(step('idle', 'disable'), { state: 'idle', actions: [] });
});
test('unexpected events and prototype names rejected', () => {
  for (const [state, event] of [['idle', 'failure'], ['active', 'enable'], ['active', 'SIGTERM'], ['oops', 'disable']]) {
    assert.throws(() => step(state, event));
  }
  for (const scenario of ['toString', '__proto__', 'unknown']) assert.throws(() => dnsLifecycleDryRun(scenario));
});
for (const scenario of Object.keys(DNS_SCENARIOS)) test(`offline ${scenario} plan is deterministic and never claims host integration`, () => {
  const report = dnsLifecycleDryRun(scenario);
  assert.deepEqual(report, dnsLifecycleDryRun(scenario));
  assert.equal(report.systemDnsChanged, false); assert.equal(report.backend, 'unselected');
  assert.equal(report.persistentRecoveryImplemented, false);
  assert.equal(report.steps.at(-1).state, scenario === 'conflict' ? 'conflict' : scenario === 'restore-failure' ? 'blocked' : 'idle');
});

test('dry-run CLI has no apply mode and rejects duplicates/unknown arguments', async () => {
  for (const args of [['--apply'], ['--scenario=normal', '--scenario=outage'], ['--help', '--apply'], ['--scenario=toString']]) {
    const result = await runCommand(process.execPath, ['scripts/dns-lifecycle.mjs', ...args]);
    assert.equal(result.reason, null); assert.equal(result.code, 1); assert.equal(result.stdout, '');
  }
  const result = await runCommand(process.execPath, ['scripts/dns-lifecycle.mjs']);
  assert.equal(result.code, 0); assert.deepEqual(JSON.parse(result.stdout), dnsLifecycleDryRun());
});
test('isolated worker refuses execution in host namespaces before any mount or firewall write', async () => {
  const env = cleanEnvironment(process.env);
  for (const key of ['MESHPN_PARENT_NETNS', 'MESHPN_PARENT_PIDNS', 'MESHPN_PARENT_MNTNS', 'MESHPN_DNS_LIFECYCLE_DIR']) delete env[key];
  const result = await runCommand(process.execPath, ['scripts/dns-lifecycle-lab.mjs', '--isolated'], { env });
  assert.equal(result.reason, null); assert.equal(result.code, 1); assert.equal(result.stdout, '');
  assert.match(result.stderr, /use public browser soak launcher/);
});
