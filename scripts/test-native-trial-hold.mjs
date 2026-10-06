import test from 'node:test';
import assert from 'node:assert/strict';
import { probeNativeHold } from './lib/native-trial-hold.mjs';

function setup(extra = {}) {
  let now = 0;
  const report = {}, session = { healthy: () => true, diagnostics: () => ({ stateCounts: { ready: 3, h2_peer_end_stream: 2 } }) };
  return { seconds: 25, session, report, probe: async () => true,
    now: () => now, sleep: async ms => { now += ms; }, ...extra };
}
test('hold probes through quiet gaps and retains full counts', async () => {
  const io = setup(); await probeNativeHold(io);
  assert.equal(io.report.status, 'passed'); assert.equal(io.report.passed, 3);
  assert.deepEqual(io.report.samples.map(s => s.atMs), [0, 10000, 20000]);
  assert.equal(io.report.seconds, 25); assert.equal(io.report.sessionStateCounts.h2_peer_end_stream, 2);
});
test('zero hold does not make requests', async () => {
  const io = setup({ seconds: 0, probe: () => assert.fail() }); await probeNativeHold(io);
  assert.equal(io.report.status, 'not-requested');
});
for (const probe of [async () => false, async () => { throw Error('SECRET'); }]) test('failed hold retains safe evidence for rollback report', async () => {
  const io = setup({ probe }); await assert.rejects(probeNativeHold(io), /native_hold_https_failed/);
  assert.equal(io.report.failed, 1); assert.equal(io.report.status, 'failed');
  assert.doesNotMatch(JSON.stringify(io.report), /SECRET/);
});
test('foreign packet is not accepted as stability even when HTTPS works', async () => {
  const io = setup(); io.session.diagnostics = () => ({ stateCounts: { peer_address: 1 } });
  await assert.rejects(probeNativeHold(io), /native_peer_address_rejected/);
  assert.equal(io.report.status, 'failed'); assert.equal(io.report.passed, 0);
});
test('cancellation and engine exit still trigger bounded rollback', async () => {
  for (const mode of ['cancelled', 'exit']) {
    const io = setup();
    if (mode === 'cancelled') io.cancelled = () => true; else io.session.healthy = () => false;
    await assert.rejects(probeNativeHold(io), mode === 'cancelled' ? /cancelled/ : /native_exited_during_trial/);
    assert.equal(io.report.status, 'failed'); assert.equal(io.report.samples.length, 0);
  }
});
