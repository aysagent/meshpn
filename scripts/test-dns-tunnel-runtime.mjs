import assert from 'node:assert/strict';
import test from 'node:test';
import { startTunnelDnsRuntime } from './lib/dns-tunnel-runtime.mjs';

function fixture(fail = null) {
  const events = [];
  const record = (name) => { events.push(name); if (name === fail) throw new Error(`fail ${name}`); };
  const journal = { begin: () => record('begin'), applyStage: (stage) => record(stage),
    activate: () => record('open-gate'), restore: () => record('restore'), release: () => record('release') };
  const forwarder = { stats: () => ({}), close: async () => record('forwarder-close') };
  const dependencies = { createForwarder: () => { record('forwarder'); return forwarder; },
    startStub: async () => { record('listen'); return { stats: () => ({}), close: async () => { record('stub-close'); await forwarder.close(); } }; } };
  return { events, journal, dependencies };
}
test('runtime installs guard/routes before listener; opens capture only on explicit activation', async () => {
  const f = fixture(), r = await startTunnelDnsRuntime({ journal: f.journal, config: {} }, f.dependencies);
  assert.deepEqual(f.events, ['begin', 'guard', 'route', 'forwarder', 'listen']); assert.equal(r.stats().active, false);
  r.activate(); assert.deepEqual(f.events.slice(-2), ['activate', 'open-gate']); assert.equal(r.stats().active, true);
  assert.throws(() => r.activate()); await r.close(); await r.close();
  assert.deepEqual(f.events.slice(-4), ['stub-close', 'forwarder-close', 'restore', 'release']);
});
test('abnormal shutdown closes sockets but retains network protection and journal', async () => {
  const f = fixture(), r = await startTunnelDnsRuntime({ journal: f.journal, config: {} }, f.dependencies);
  r.activate(); await r.close({ restore: false }); assert.ok(!f.events.includes('restore'));
  assert.deepEqual(f.events.slice(-3), ['stub-close', 'forwarder-close', 'release']); assert.throws(() => r.activate());
});
for (const failure of ['route', 'listen']) test(`failed ${failure} retains protection, releases lock and closes allocated resources`, async () => {
  const f = fixture(failure);
  await assert.rejects(startTunnelDnsRuntime({ journal: f.journal, config: {} }, f.dependencies), /fail/);
  assert.ok(!f.events.includes('restore')); assert.equal(f.events.at(-1), 'release');
  assert.equal(f.events.includes('forwarder-close'), failure === 'listen');
});
test('rollback error is propagated while releasing lock for explicit recovery', async () => {
  const f = fixture('restore'), r = await startTunnelDnsRuntime({ journal: f.journal, config: {} }, f.dependencies);
  await assert.rejects(r.close(), /fail restore/); assert.equal(f.events.at(-1), 'release');
});
