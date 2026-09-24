import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm, readFile, writeFile, chmod, symlink, link, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createResolvedJournalBackend } from './lib/dns-resolved-backend.mjs';
import { RESOLVED_PROPERTIES, managedResolvedSettings, validateResolvedJournal, readResolvedJournal,
  writeResolvedJournal, resolvedTransaction } from './lib/dns-resolved-journal.mjs';

const scope = { net: 'net:[1]', mnt: 'mnt:[2]', pid: 'pid:[3]' };
const context = { scope, busId: 'b'.repeat(32), owner: ':1.2', link: { ifindex: 2, ifname: 'dnsfixture', address: '02:00:00:00:00:01' } };
const baseline = { DNSEx: [[2, [127, 0, 0, 55], 53, '']], Domains: [['baseline.test', false]], DefaultRoute: false };
const managed = managedResolvedSettings(1053);
async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-resolved-journal-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const state = { context: structuredClone(context), settings: structuredClone(baseline), guard: false, ready: true, port: 1053 }, writes = [];
  const backend = {
    async ensureGuard() { state.guard = true; },
    async view() { return structuredClone({ context: state.context, settings: state.settings }); },
    async probe() { assert.ok(state.guard); assert.ok(state.ready, 'not ready'); },
    async adapterPort() { return state.port; },
    async set(ctx, property, value, before) {
      assert.ok(state.guard); assert.deepEqual(ctx, state.context); assert.deepEqual(before, state.settings);
      // An intent must already be durable before this setter.
      const record = await readResolvedJournal(directory);
      assert.equal(record.pending, true); assert.equal(RESOLVED_PROPERTIES[record.cursor], property);
      state.settings[property] = structuredClone(value); writes.push(property);
    },
    async removeGuard(ctx, settings) {
      assert.deepEqual(ctx, state.context); assert.deepEqual(state.settings, settings); assert.deepEqual(settings, baseline);
      const record = await readResolvedJournal(directory);
      assert.equal(record.direction, 'restore'); assert.equal(record.cursor, 3); assert.equal(record.pending, false);
      state.guard = false;
    },
  };
  const run = (operation, checkpoint) => resolvedTransaction({ directory, operation, scope, backend, checkpoint });
  return { directory, state, backend, writes, run };
}
const crash = (point) => async (current) => { if (point === current) throw new Error('interruption'); };

test('resolved journal lifecycle: private snapshot, stable id, terminal replay, no new enable', async (t) => {
  const f = await fixture(t), active = await f.run('enable');
  assert.equal(active.status, 'active'); assert.deepEqual(f.state.settings, managed); assert.ok(f.state.guard);
  assert.equal((await stat(join(f.directory, 'journal.json'))).mode & 0o777, 0o600);
  assert.deepEqual((await readResolvedJournal(f.directory)).original, baseline);
  assert.deepEqual(await f.run('recover'), active);
  await assert.rejects(f.run('enable'), /already exists/);
  const released = await f.run('disable'); assert.equal(released.id, active.id); assert.equal(released.status, 'released');
  assert.deepEqual(f.state.settings, baseline); assert.equal(f.state.guard, false);
  assert.deepEqual(await f.run('recover'), released); assert.equal(f.state.guard, false);
  await assert.rejects(f.run('enable'), /already exists/);
});
for (const direction of ['apply', 'restore']) {
  const points = direction === 'apply' ? ['prepared', 'ready', 'active'] : ['restore-start', 'restore-complete', 'guard-removed', 'released'];
  for (const property of RESOLVED_PROPERTIES) for (const boundary of ['intent', 'set', 'ack']) {
    points.push(`${direction}:${property}:${boundary}`);
    if (boundary !== 'set') for (const flush of ['file-synced', 'renamed', 'dir-synced']) points.push(`${direction}:${property}:${boundary}:${flush}`);
  }
  for (const point of points) test(`resolved recovery after ${point}`, async (t) => {
    const f = await fixture(t);
    if (direction === 'restore') await f.run('enable');
    await assert.rejects(f.run(direction === 'apply' ? 'enable' : 'disable', crash(point)), /interruption/);
    const id = (await readResolvedJournal(f.directory)).id;
    const recovered = await f.run('recover'); assert.equal(recovered.id, id);
    assert.equal(recovered.status, direction === 'apply' ? 'active' : 'released');
    assert.deepEqual(f.state.settings, direction === 'apply' ? managed : baseline);
    assert.equal(f.state.guard, direction === 'apply');
    // No duplicate setter when the D-Bus response or journal ack was lost.
    assert.deepEqual(f.writes, direction === 'apply' ? RESOLVED_PROPERTIES : [...RESOLVED_PROPERTIES, ...RESOLVED_PROPERTIES]);
  });
}
for (const point of ['prepared', 'apply:DNSEx:intent', 'apply:DNSEx:set', 'apply:Domains:set', 'apply:DefaultRoute:set']) {
  test(`explicit disable of partial apply: ${point}`, async (t) => {
    const f = await fixture(t); await assert.rejects(f.run('enable', crash(point)), /interruption/);
    assert.equal((await f.run('disable')).status, 'released');
    assert.deepEqual(f.state.settings, baseline); assert.equal(f.state.guard, false);
  });
}
for (const change of ['owner', 'bus', 'link', 'scope', 'settings', 'endpoint', 'unavailable']) test(`resolved recovery refuses changed ${change}`, async (t) => {
  const f = await fixture(t); await assert.rejects(f.run('enable', crash('apply:DNSEx:set')), /interruption/);
  if (change === 'owner') f.state.context.owner = ':1.3';
  if (change === 'bus') f.state.context.busId = 'c'.repeat(32);
  if (change === 'link') f.state.context.link.address = '02:00:00:00:00:02';
  if (change === 'scope') f.state.context.scope.net = 'net:[4]';
  if (change === 'settings') f.state.settings.Domains = [['foreign.test', true]];
  if (change === 'endpoint') f.state.port++;
  if (change === 'unavailable') f.state.ready = false;
  const bytes = await readFile(join(f.directory, 'journal.json')), settings = structuredClone(f.state.settings);
  await assert.rejects(f.run('recover')); assert.ok(f.state.guard); assert.deepEqual(f.state.settings, settings);
  assert.deepEqual(await readFile(join(f.directory, 'journal.json')), bytes);
});
test('readiness failure and lost setter reply retain recoverable intent', async (t) => {
  const f = await fixture(t); f.state.ready = false;
  await assert.rejects(f.run('enable'), /not ready/); assert.deepEqual(f.state.settings, baseline); assert.ok(f.state.guard);
  f.state.ready = true; const set = f.backend.set;
  f.backend.set = async (...args) => { await set(...args); throw new Error('reply lost'); };
  await assert.rejects(f.run('recover'), /reply lost/);
  assert.equal((await readResolvedJournal(f.directory)).pending, true);
  f.backend.set = set; await f.run('recover'); assert.deepEqual(f.writes, RESOLVED_PROPERTIES);
});
test('conflict after restore prevents guard removal', async (t) => {
  const f = await fixture(t); await f.run('enable');
  await assert.rejects(f.run('disable', async (point) => {
    if (point === 'restore-complete') f.state.settings.Domains = [['foreign.test', false]];
  }), /ownership conflict/); assert.ok(f.state.guard);
});
test('missing journal and uncommitted initial snapshot cannot authorize recovery', async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.run('recover'), { code: 'ENOENT' }); assert.ok(f.state.guard);
  await assert.rejects(f.run('enable', crash('prepared:file-synced')), /interruption/);
  await assert.rejects(f.run('recover'), { code: 'ENOENT' }); assert.deepEqual(f.state.settings, baseline);
});
for (const flush of ['file-synced', 'renamed', 'dir-synced']) test(`restore direction is determined by committed intent at ${flush}`, async (t) => {
  const f = await fixture(t); await f.run('enable');
  await assert.rejects(f.run('disable', crash(`restore-start:${flush}`)), /interruption/);
  assert.deepEqual(f.state.settings, managed); assert.ok(f.state.guard);
  const result = await f.run('recover'), committed = flush !== 'file-synced';
  assert.equal(result.status, committed ? 'released' : 'active');
  assert.deepEqual(f.state.settings, committed ? baseline : managed); assert.equal(f.state.guard, !committed);
});
for (const flush of ['renamed', 'dir-synced']) test(`initial prepared snapshot recovers after ${flush}`, async (t) => {
  const f = await fixture(t); await assert.rejects(f.run('enable', crash(`prepared:${flush}`)), /interruption/);
  assert.deepEqual(f.state.settings, baseline); assert.equal((await f.run('recover')).status, 'active');
  assert.deepEqual(f.state.settings, managed); assert.ok(f.state.guard);
});
for (const kind of ['malformed', 'oversized', 'public-mode', 'symlink', 'hardlink', 'public-directory']) {
  test(`resolved journal refuses ${kind}`, async (t) => {
    const f = await fixture(t); await f.run('enable'); const file = join(f.directory, 'journal.json');
    if (kind === 'malformed') await writeFile(file, '{');
    if (kind === 'oversized') await writeFile(file, ' '.repeat(65537));
    if (kind === 'public-mode') await chmod(file, 0o644);
    if (kind === 'symlink') { await rm(file); await symlink('missing', file); }
    if (kind === 'hardlink') await link(file, join(f.directory, 'alias'));
    if (kind === 'public-directory') await chmod(f.directory, 0o755);
    await assert.rejects(f.run('recover')); assert.ok(f.state.guard); assert.deepEqual(f.state.settings, managed);
  });
}
test('resolved schema rejects unknown fields, invalid identities and unreachable states', async (t) => {
  const f = await fixture(t); await f.run('enable'); const record = await readResolvedJournal(f.directory);
  for (const mutate of [
    (r) => { r.extra = '/etc/resolv.conf'; }, (r) => { r.schema = 2; }, (r) => { r.backend = 'host'; },
    (r) => { r.context.busId = 'bad'; }, (r) => { r.context.owner = 'org.freedesktop.resolve1'; },
    (r) => { r.context.link.ifindex = 1; }, (r) => { r.context.scope.net = 'host'; },
    (r) => { r.stage = 'released'; }, (r) => { r.pending = true; }, (r) => { r.cursor = 4; },
    (r) => { r.start.Domains = [['foreign.test', true]]; }, (r) => { r.original.DNSEx = []; },
    (r) => { r.managed.DNSEx[0][2] = 53; }, (r) => { r.direction = 'restore'; r.start.DefaultRoute = true; },
  ]) { const value = structuredClone(record); mutate(value); assert.throws(() => validateResolvedJournal(value)); }
  record.context.scope.pid = 'pid:[99]'; await writeResolvedJournal(f.directory, record);
  await assert.rejects(f.run('recover'), /stale namespace/); assert.ok(f.state.guard);
});
test('journal backend pins unique owner, detects bus restart and rechecks guard removal', async () => {
  let ctx = structuredClone(context), settings = structuredClone(baseline), release = 0, called;
  const bus = { id: async () => ctx.busId, owner: async () => ctx.owner,
    property: async (owner, index, key) => { assert.equal(owner, ctx.owner); assert.equal(index, 2); return structuredClone(settings[key]); },
    set: async (owner, args) => { called = { owner, args }; } };
  const backend = createResolvedJournalBackend({ bus, ifindex: 2, identity: async () => structuredClone(ctx.link), scope,
    ensureGuard: async () => {}, removeGuard: async () => { release++; }, probe: async () => {}, port: 1053 });
  const view = await backend.view(); assert.deepEqual(view.context, context);
  await backend.set(context, 'DefaultRoute', true, baseline); assert.equal(called.owner, ':1.2');
  ctx.busId = 'd'.repeat(32);
  await assert.rejects(backend.set(context, 'DefaultRoute', true, baseline), /context changed/);
  await assert.rejects(backend.removeGuard(context, baseline), /context changed/); assert.equal(release, 0);
  ctx = structuredClone(context); settings.Domains = [['foreign.test', true]];
  await assert.rejects(backend.removeGuard(context, baseline), /ownership conflict/); assert.equal(release, 0);
  settings = structuredClone(baseline); await backend.removeGuard(context, baseline); assert.equal(release, 1);
});
