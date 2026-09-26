import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, symlink, readlink, readFile, writeFile, rename, rm, chmod, link, mkdir, readdir, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { queryNamespaceDns53 } from './lib/transparent-dns-lab.mjs';
import { createResolverObjectFiles } from './lib/dns-resolver-object-files.mjs';
import { RESOLVER_TARGET, RESOLVER_MANAGED, resolverObjectTransaction, readResolverObjectJournal,
  inspectResolverObjectTransaction } from './lib/dns-resolver-object-journal.mjs';
const scope = { net: 'net:[1]', mnt: 'mnt:[2]', pid: 'pid:[3]' };
test('namespace-only port 53 probe refuses ordinary host execution before sending DNS', async () => {
  await assert.rejects(queryNamespaceDns53(Buffer.alloc(12)));
});
async function fixture(t) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'meshpn-resolver-object-test-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'resolv.conf'); await symlink(RESOLVER_TARGET, path);
  const state = { guard: false, ready: true, targetMissing: true, mounted: false, probes: 0,
    context: { scope: structuredClone(scope), bootId: '12345678-1234-1234-1234-123456789abc' } };
  let hook = async () => {};
  const backend = await createResolverObjectFiles({ directory, identity: async () => structuredClone(state.context),
    checkEnvironment: async () => { assert.ok(state.targetMissing, 'target appeared'); assert.equal(state.mounted, false, 'mountpoint'); },
    ensureGuard: async () => { state.guard = true; }, probe: async () => { state.probes++; assert.ok(state.guard); assert.ok(state.ready, 'not ready'); },
    checkpoint: (p) => hook(p) });
  return { directory, path, backend, state,
    run: (operation, checkpoint = async () => {}) => { hook = checkpoint; return resolverObjectTransaction({ directory, operation, scope, backend, checkpoint }); },
    inspect: () => inspectResolverObjectTransaction({ directory, scope, backend }) };
}
const interrupt = (at) => async (p) => { if (at === p) throw new Error('interruption'); };
test('guard failure cannot prepare snapshots or write a journal', async (t) => {
  const f = await fixture(t); f.backend.ensureGuard = async () => { throw new Error('guard unavailable'); };
  const files = await readdir(f.directory);
  await assert.rejects(f.run('enable'), /guard unavailable/);
  assert.deepEqual(await readdir(f.directory), files); assert.equal(f.state.probes, 0);
  assert.equal(await readlink(f.path), RESOLVER_TARGET);
});
test('resolver object lifecycle switches nofollow, restores exact link text, never releases guard', async (t) => {
  const f = await fixture(t), original = await f.backend.view();
  const active = await f.run('enable'); assert.equal(active.status, 'active'); assert.equal(active.protectionRetained, true);
  assert.equal(await readFile(f.path, 'utf8'), RESOLVER_MANAGED); assert.ok(f.state.guard);
  assert.deepEqual(await f.run('recover'), active);
  const r = await readResolverObjectJournal(f.directory); assert.deepEqual(r.original, original.snapshot);
  f.state.ready = false; const restored = await f.run('disable'); assert.equal(restored.status, 'restored'); assert.ok(f.state.guard);
  assert.equal(await readlink(f.path), RESOLVER_TARGET); assert.notEqual((await f.backend.view()).snapshot.identity, original.snapshot.identity);
  assert.deepEqual(await f.run('recover'), restored); await assert.rejects(f.run('enable'), /already exists/);
});
for (const direction of ['apply', 'restore']) {
  const phases = direction === 'apply' ? ['prepared', 'apply-intent', 'active'] : ['restore-intent', 'restored'];
  const points = phases.flatMap((p) => [p, ...['file-synced', 'renamed', 'dir-synced'].map((s) => `${p}:${s}`)]);
  points.push(`${direction}:set`, `${direction}:object:renamed`, `${direction}:object:dir-synced`);
  if (direction === 'apply') points.push('ready');
  for (const point of new Set(points)) test(`resolver object interruption at ${point}`, async (t) => {
    const f = await fixture(t); if (direction === 'restore') await f.run('enable');
    await assert.rejects(f.run(direction === 'apply' ? 'enable' : 'disable', interrupt(point)), /interruption/);
    if (point === 'prepared:file-synced') {
      await assert.rejects(f.run('recover'), { code: 'ENOENT' }); assert.equal(await readlink(f.path), RESOLVER_TARGET); return;
    }
    const r = await readResolverObjectJournal(f.directory);
    const restore = ['restore-intent', 'restored'].includes(r.phase);
    assert.equal((await f.run('recover')).status, restore ? 'restored' : 'active'); assert.ok(f.state.guard);
    if (restore) assert.equal(await readlink(f.path), RESOLVER_TARGET);
    else assert.equal(await readFile(f.path, 'utf8'), RESOLVER_MANAGED);
  });
}
for (const point of ['prepared', 'apply-intent', 'apply:set', 'active']) test(`explicit offline disable after ${point}`, async (t) => {
  const f = await fixture(t); await assert.rejects(f.run('enable', interrupt(point)), /interruption/);
  f.state.ready = false; assert.equal((await f.run('disable')).status, 'restored'); assert.ok(f.state.guard);
  assert.equal(await readlink(f.path), RESOLVER_TARGET);
});
test('dry-run has no guard/probe/writes; readiness failure leaves original symlink', async (t) => {
  const f = await fixture(t); f.state.ready = false; await assert.rejects(f.run('enable'), /not ready/);
  const before = await readFile(join(f.directory, 'journal.json')), files = await readdir(f.directory), probes = f.state.probes;
  f.state.guard = false; const r = await f.inspect(); assert.equal(r.readinessVerified, false); assert.equal(r.systemSettingsChanged, false);
  assert.equal(f.state.guard, false); assert.equal(f.state.probes, probes); assert.deepEqual(await readdir(f.directory), files);
  assert.deepEqual(await readFile(join(f.directory, 'journal.json')), before); assert.equal(await readlink(f.path), RESOLVER_TARGET);
});
for (const mutation of ['foreign-link', 'foreign-file', 'same-bytes-new-inode', 'mode', 'hardlink', 'corrupt-journal', 'missing-journal',
  'missing-snapshot', 'changed-snapshot', 'stale-boot', 'stale-namespace', 'target-appeared', 'mounted']) {
  test(`resolver refuses ${mutation} under guard`, async (t) => {
    const f = await fixture(t); await f.run('enable');
    if (mutation === 'foreign-link') { await rename(f.path, join(f.directory, 'saved')); await symlink('/foreign', f.path); }
    if (mutation === 'foreign-file') await writeFile(f.path, 'nameserver 8.8.8.8\n');
    if (mutation === 'same-bytes-new-inode') { await writeFile(join(f.directory, 'foreign'), RESOLVER_MANAGED, { mode: 0o644 }); await rename(join(f.directory, 'foreign'), f.path); }
    if (mutation === 'mode') await chmod(f.path, 0o666);
    if (mutation === 'hardlink') await link(f.path, join(f.directory, 'hardlink'));
    if (mutation === 'corrupt-journal') await writeFile(join(f.directory, 'journal.json'), '{');
    if (mutation === 'missing-journal') await rename(join(f.directory, 'journal.json'), join(f.directory, 'saved-journal'));
    if (mutation === 'missing-snapshot') await rename(join(f.directory, 'restored.conf'), join(f.directory, 'saved-snapshot'));
    if (mutation === 'changed-snapshot') { await rename(join(f.directory, 'restored.conf'), join(f.directory, 'saved-snapshot')); await symlink('/foreign', join(f.directory, 'restored.conf')); }
    if (mutation === 'stale-boot') f.state.context.bootId = '98765432-1234-1234-1234-123456789abc';
    if (mutation === 'stale-namespace') f.state.context.scope.net = 'net:[99]';
    if (mutation === 'target-appeared') f.state.targetMissing = false;
    if (mutation === 'mounted') f.state.mounted = true;
    const before = await readFile(join(f.directory, 'journal.json')).catch((e) => { assert.equal(e.code, 'ENOENT'); return null; });
    f.state.guard = false; await assert.rejects(f.run('disable')); assert.ok(f.state.guard);
    assert.deepEqual(await readFile(join(f.directory, 'journal.json')).catch(() => null), before);
  });
}
for (const kind of ['file', 'different-link', 'directory']) test(`unsupported baseline ${kind} has no journal or snapshots`, async (t) => {
  const f = await fixture(t); await rename(f.path, join(f.directory, 'saved'));
  if (kind === 'file') await writeFile(f.path, RESOLVER_MANAGED, { mode: 0o644 });
  else if (kind === 'different-link') await symlink('/different', f.path); else await mkdir(f.path);
  await assert.rejects(f.run('enable')); assert.ok(f.state.guard);
  for (const name of ['journal.json', 'managed.conf', 'restored.conf']) assert.ok(!(await readdir(f.directory)).includes(name));
});
for (const point of ['managed:file-synced', 'snapshots:dir-synced']) test(`orphan preparation ${point} is never adopted`, async (t) => {
  const f = await fixture(t); await assert.rejects(f.run('enable', interrupt(point)), /interruption/);
  await assert.rejects(f.run('recover'), { code: 'ENOENT' }); await assert.rejects(f.run('enable'), { code: 'EEXIST' });
  assert.equal(await readlink(f.path), RESOLVER_TARGET); assert.ok(f.state.guard);
});
