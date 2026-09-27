import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, realpath, mkdir, writeFile, readFile, symlink, readlink, rm, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createDnsmasqJournalFiles } from './lib/dnsmasq-journal-files.mjs';
import { createResolverObjectFiles } from './lib/dns-resolver-object-files.mjs';
import { readDnsmasqJournal } from './lib/dnsmasq-journal.mjs';
import { RESOLVER_TARGET, RESOLVER_MANAGED, readResolverObjectJournal } from './lib/dns-resolver-object-journal.mjs';
import { pairRadxaBackends, radxaDnsTransaction, inspectRadxaTransaction, readRadxaJournal } from './lib/dns-radxa-journal.mjs';
import { RADXA_APPLY_CUTS, RADXA_RESTORE_CUTS } from './lib/dns-radxa-crash-lab.mjs';
import { verifyRadxaGuardRestore } from './lib/dns-radxa-guard-restore.mjs';
const scope = { net: 'net:[1]', mnt: 'mnt:[2]', pid: 'pid:[3]' };
const baseline = await readFile(new URL('./fixtures/dns-clients/radxa-dnsmasq.conf', import.meta.url), 'utf8');
const crash = (at) => async (p) => { if (p === at) throw new Error('interruption'); };
async function fixture(t, resolverBaseline = 'dangling-stub') {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'meshpn-radxa-test-'))), resolverDir = join(directory, 'resolver-etc');
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(resolverDir, { mode: 0o700 }); await mkdir(join(directory, 'radxa'), { mode: 0o700 });
  await writeFile(join(directory, 'dnsmasq.conf'), baseline, { mode: 0o600 });
  if (resolverBaseline === 'localhost-file') {
    await writeFile(join(resolverDir, 'resolv.conf'), RESOLVER_MANAGED); await chmod(join(resolverDir, 'resolv.conf'), 0o644);
  } else await symlink(RESOLVER_TARGET, join(resolverDir, 'resolv.conf'));
  const state = { guard: false, ready: true, loaded: null, events: [],
    bootId: '12345678-1234-1234-1234-123456789abc', targetMissing: true };
  const ensureGuard = async () => { state.guard = true; }, identity = () => ({ scope, bootId: state.bootId });
  const dnsmasq = await createDnsmasqJournalFiles({ directory, port: 1053, normalizeDhcpDns: true,
    identity: async () => ({ ...identity(), executableSha256: 'a'.repeat(64), link: { ifindex: 2, ifname: 'usb0', address: '02:00:00:00:00:01' } }),
    ensureGuard, removeGuard: async () => { throw new Error('guard release forbidden'); },
    probe: async () => { assert.ok(state.guard); assert.ok(state.ready, 'adapter down'); },
    activate: async (r) => { state.events.push(`daemon:${r.direction}`); state.loaded = r.direction; } });
  const resolver = await createResolverObjectFiles({ directory: resolverDir, baseline: resolverBaseline, identity, ensureGuard,
    checkEnvironment: async () => assert.ok(state.targetMissing),
    probe: async () => { assert.ok(state.guard); assert.ok(state.ready); assert.equal(state.loaded, 'apply'); } });
  const select = resolver.select;
  resolver.select = async (r, expected) => {
    if (r.phase === 'apply-intent') assert.equal(state.loaded, 'apply');
    state.events.push(`resolver:${r.phase}`); return select(r, expected);
  };
  const backend = pairRadxaBackends(dnsmasq, resolver);
  return { directory, resolverDir, backend, state,
    run: (operation, checkpoint) => radxaDnsTransaction({ directory, scope, backend, operation, checkpoint }),
    inspect: () => inspectRadxaTransaction({ directory, scope, backend }) };
}
test('paired lifecycle: daemon before resolver, reverse offline rollback, stable id, guard retained', async (t) => {
  const f = await fixture(t), active = await f.run('enable'); assert.equal(active.status, 'active');
  assert.deepEqual(await f.run('recover'), active);
  f.state.ready = false;
  const restored = await f.run('disable'); assert.equal(restored.status, 'restored'); assert.equal(restored.id, active.id);
  assert.equal(restored.protectionRetained, true); assert.ok(f.state.guard);
  assert.equal(await readFile(join(f.directory, 'dnsmasq.conf'), 'utf8'), baseline);
  assert.equal(await readlink(join(f.resolverDir, 'resolv.conf')), RESOLVER_TARGET);
  assert.ok(f.state.events.indexOf('resolver:restore-intent') < f.state.events.indexOf('daemon:restore'));
  f.state.loaded = null;
  assert.deepEqual(await f.run('recover'), restored); assert.equal(f.state.loaded, 'restore');
  await assert.rejects(f.run('enable'), /already exists/);
});
test('Radxa guard release requires explicit localhost baseline and loaded restored daemon', async (t) => {
  const f = await fixture(t, 'localhost-file');
  const proof = (verifyDaemon = async () => f.state.loaded === 'restore') =>
    verifyRadxaGuardRestore({ directory: f.directory, scope, backend: f.backend, verifyDaemon });
  await f.run('enable'); await assert.rejects(proof());
  await f.run('disable'); assert.equal(await proof(), true);
  f.state.loaded = null; await assert.rejects(proof(), /daemon proof/);
  f.state.loaded = 'restore';
  await assert.rejects(proof(async () => { f.state.bootId = '22345678-1234-1234-1234-123456789abc'; return true; }));
});
test('Radxa guard proof refuses exact rollback to dangling stub and absent daemon proof', async (t) => {
  const f = await fixture(t); await f.run('enable'); await f.run('disable');
  let calls = 0;
  await assert.rejects(verifyRadxaGuardRestore({ directory: f.directory, scope, backend: f.backend,
    verifyDaemon: async () => { calls++; return true; } }), /localhost-file baseline/);
  assert.equal(calls, 0);
  const healthy = await fixture(t, 'localhost-file'); await healthy.run('enable'); await healthy.run('disable');
  await assert.rejects(verifyRadxaGuardRestore({ directory: healthy.directory, scope, backend: healthy.backend }), /daemon proof/);
});
test('Radxa guard proof rejects a foreign resolver and unfinished paired rollback', async (t) => {
  const f = await fixture(t, 'localhost-file'), proof = () => verifyRadxaGuardRestore({ directory: f.directory,
    scope, backend: f.backend, verifyDaemon: async () => true });
  await f.run('enable'); await assert.rejects(f.run('disable', crash('restore-dnsmasq')), /interruption/);
  await assert.rejects(proof()); await f.run('disable');
  await writeFile(join(f.resolverDir, 'resolv.conf'), 'nameserver 192.0.2.1\n'); await assert.rejects(proof());
});
for (const point of [...RADXA_APPLY_CUTS, ...RADXA_RESTORE_CUTS]) test(`paired localhost-file rollback after ${point}`, async (t) => {
  const f = await fixture(t, 'localhost-file'), restoring = RADXA_RESTORE_CUTS.includes(point);
  if (restoring) await f.run('enable');
  await assert.rejects(f.run(restoring ? 'disable' : 'enable', crash(point)), /interruption/);
  f.state.ready = false;
  const restored = await f.run('disable'); assert.equal(restored.status, 'restored'); assert.equal(restored.protectionRetained, true);
  assert.equal(await readFile(join(f.resolverDir, 'resolv.conf'), 'utf8'), RESOLVER_MANAGED);
  const r = await readResolverObjectJournal(f.resolverDir); assert.equal(r.original.kind, 'file'); assert.equal(r.restored.kind, 'file');
  assert.notEqual(r.restored.identity, r.original.identity); assert.notEqual(r.restored.identity, r.managed.identity);
  assert.equal(await readFile(join(f.directory, 'dnsmasq.conf'), 'utf8'), baseline);
  assert.deepEqual(await f.run('recover'), restored); assert.ok(f.state.guard);
});
const applyCuts = [...RADXA_APPLY_CUTS, ...['dnsmasq', 'resolver', 'active'].flatMap((p) => ['file-synced', 'renamed', 'dir-synced'].map((s) => `${p}:${s}`))];
const restoreCuts = [...RADXA_RESTORE_CUTS, ...['restore-resolver', 'restore-dnsmasq', 'restored'].flatMap((p) => ['file-synced', 'renamed', 'dir-synced'].map((s) => `${p}:${s}`))];
for (const [direction, points] of [['apply', applyCuts], ['restore', restoreCuts]]) for (const point of points) {
  test(`paired recovery after ${point}`, async (t) => {
    const f = await fixture(t); if (direction === 'restore') await f.run('enable');
    await assert.rejects(f.run(direction === 'apply' ? 'enable' : 'disable', crash(point)), /interruption/);
    if (point === 'dnsmasq:file-synced') {
      await assert.rejects(f.run('recover'), { code: 'ENOENT' });
      assert.equal(await readFile(join(f.directory, 'dnsmasq.conf'), 'utf8'), baseline); return;
    }
    const r = await readRadxaJournal(f.directory);
    const expected = r.phase.startsWith('restore') ? 'restored' : 'active';
    assert.equal((await f.run('recover')).status, expected); assert.ok(f.state.guard);
  });
}
for (const point of RADXA_APPLY_CUTS) test(`explicit offline disable at ${point}`, async (t) => {
  const f = await fixture(t); await assert.rejects(f.run('enable', crash(point)), /interruption/);
  f.state.ready = false; assert.equal((await f.run('disable')).status, 'restored'); assert.ok(f.state.guard);
});
for (const point of ['seed-dnsmasq:file-synced', 'seed-dnsmasq:renamed', 'seed-resolver:file-synced', 'seed-resolver:dir-synced']) {
  test(`orphan seed not adopted: ${point}`, async (t) => {
    const f = await fixture(t); await assert.rejects(f.run('enable', crash(point)), /interruption/);
    await assert.rejects(f.run('recover'), { code: 'ENOENT' }); await assert.rejects(f.run('enable'));
    assert.equal(await readFile(join(f.directory, 'dnsmasq.conf'), 'utf8'), baseline);
    assert.equal(await readlink(join(f.resolverDir, 'resolv.conf')), RESOLVER_TARGET);
  });
}
for (const conflict of ['id', 'resolver-id', 'boot', 'target', 'missing-child', 'corrupt-parent', 'foreign-resolver', 'foreign-dnsmasq']) {
  test(`paired refuses ${conflict} before repairing either child`, async (t) => {
    const f = await fixture(t); await f.run('enable'); f.state.events.length = 0;
    const dpath = join(f.directory, 'journal.json'), rpath = join(f.resolverDir, 'journal.json');
    if (conflict === 'id' || conflict === 'resolver-id') {
      const path = conflict === 'id' ? dpath : rpath, r = JSON.parse(await readFile(path));
      r.id = 'b'.repeat(32); await writeFile(path, JSON.stringify(r));
    } else if (conflict === 'boot') f.state.bootId = '22345678-1234-1234-1234-123456789abc';
    else if (conflict === 'target') f.state.targetMissing = false;
    else if (conflict === 'missing-child') await rm(rpath);
    else if (conflict === 'corrupt-parent') await writeFile(join(f.directory, 'radxa', 'journal.json'), '{}');
    else await writeFile(conflict === 'foreign-resolver' ? join(f.resolverDir, 'resolv.conf') : join(f.directory, 'dnsmasq.conf'), 'foreign\n');
    const before = await readFile(join(f.directory, 'radxa', 'journal.json'));
    await assert.rejects(f.run('recover')); await assert.rejects(f.run('disable'));
    assert.equal(f.state.events.length, 0); assert.ok(f.state.guard);
    assert.deepEqual(await readFile(join(f.directory, 'radxa', 'journal.json')), before);
  });
}
test('dry-run has no guard/probes/daemon writes; active recovery reconciles daemon', async (t) => {
  const f = await fixture(t); await f.run('enable'); f.state.guard = false; f.state.ready = false; f.state.events.length = 0;
  assert.equal((await f.inspect()).readinessVerified, false); assert.equal(f.state.guard, false); assert.equal(f.state.events.length, 0);
  await assert.rejects(f.run('recover')); assert.ok(f.state.guard); assert.equal(f.state.events.length, 0);
  f.state.ready = true; f.state.loaded = null; await f.run('recover'); assert.equal(f.state.loaded, 'apply');
});
test('guard failure leaves both baseline objects and all journals untouched', async (t) => {
  const f = await fixture(t); f.backend.ensureGuard = async () => { throw new Error('guard failed'); };
  await assert.rejects(f.run('enable'), /guard failed/);
  await assert.rejects(readRadxaJournal(f.directory), { code: 'ENOENT' }); await assert.rejects(readDnsmasqJournal(f.directory), { code: 'ENOENT' });
  assert.equal(await readFile(join(f.directory, 'dnsmasq.conf'), 'utf8'), baseline);
});
