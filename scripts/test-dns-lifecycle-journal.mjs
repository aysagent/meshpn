import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm, readFile, writeFile, readdir, chmod, symlink, link, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateDnsJournal, writeDnsJournal, readDnsJournal } from './lib/dns-lifecycle-journal.mjs';
import { dnsTransaction, sameDnsObject, expectedDnsObjects } from './lib/dns-lifecycle-transaction.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

const scope = { net: 'net:[1]', mnt: 'mnt:[2]', pid: 'pid:[3]' };
const original = { identity: '1:11', sha256: 'a'.repeat(64) };
const managed = { identity: '1:12', sha256: 'b'.repeat(64) };
const restored = { identity: '1:13', sha256: original.sha256 };
const record = () => ({ schema: 1, backend: 'namespace-fixture', id: 'c'.repeat(32), scope: { ...scope },
  stage: 'prepared', original: { ...original }, managed: { ...managed }, restored: { ...restored } });
async function directory(t) {
  const path = await mkdtemp(join(tmpdir(), 'meshpn-journal-test-'));
  t.after(() => rm(path, { recursive: true, force: true })); return path;
}
async function fixture(t) {
  const path = await directory(t), log = [];
  const state = { current: original, guard: false, ready: true };
  const backend = {
    async ensureGuard() { state.guard = true; log.push('guard'); },
    async removeGuard() { assert.ok(sameDnsObject(state.current, restored)); state.guard = false; log.push('release'); },
    async current() { return { ...state.current }; },
    async prepare() { assert.ok(state.guard); return { original, managed, restored }; },
    async verifySnapshots(value) { assert.deepEqual(value.restored, restored); },
    async probe() { assert.ok(state.ready, 'not ready'); },
    async select(name, value, expected) {
      assert.ok(state.guard); assert.ok(expected.some((item) => sameDnsObject(item, state.current)));
      state.current = value[name]; log.push(name);
    },
  };
  const run = (operation, checkpoint) => dnsTransaction({ directory: path, scope, operation, backend, checkpoint });
  return { path, state, backend, log, run };
}

test('journal validates a bounded fixed schema, no paths/commands', () => {
  assert.deepEqual(validateDnsJournal(record()), record());
  for (const mutate of [
    (r) => { r.schema = 2; }, (r) => { r.backend = 'host'; }, (r) => { r.extra = '/etc/resolv.conf'; },
    (r) => { r.id = 'bad'; }, (r) => { r.stage = '__proto__'; }, (r) => { r.scope.net = 'host'; },
    (r) => { r.original.identity = '../../file'; }, (r) => { r.managed.sha256 = 'x'.repeat(64); },
    (r) => { r.restored.sha256 = r.managed.sha256; }, (r) => { r.scope.other = 'x'; },
  ]) { const value = record(); mutate(value); assert.throws(() => validateDnsJournal(value)); }
});
test('journal roundtrip keeps permissions private and writes no config content', async (t) => {
  const path = await directory(t); await writeDnsJournal(path, record());
  assert.deepEqual(await readDnsJournal(path), record());
  assert.equal((await stat(join(path, 'journal.json'))).mode & 0o777, 0o600);
  assert.ok(!(await readFile(join(path, 'journal.json'), 'utf8')).includes('nameserver'));
});
test('uncommitted first journal temp is never accepted as a snapshot', async (t) => {
  const path = await directory(t);
  await assert.rejects(writeDnsJournal(path, record(), async (point) => {
    if (point === 'prepared:file-synced') throw new Error('crash');
  }), /crash/);
  await assert.rejects(readDnsJournal(path), { code: 'ENOENT' });
  assert.equal((await readdir(path)).filter((file) => file.endsWith('.tmp')).length, 1);
});
for (const point of ['active:file-synced', 'active:renamed', 'active:dir-synced']) {
  test(`journal interruption at ${point} yields one complete version`, async (t) => {
    const path = await directory(t); await writeDnsJournal(path, record());
    await assert.rejects(writeDnsJournal(path, { ...record(), stage: 'active' }, async (stage) => {
      if (stage === point) throw new Error('interrupted');
    }), /interrupted/);
    assert.equal((await readDnsJournal(path)).stage, point.endsWith('file-synced') ? 'prepared' : 'active');
    if (point.endsWith('file-synced')) assert.equal((await readdir(path)).filter((file) => file.endsWith('.tmp')).length, 1);
  });
}
for (const kind of ['malformed', 'oversized', 'public-mode', 'symlink', 'hardlink', 'public-directory', 'symlink-directory']) {
  test(`journal refuses ${kind}`, async (t) => {
    const path = await directory(t), file = join(path, 'journal.json');
    await writeDnsJournal(path, record()); let readPath = path;
    if (kind === 'malformed') await writeFile(file, '{');
    if (kind === 'oversized') await writeFile(file, ' '.repeat(8193));
    if (kind === 'public-mode') await chmod(file, 0o644);
    if (kind === 'symlink') { await rm(file); await symlink('missing.json', file); }
    if (kind === 'hardlink') await link(file, join(path, 'alias'));
    if (kind === 'public-directory') await chmod(path, 0o755);
    if (kind === 'symlink-directory') {
      const outer = await directory(t); readPath = join(outer, 'alias'); await symlink(path, readPath);
    }
    await assert.rejects(readDnsJournal(readPath));
  });
}
test('enable requires an absent journal; restart preserves transaction id', async (t) => {
  const f = await fixture(t), first = await f.run('enable');
  assert.equal(first.status, 'active'); assert.ok(f.state.guard);
  await assert.rejects(f.run('enable'), /already exists/);
  assert.deepEqual(await f.run('recover'), first);
  const last = await f.run('disable'); assert.equal(last.id, first.id); assert.equal(last.status, 'released');
  assert.equal(f.state.guard, false); assert.deepEqual(f.state.current, restored);
  assert.deepEqual(await f.run('recover'), last); // terminal tombstone is replayable, not discarded
});
for (const point of ['prepared', 'apply-intent', 'applied', 'active:file-synced', 'active']) {
  test(`apply interruption ${point} resumes without restoring baseline`, async (t) => {
    const f = await fixture(t);
    await assert.rejects(f.run('enable', async (stage) => { if (stage === point) throw new Error('crash'); }), /crash/);
    const id = (await readDnsJournal(f.path)).id;
    assert.ok(f.state.guard); assert.equal((await f.run('recover')).id, id);
    assert.deepEqual(f.state.current, managed); assert.ok(!f.log.includes('release')); assert.ok(!f.log.includes('restored'));
  });
}
for (const point of ['restore-intent', 'restored-dns', 'restore-committed', 'guard-removed']) {
  test(`disable interruption ${point} finishes only the durable restore intent`, async (t) => {
    const f = await fixture(t); await f.run('enable');
    await assert.rejects(f.run('disable', async (stage) => { if (stage === point) throw new Error('crash'); }), /crash/);
    assert.equal((await f.run('recover')).status, 'released');
    assert.deepEqual(f.state.current, restored); assert.equal(f.state.guard, false);
    assert.ok(f.log.indexOf('restored') < f.log.indexOf('release'));
  });
}
test('missing/corrupt/stale journal never authorizes release', async (t) => {
  const f = await fixture(t); await assert.rejects(f.run('recover'), { code: 'ENOENT' }); assert.ok(f.state.guard);
  await f.run('enable'); const value = await readDnsJournal(f.path); value.scope.pid = 'pid:[999]';
  await writeDnsJournal(f.path, value); await assert.rejects(f.run('recover'), /stale namespace/);
  await writeFile(join(f.path, 'journal.json'), '{broken'); await assert.rejects(f.run('disable'));
  assert.ok(f.state.guard); assert.ok(!f.log.includes('release')); assert.deepEqual(f.state.current, managed);
});
test('identical text with a different inode is an ownership conflict', async (t) => {
  const f = await fixture(t); await f.run('enable'); f.state.current = { ...managed, identity: '1:999' };
  await assert.rejects(f.run('recover'), /ownership conflict/); await assert.rejects(f.run('disable'), /ownership conflict/);
  assert.equal(f.state.current.identity, '1:999'); assert.ok(f.state.guard);
});
test('race after readiness is rechecked before apply intent', async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.run('enable', async (point) => { if (point === 'ready') f.state.current = { ...managed, identity: '1:999' }; }), /ownership conflict/);
  assert.equal((await readDnsJournal(f.path)).stage, 'prepared'); assert.ok(f.state.guard);
});
test('readiness and restore backend failures retain guard and recoverable journal', async (t) => {
  const f = await fixture(t); f.state.ready = false;
  await assert.rejects(f.run('enable'), /not ready/); assert.ok(f.state.guard);
  f.state.ready = true; await f.run('recover');
  const select = f.backend.select; f.backend.select = async () => { throw new Error('mount failed'); };
  await assert.rejects(f.run('disable'), /mount failed/);
  assert.equal((await readDnsJournal(f.path)).stage, 'restoring'); assert.ok(f.state.guard);
  f.backend.select = select; assert.equal((await f.run('recover')).status, 'released');
});
test('foreign change after restore commit does not release guard', async (t) => {
  const f = await fixture(t); await f.run('enable');
  await assert.rejects(f.run('disable', async (point) => {
    if (point === 'restore-committed') f.state.current = { ...restored, identity: '1:999' };
  }), /ownership conflict/);
  assert.ok(f.state.guard); assert.ok(!f.log.includes('release'));
});
test('journal stage rejects unrelated objects and unknown stages', () => {
  assert.equal(sameDnsObject(undefined, undefined), false);
  assert.equal(sameDnsObject(original, undefined), false);
  assert.equal(expectedDnsObjects({ ...record(), stage: 'active' }).length, 1);
  assert.equal(expectedDnsObjects({ ...record(), stage: 'restored' }).length, 1);
  assert.throws(() => expectedDnsObjects({ ...record(), stage: 'unknown' }));
});
test('private crash worker refuses execution outside namespace parent', async () => {
  const result = await runCommand(process.execPath, ['scripts/lib/dns-lifecycle-crash-worker.mjs'], { env: cleanEnvironment(process.env) });
  assert.equal(result.reason, null); assert.equal(result.code, 2); assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'DNS_CONTROLLER_REFUSED\n');
});
