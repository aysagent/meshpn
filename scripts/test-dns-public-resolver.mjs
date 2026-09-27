import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, chmod, readFile, writeFile, rename, rm, realpath, readdir, symlink, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPublicResolverObjectFiles } from './lib/dns-resolver-object-files.mjs';
import { resolverObjectTransaction, readResolverObjectJournal, RESOLVER_MANAGED, RESOLVER_TARGET } from './lib/dns-resolver-object-journal.mjs';

const scope = { net: 'net:[1]', mnt: 'mnt:[2]', pid: 'pid:[3]' };
async function fixture(t, separateSnapshots = false) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'meshpn-public-resolver-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const directory = join(root, 'private'), targetDirectory = join(root, 'public');
  await mkdir(directory, { mode: 0o700 }); await mkdir(targetDirectory, { mode: 0o755 }); await chmod(targetDirectory, 0o755);
  const snapshots = separateSnapshots ? join(root, 'snapshots') : directory;
  if (separateSnapshots) await mkdir(snapshots, { mode: 0o700 });
  const path = join(targetDirectory, 'resolv.conf'); await writeFile(path, RESOLVER_MANAGED, { mode: 0o644 }); await chmod(path, 0o644);
  let allowed = true, ready = true, protectedDns = false, hook = async () => {};
  const options = { directory: snapshots, targetDirectory, baseline: 'localhost-file',
    identity: async () => ({ scope, bootId: '12345678-1234-1234-1234-123456789abc' }),
    checkEnvironment: async () => assert.ok(allowed, 'authority lost'),
    ensureGuard: async () => { protectedDns = true; },
    probe: async () => { assert.ok(protectedDns); assert.ok(ready, 'not ready'); }, checkpoint: (p) => hook(p) };
  let backend = await createPublicResolverObjectFiles(options);
  return { root, directory, snapshots, targetDirectory, path, options,
    deny: () => { allowed = false; }, offline: () => { ready = false; },
    recreate: async () => { backend = await createPublicResolverObjectFiles(options); },
    run: (operation, cut) => {
      hook = async (p) => { if (p === cut) throw new Error('cut'); };
      return resolverObjectTransaction({ directory, scope, backend, operation, checkpoint: (p) => hook(p) });
    } };
}
test('public resolver is separate from private journal/snapshots through apply and offline restore', async (t) => {
  const f = await fixture(t); assert.equal((await f.run('enable')).status, 'active');
  const r = await readResolverObjectJournal(f.directory);
  assert.notEqual(r.context.targetDirectoryIdentity, r.context.directoryIdentity);
  assert.deepEqual(await readdir(f.targetDirectory), ['resolv.conf']);
  assert.equal((await lstat(f.targetDirectory)).mode & 0o777, 0o755);
  assert.equal((await lstat(f.directory)).mode & 0o777, 0o700);
  assert.equal((await lstat(f.path)).mode & 0o777, 0o644);
  assert.equal((await lstat(join(f.directory, 'journal.json'))).mode & 0o777, 0o600);
  f.offline(); assert.equal((await f.run('disable')).status, 'restored');
  assert.equal(await readFile(f.path, 'utf8'), RESOLVER_MANAGED);
  assert.deepEqual(await readdir(f.targetDirectory), ['resolv.conf']);
  assert.equal((await f.run('recover')).status, 'restored');
});
test('journal can be separate from same-mount private snapshots and public resolver', async (t) => {
  const f = await fixture(t, true); await f.run('enable');
  const r = await readResolverObjectJournal(f.directory), s = await lstat(f.snapshots);
  assert.equal(r.context.directoryIdentity, `${s.dev}:${s.ino}`);
  assert.deepEqual(await readdir(f.directory), ['journal.json']);
  assert.deepEqual(await readdir(f.snapshots), ['restored.conf']);
  await f.recreate(); f.offline(); await f.run('disable');
  assert.deepEqual(await readdir(f.snapshots), []);
  assert.equal(await readFile(f.path, 'utf8'), RESOLVER_MANAGED);
});
for (const cut of ['prepared', 'apply-intent', 'apply:object:renamed', 'apply:target:dir-synced', 'apply:object:dir-synced',
  'active', 'restore-intent', 'restore:object:renamed', 'restore:target:dir-synced', 'restore:object:dir-synced', 'restored']) {
  test(`public/private recovery at ${cut}`, async (t) => {
    const f = await fixture(t), restore = cut.startsWith('restore');
    if (restore) await f.run('enable');
    await assert.rejects(f.run(restore ? 'disable' : 'enable', cut), /cut/);
    await f.recreate(); assert.equal((await f.run('recover')).status, restore ? 'restored' : 'active');
    assert.equal(await readFile(f.path, 'utf8'), RESOLVER_MANAGED);
    assert.deepEqual(await readdir(f.targetDirectory), ['resolv.conf']);
  });
}
test('replacing public parent is rejected even after recreating backend and moving exact current inode', async (t) => {
  const f = await fixture(t); await f.run('enable');
  const before = await readFile(join(f.directory, 'journal.json'));
  await rename(f.targetDirectory, `${f.targetDirectory}-old`); await mkdir(f.targetDirectory, { mode: 0o755 }); await chmod(f.targetDirectory, 0o755);
  await rename(`${f.targetDirectory}-old/resolv.conf`, f.path);
  await f.recreate(); await assert.rejects(f.run('disable'), /context changed/);
  assert.deepEqual(await readFile(join(f.directory, 'journal.json')), before);
});
for (const kind of ['mode', 'bytes', 'dangling', 'authority']) test(`public resolver refuses ${kind} without journal changes`, async (t) => {
  const f = await fixture(t); await f.run('enable'); const before = await readFile(join(f.directory, 'journal.json'));
  if (kind === 'mode') await chmod(f.targetDirectory, 0o777);
  if (kind === 'bytes') await writeFile(f.path, 'nameserver 8.8.8.8\n');
  if (kind === 'dangling') { await rename(f.path, `${f.path}-old`); await symlink(RESOLVER_TARGET, f.path); }
  if (kind === 'authority') f.deny();
  await assert.rejects(f.run('disable')); assert.deepEqual(await readFile(join(f.directory, 'journal.json')), before);
});
test('public factory requires explicit healthy baseline and never creates files on refusal', async (t) => {
  const f = await fixture(t);
  for (const options of [{ baseline: 'dangling-stub' }, { baseline: undefined }, { checkEnvironment: undefined },
    { targetDirectory: '' }, { targetDirectory: 'relative' }, { targetDirectory: f.directory }])
    await assert.rejects(createPublicResolverObjectFiles({ ...f.options, ...options }));
  assert.deepEqual(await readdir(f.directory), []); assert.deepEqual(await readdir(f.targetDirectory), ['resolv.conf']);
});
