/** File backends only; OS authority and the lifecycle lock belong to the caller.
 * The original fixture factory keeps all files private. The public-layout
 * factory separates a readable resolver from private snapshots/journal. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { open, lstat, readlink, symlink, rename, realpath, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { privateJournalDirectory, syncDirectory } from './dns-lifecycle-journal.mjs';
import { RESOLVER_TARGET, RESOLVER_MANAGED, resolverHash, validateResolverContext, validateResolverObject } from './dns-resolver-object-journal.mjs';

async function snapshot(path) {
  const before = await lstat(path, { bigint: true });
  assert.equal(before.nlink, 1n); assert.equal(before.uid, BigInt(process.getuid())); assert.equal(before.gid, BigInt(process.getgid()));
  let kind, value;
  if (before.isSymbolicLink()) { kind = 'symlink'; value = await readlink(path); }
  else {
    assert.ok(before.isFile(), 'resolver must be a regular file or symlink'); kind = 'file';
    const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const stat = await fd.stat({ bigint: true }); assert.equal(stat.ino, before.ino); assert.equal(stat.dev, before.dev);
      assert.ok(stat.size > 0n && stat.size <= 4096n);
      const buffer = Buffer.alloc(4097), { bytesRead } = await fd.read(buffer, 0, buffer.length, 0);
      assert.equal(BigInt(bytesRead), stat.size); value = resolverHash(buffer.subarray(0, bytesRead));
      assert.equal((await fd.stat({ bigint: true })).ctimeNs, before.ctimeNs);
    } finally { await fd.close(); }
  }
  const after = await lstat(path, { bigint: true });
  assert.equal(after.dev, before.dev); assert.equal(after.ino, before.ino); assert.equal(after.ctimeNs, before.ctimeNs);
  return validateResolverObject({ kind, value, identity: `${before.dev}:${before.ino}`, uid: Number(before.uid), gid: Number(before.gid), mode: Number(before.mode & 0o7777n) });
}
async function mountIdentity(path) {
  const fd = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const match = /^mnt_id:\s+(\d+)$/m.exec(await readFile(`/proc/self/fdinfo/${fd.fd}`, 'utf8'));
    assert.ok(match, 'mount identity unavailable'); return match[1];
  } finally { await fd.close(); }
}
export const createResolverObjectFiles = (options) => buildFiles(options, null);
export async function createPublicResolverObjectFiles({ targetDirectory, ...options }) {
  assert.equal(process.platform, 'linux');
  assert.equal(options.baseline, 'localhost-file', 'public resolver requires reviewed healthy baseline');
  assert.equal(typeof targetDirectory, 'string');
  assert.equal(resolve(targetDirectory), targetDirectory, 'absolute canonical target directory required');
  assert.equal(typeof options.checkEnvironment, 'function', 'OS ownership/authority check required');
  return buildFiles(options, targetDirectory);
}
async function buildFiles({ directory, identity, checkEnvironment, ensureGuard, probe,
  baseline = 'dangling-stub', checkpoint = async () => {} }, targetDirectory) {
  assert.ok(['dangling-stub', 'localhost-file'].includes(baseline), 'unsupported resolver baseline');
  const originalKind = baseline === 'dangling-stub' ? 'symlink' : 'file';
  await privateJournalDirectory(directory); assert.equal(await realpath(directory), resolve(directory));
  const initial = await lstat(directory, { bigint: true }), directoryIdentity = `${initial.dev}:${initial.ino}`;
  const currentDirectory = targetDirectory ?? directory;
  const paths = { current: join(currentDirectory, 'resolv.conf'), managed: join(directory, 'managed.conf'), restored: join(directory, 'restored.conf') };
  const publicDirectory = async () => {
    assert.equal(await realpath(currentDirectory), resolve(currentDirectory));
    const s = await lstat(currentDirectory, { bigint: true });
    assert.ok(s.isDirectory() && s.uid === BigInt(process.getuid()) && s.gid === BigInt(process.getgid()));
    assert.equal(s.mode & 0o7777n, 0o755n, 'public resolver directory must be searchable/readable');
    assert.equal(s.dev, initial.dev, 'atomic resolver replacement requires same filesystem');
    assert.equal(await mountIdentity(currentDirectory), await mountIdentity(directory),
      'atomic resolver replacement requires same mount, not only same device');
    assert.notEqual(`${s.dev}:${s.ino}`, directoryIdentity);
    const mounts = (await readFile('/proc/self/mountinfo', 'utf8')).split('\n').map((line) =>
      line.split(' ')[4]?.replace(/\\([0-7]{3})/g, (_all, octal) => String.fromCharCode(parseInt(octal, 8))));
    for (const path of Object.values(paths)) assert.ok(!mounts.includes(resolve(path)), 'resolver object must not be a mountpoint');
    return `${s.dev}:${s.ino}`;
  };
  // Before any staging writes. Re-created backends also bind this identity into
  // the journal context, so replacing the public directory cannot reset trust.
  await checkEnvironment();
  const targetDirectoryIdentity = targetDirectory ? await publicDirectory() : undefined;
  const context = async () => {
    await privateJournalDirectory(directory); assert.equal(await realpath(directory), resolve(directory));
    const stat = await lstat(directory, { bigint: true }); assert.equal(`${stat.dev}:${stat.ino}`, directoryIdentity, 'directory replaced');
    await checkEnvironment();
    if (targetDirectory) assert.equal(await publicDirectory(), targetDirectoryIdentity, 'public resolver directory replaced');
    return validateResolverContext({ ...await identity(), directoryIdentity,
      ...(targetDirectory ? { targetDirectoryIdentity } : {}) });
  };
  const view = async () => ({ context: await context(), snapshot: await snapshot(paths.current) });
  const match = async (r, expected) => {
    const v = await view(); assert.deepEqual(v.context, r.context, 'resolver context changed'); assert.deepEqual(v.snapshot, expected, 'resolver ownership conflict');
  };
  const writeLocalhost = async (path) => {
    const fd = await open(path, 'wx', 0o644);
    try { await fd.chmod(0o644); await fd.writeFile(RESOLVER_MANAGED); await fd.sync(); } finally { await fd.close(); }
  };
  const backend = { ensureGuard, probe, view,
    async prepare() {
      const v = await view(); assert.equal(v.snapshot.kind, originalKind, 'resolver baseline selection mismatch');
      await writeLocalhost(paths.managed);
      await checkpoint('managed:file-synced');
      if (originalKind === 'symlink') await symlink(RESOLVER_TARGET, paths.restored);
      else { await writeLocalhost(paths.restored); await checkpoint('restored:file-synced'); }
      await syncDirectory(directory); await checkpoint('snapshots:dir-synced');
      const r = { context: v.context, original: v.snapshot, managed: await snapshot(paths.managed), restored: await snapshot(paths.restored) };
      await match(r, r.original); return r;
    },
    async verifySnapshots(r) {
      assert.equal(r.original.kind, originalKind, 'resolver baseline selection mismatch');
      const v = await view(); assert.deepEqual(v.context, r.context, 'resolver context changed');
      for (const name of ['managed', 'restored']) {
        if (v.snapshot.identity === r[name].identity) { assert.deepEqual(v.snapshot, r[name]); continue; }
        if (name === 'managed' && v.snapshot.identity === r.restored.identity) continue;
        assert.deepEqual(await snapshot(paths[name]), r[name], 'resolver snapshot changed');
      }
    },
    async select(r, expected) {
      assert.ok(['apply-intent', 'restore-intent'].includes(r.phase));
      const name = r.phase === 'apply-intent' ? 'managed' : 'restored';
      await backend.verifySnapshots(r); await match(r, expected); assert.deepEqual(await snapshot(paths[name]), r[name]);
      // Owned directory + caller's flock; not CAS against hostile same-uid/root writers.
      const direction = r.phase === 'apply-intent' ? 'apply' : 'restore';
      await rename(paths[name], paths.current); await checkpoint(`${direction}:object:renamed`);
      if (targetDirectory) {
        await syncDirectory(currentDirectory); await checkpoint(`${direction}:target:dir-synced`);
      }
      await syncDirectory(directory); await checkpoint(`${direction}:object:dir-synced`);
      await match(r, r[name]);
    },
  };
  return backend;
}
