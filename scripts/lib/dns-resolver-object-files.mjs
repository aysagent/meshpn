/** Fixed names inside an owned 0700 fixture directory. Never accepts /etc as a target. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { open, lstat, readlink, symlink, rename, realpath } from 'node:fs/promises';
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
export async function createResolverObjectFiles({ directory, identity, checkEnvironment, ensureGuard, probe, checkpoint = async () => {} }) {
  await privateJournalDirectory(directory); assert.equal(await realpath(directory), resolve(directory));
  const initial = await lstat(directory, { bigint: true }), directoryIdentity = `${initial.dev}:${initial.ino}`;
  const paths = { current: join(directory, 'resolv.conf'), managed: join(directory, 'managed.conf'), restored: join(directory, 'restored.conf') };
  const context = async () => {
    await privateJournalDirectory(directory); assert.equal(await realpath(directory), resolve(directory));
    const stat = await lstat(directory, { bigint: true }); assert.equal(`${stat.dev}:${stat.ino}`, directoryIdentity, 'directory replaced');
    await checkEnvironment(); return validateResolverContext({ ...await identity(), directoryIdentity });
  };
  const view = async () => ({ context: await context(), snapshot: await snapshot(paths.current) });
  const match = async (r, expected) => {
    const v = await view(); assert.deepEqual(v.context, r.context, 'resolver context changed'); assert.deepEqual(v.snapshot, expected, 'resolver ownership conflict');
  };
  const backend = { ensureGuard, probe, view,
    async prepare() {
      const v = await view(); assert.equal(v.snapshot.kind, 'symlink', 'only reviewed dangling symlink baseline supported');
      const fd = await open(paths.managed, 'wx', 0o644);
      try { await fd.chmod(0o644); await fd.writeFile(RESOLVER_MANAGED); await fd.sync(); } finally { await fd.close(); }
      await checkpoint('managed:file-synced');
      await symlink(RESOLVER_TARGET, paths.restored); await syncDirectory(directory); await checkpoint('snapshots:dir-synced');
      const r = { context: v.context, original: v.snapshot, managed: await snapshot(paths.managed), restored: await snapshot(paths.restored) };
      await match(r, r.original); return r;
    },
    async verifySnapshots(r) {
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
      await syncDirectory(directory); await checkpoint(`${direction}:object:dir-synced`);
      await match(r, r[name]);
    },
  };
  return backend;
}
