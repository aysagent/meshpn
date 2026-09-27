/** Inactive-only code publication. No service, DNS, opt-in or host CLI here.
 * Caller supplies a real inactive proof and holds its stable deployment flock.
 * Tests use a private root. Removed code is quarantined, never recursively erased. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { open, lstat, realpath, readFile, readdir, mkdir } from 'node:fs/promises';
import { join, dirname, resolve } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { inspectDnsInstalledBundle, validateDnsInstalledBundle } from './dns-installed-authority.mjs';
import { privateJournalDirectory, syncDirectory, readPrivateJournal, writePrivateJournal } from './dns-lifecycle-journal.mjs';
import { assertDnsCommandLock, inspectDnsSystemExecutable, runLockedDnsCommand } from './dns-system-command.mjs';

const LIMIT = 262144;
const hash = (v) => createHash('sha256').update(v).digest('hex');
const id = (s) => `${s.dev}:${s.ino}:${s.mode}`;
const fileId = (s) => `${s.dev}:${s.ino}:${s.ctimeNs}:${s.mode}`;
const keys = (v, names) => {
  assert.ok(v && typeof v === 'object' && !Array.isArray(v));
  assert.deepEqual(Object.keys(v).sort(), [...names].sort());
};
const absent = async (path) => {
  try { await lstat(path); return false; } catch (e) { if (e.code === 'ENOENT') return true; throw e; }
};
function bundleDirectories(files) {
  const dirs = new Set(['']);
  for (const path of Object.keys(files)) for (let p = dirname(path); p !== '.'; p = dirname(p)) dirs.add(p);
  return [...dirs].sort();
}
function validateSnapshot(v) {
  keys(v, ['rootIdentity', 'manifestIdentity', 'sha256', 'files', 'directories']);
  assert.match(v.rootIdentity, /^\d+:\d+:\d+$/); assert.match(v.manifestIdentity, /^\d+:\d+:\d+:\d+$/);
  assert.match(v.sha256, /^[a-f0-9]{64}$/);
  // Reuse the manifest path grammar and bounded file count, without confusing
  // inode identities with content hashes.
  validateDnsInstalledBundle({ schema: 1, kind: 'clean-vpn-dns-code-bundle',
    files: Object.fromEntries(Object.keys(v.files).map((p) => [p, '0'.repeat(64)])) });
  for (const value of Object.values(v.files)) assert.match(value, /^\d+:\d+:\d+:\d+$/);
  assert.deepEqual(Object.keys(v.directories).sort(), bundleDirectories(v.files));
  for (const value of Object.values(v.directories)) assert.match(value, /^\d+:\d+:\d+$/);
  assert.equal(v.directories[''], v.rootIdentity);
  for (const entry of ['scripts/dns-client.mjs', 'scripts/dns-boot-guard.mjs', 'scripts/dns-exit-adapter.mjs'])
    assert.ok(Object.hasOwn(v.files, entry), 'all installed service entrypoints required');
  return v;
}
export function validateDnsBundleJournal(v) {
  keys(v, ['schema', 'backend', 'id', 'root', 'rootIdentity', 'parentIdentity', 'directoryIdentity', 'stage', 'bundle']);
  assert.equal(v.schema, 1); assert.equal(v.backend, 'dns-deployment-bundle');
  assert.match(v.id, /^[a-f0-9]{32}$/); assert.equal(resolve(v.root), v.root);
  for (const key of ['rootIdentity', 'parentIdentity', 'directoryIdentity']) assert.match(v[key], /^\d+:\d+:\d+$/);
  assert.ok(['prepared', 'installed', 'removing', 'removed'].includes(v.stage));
  validateSnapshot(v.bundle); return v;
}
export const readDnsBundleJournal = (directory) => readPrivateJournal(directory, validateDnsBundleJournal, LIMIT);
async function trustedDirectory(path, mode) {
  const s = await lstat(path, { bigint: true });
  assert.ok(s.isDirectory() && s.uid === BigInt(process.getuid()) && !(s.mode & 0o022n), 'untrusted bundle directory');
  if (mode !== undefined) assert.equal(s.mode & 0o7777n, BigInt(mode));
  return id(s);
}
async function mountId(path) {
  const fd = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const m = /^mnt_id:\s+(\d+)$/m.exec(await readFile(`/proc/self/fdinfo/${fd.fd}`, 'utf8'));
    assert.ok(m); assert.equal(id(await fd.stat({ bigint: true })), id(await lstat(path, { bigint: true })));
    return m[1];
  } finally { await fd.close(); }
}
async function sourceBytes(path, expected, max) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
  try {
    const s = await fd.stat({ bigint: true });
    assert.ok(s.isFile() && s.uid === BigInt(process.getuid()) && s.nlink === 1n && (s.mode & 0o7777n) === 0o644n);
    assert.equal(fileId(s), expected); assert.ok(s.size > 0n && s.size <= BigInt(max));
    const bytes = Buffer.alloc(Number(s.size) + 1); let used = 0;
    while (used < bytes.length) { const r = await fd.read(bytes, used, bytes.length - used, null); if (!r.bytesRead) break; used += r.bytesRead; }
    assert.equal(BigInt(used), s.size); assert.equal(fileId(await fd.stat({ bigint: true })), expected);
    assert.equal(fileId(await lstat(path, { bigint: true })), expected); return bytes.subarray(0, used);
  } finally { await fd.close(); }
}

export async function dnsDeploymentBundle({ root, directory, operation, source, expectedSha256, lockFd, assertInactive, checkpoint = async () => {} }) {
  assert.ok(['install', 'inspect', 'recover', 'remove'].includes(operation));
  assert.equal(typeof assertInactive, 'function');
  assert.equal(resolve(root), root); assert.equal(resolve(directory), directory);
  assert.equal(await realpath(root), root); assert.equal(await realpath(directory), directory);
  const parent = join(root, 'opt'), target = join(parent, 'clean-vpn');
  const staged = join(directory, 'bundle'), retired = join(directory, 'retired');
  // The journal cannot live inside the object being published/retired.
  assert.ok(directory !== target && !directory.startsWith(`${target}/`));
  const identity = { rootIdentity: await trustedDirectory(root), parentIdentity: await trustedDirectory(parent, 0o755),
    directoryIdentity: await trustedDirectory(directory, 0o700) };
  await privateJournalDirectory(directory);
  const tool = await inspectDnsSystemExecutable('/usr/bin/mv');
  const context = async () => {
    assert.equal(await realpath(root), root); assert.equal(await realpath(directory), directory);
    assert.equal(await trustedDirectory(root), identity.rootIdentity);
    assert.equal(await trustedDirectory(parent, 0o755), identity.parentIdentity);
    assert.equal(await trustedDirectory(directory, 0o700), identity.directoryIdentity);
    await assertDnsCommandLock(lockFd); assert.equal(await assertInactive(), true, 'inactive deployment proof required');
    assert.equal(await mountId(parent), await mountId(directory), 'cross-mount bundle publication unsupported');
  };
  await context();
  let record;
  if (operation === 'install') {
    assert.match(expectedSha256, /^[a-f0-9]{64}$/);
    assert.equal(await realpath(source), source);
    assert.ok(source !== target && !source.startsWith(`${target}/`) && source !== directory && !source.startsWith(`${directory}/`));
    assert.equal(await absent(target), true, 'bundle target already exists');
    assert.deepEqual(await readdir(directory), [], 'fresh bundle journal required');
    const before = validateSnapshot(await inspectDnsInstalledBundle(source, process.getuid()));
    assert.equal(before.sha256, expectedSha256, 'unapproved bundle hash');
    const manifest = await sourceBytes(join(source, 'bundle.json'), before.manifestIdentity, 131072);
    const value = validateDnsInstalledBundle(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(manifest)));
    await context(); await mkdir(staged, { mode: 0o755 });
    // Explicit chmod via the open descriptor makes the public layout independent
    // of the invoking root's umask. Source files are copied, never hardlinked.
    const makePublic = async (path) => { const fd = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      try { await fd.chmod(0o755); } finally { await fd.close(); } };
    await makePublic(staged);
    for (const p of bundleDirectories(before.files).filter(Boolean)) { await mkdir(join(staged, p), { mode: 0o755 }); await makePublic(join(staged, p)); }
    for (const p of [...Object.keys(before.files).sort(), 'bundle.json']) {
      await context();
      const bytes = p === 'bundle.json' ? manifest : await sourceBytes(join(source, p), before.files[p], 1048576);
      assert.equal(hash(bytes), p === 'bundle.json' ? expectedSha256 : value.files[p]);
      const fd = await open(join(staged, p), 'wx', 0o644);
      try { await fd.chmod(0o644); await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
    }
    for (const p of bundleDirectories(before.files).reverse()) await syncDirectory(join(staged, p));
    await syncDirectory(directory); await checkpoint('bundle:staged');
    assert.deepEqual(await inspectDnsInstalledBundle(source, process.getuid()), before, 'source changed during staging');
    const bundle = validateSnapshot(await inspectDnsInstalledBundle(staged, process.getuid()));
    assert.equal(bundle.sha256, expectedSha256);
    record = { schema: 1, backend: 'dns-deployment-bundle', id: randomBytes(16).toString('hex'), root, ...identity, stage: 'prepared', bundle };
    await writePrivateJournal(directory, record, validateDnsBundleJournal, checkpoint, LIMIT);
  } else record = await readDnsBundleJournal(directory);
  assert.equal(record.root, root);
  for (const [key, value] of Object.entries(identity)) assert.equal(record[key], value, 'bundle context changed');
  const state = async () => {
    await context(); const present = [];
    for (const path of [staged, target, retired]) {
      if (await absent(path)) continue;
      assert.deepEqual(await inspectDnsInstalledBundle(path, process.getuid()), record.bundle, 'foreign or changed bundle');
      assert.equal(await mountId(path), await mountId(directory), 'bundle mount changed'); present.push(path);
    }
    assert.equal(present.length, 1, 'bundle missing or ambiguous');
    if (record.stage === 'prepared') assert.ok([staged, target].includes(present[0]));
    if (record.stage === 'installed') assert.equal(present[0], target);
    if (record.stage === 'removed') assert.equal(present[0], retired);
    return present[0];
  };
  await state();
  const save = async (stage) => { record = { ...record, stage }; await writePrivateJournal(directory, record, validateDnsBundleJournal, checkpoint, LIMIT); };
  if (operation !== 'inspect') {
    if (operation === 'remove' && !['removing', 'removed'].includes(record.stage)) await save('removing');
    const from = await state(), to = record.stage === 'prepared' ? target : record.stage === 'removing' ? retired : from;
    if (from !== to) {
      await context(); assert.equal(await absent(to), true, 'bundle destination exists');
      await checkpoint('bundle:before-move');
      await state(); await context(); assert.deepEqual(await inspectDnsSystemExecutable('/usr/bin/mv'), tool);
      // -n never replaces a foreign destination; -T never nests into it. Same
      // mount is required above: no cross-filesystem copy/remove fallback.
      await runLockedDnsCommand('/usr/bin/mv', ['--no-clobber', '--no-target-directory', '--', from, to], { lockFd });
      await checkpoint(record.stage === 'prepared' ? 'bundle:published' : 'bundle:retired');
      await context(); assert.deepEqual(await inspectDnsSystemExecutable('/usr/bin/mv'), tool);
      assert.equal(await absent(from), true, 'bundle move did not occur');
      await syncDirectory(dirname(from)); await syncDirectory(dirname(to));
      await state();
    }
    if (record.stage === 'prepared') await save('installed');
    else if (record.stage === 'removing') await save('removed');
    await state();
  }
  return { stage: record.stage, id: record.id, bundleSha256: record.bundle.sha256,
    files: Object.keys(record.bundle.files).length, activated: false, codeRetained: record.stage === 'removed' };
}
