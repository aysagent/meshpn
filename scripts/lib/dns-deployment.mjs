/** Ordered, inactive-only publication of code then client files. NOT activation
 * or post-activation uninstall. The caller supplies genuine OS inactivity and
 * holds the shared boot/deployment flock; no host CLI is exposed here. */
import assert from 'node:assert/strict';
import { lstat, realpath, readdir, mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { privateJournalDirectory, syncDirectory, readPrivateJournal, writePrivateJournal } from './dns-lifecycle-journal.mjs';
import { assertDnsCommandLock } from './dns-system-command.mjs';
import { inspectDnsInstalledBundle } from './dns-installed-authority.mjs';
import { dnsDeploymentBundle, readDnsBundleJournal } from './dns-deployment-bundle.mjs';
import { dnsDeploymentFiles, readDnsDeploymentJournal, dnsClientDeploymentDescriptors,
  validateDnsClientDeploymentDescriptors } from './dns-deployment-files.mjs';

const identity = (s) => `${s.dev}:${s.ino}:${s.mode}`;
const keys = (v, expected) => {
  assert.ok(v && typeof v === 'object' && !Array.isArray(v));
  assert.deepEqual(Object.keys(v).sort(), [...expected].sort());
};
export function validateDnsDeployment(v) {
  keys(v, ['schema', 'backend', 'id', 'root', 'rootIdentity', 'directoryIdentity', 'children', 'stage', 'bundleSha256', 'files']);
  assert.equal(v.schema, 1); assert.equal(v.backend, 'dns-deployment');
  assert.match(v.id, /^[a-f0-9]{32}$/); assert.equal(resolve(v.root), v.root);
  keys(v.children, ['code', 'files']);
  for (const id of [v.rootIdentity, v.directoryIdentity, ...Object.values(v.children)]) assert.match(id, /^\d+:\d+:\d+$/);
  assert.ok(['code', 'files', 'installed', 'detaching-files', 'detached', 'removing-files', 'removing-code', 'removed'].includes(v.stage));
  assert.match(v.bundleSha256, /^[a-f0-9]{64}$/); validateDnsClientDeploymentDescriptors(v.files); return v;
}
export const readDnsDeployment = (directory) => readPrivateJournal(directory, validateDnsDeployment, 8192);
async function directoryIdentity(path, mode) {
  const s = await lstat(path, { bigint: true });
  assert.ok(s.isDirectory() && s.uid === BigInt(process.getuid()) && !(s.mode & 0o022n));
  if (mode !== undefined) assert.equal(s.mode & 0o7777n, BigInt(mode));
  return identity(s);
}
async function absent(path) {
  try { await lstat(path); return false; } catch (e) { if (e.code !== 'ENOENT') throw e; return true; }
}
export async function dnsDeployment(options) {
  // Publication of code can take time. Capture sensitive client inputs before
  // the first await, so a caller mutation cannot change the eventual opt-in.
  const files = options.files?.map((f) => ({ ...f, contents: Buffer.isBuffer(f.contents) ? Buffer.from(f.contents) : f.contents }));
  try { return await applyDeployment({ ...options, files }); }
  finally { for (const f of files ?? []) if (Buffer.isBuffer(f.contents)) f.contents.fill(0); }
}
async function applyDeployment({ root, directory, operation, source, expectedSha256, files,
  lockFd, assertInactive, checkpoint = async () => {} }) {
  assert.ok(['install', 'recover', 'detach', 'remove', 'inspect'].includes(operation));
  assert.equal(typeof assertInactive, 'function');
  assert.equal(resolve(root), root); assert.equal(resolve(directory), directory);
  assert.equal(await realpath(root), root); assert.equal(await realpath(directory), directory);
  const target = join(root, 'opt/clean-vpn');
  assert.ok(directory !== target && !directory.startsWith(`${target}/`));
  await privateJournalDirectory(directory);
  const rootIdentity = await directoryIdentity(root), ownIdentity = await directoryIdentity(directory, 0o700);
  const paths = { code: join(directory, 'code'), files: join(directory, 'files') };
  let record;
  const context = async (checkInactive = false) => {
    assert.equal(await realpath(root), root); assert.equal(await realpath(directory), directory);
    assert.equal(await directoryIdentity(root), rootIdentity);
    assert.equal(await directoryIdentity(directory, 0o700), ownIdentity);
    await assertDnsCommandLock(lockFd);
    if (checkInactive) assert.equal(await assertInactive(), true, 'inactive deployment proof required');
    if (record) for (const name of ['code', 'files'])
      assert.equal(await directoryIdentity(paths[name], 0o700), record.children[name], 'deployment child directory changed');
  };
  await context(true);
  if (operation === 'install') {
    const descriptors = dnsClientDeploymentDescriptors(files, expectedSha256);
    assert.deepEqual(await readdir(directory), [], 'fresh deployment journal required');
    assert.equal(await absent(target), true, 'code target already exists');
    for (const f of descriptors) assert.equal(await absent(join(root, f.path)), true, 'client target already exists');
    for (const name of ['code', 'files']) await mkdir(paths[name], { mode: 0o700 });
    await syncDirectory(directory);
    record = { schema: 1, backend: 'dns-deployment', id: randomBytes(16).toString('hex'), root,
      rootIdentity, directoryIdentity: ownIdentity,
      children: Object.fromEntries(await Promise.all(['code', 'files'].map(async (name) => [name, await directoryIdentity(paths[name], 0o700)]))),
      stage: 'code', bundleSha256: expectedSha256, files: descriptors };
    await writePrivateJournal(directory, record, validateDnsDeployment, checkpoint, 8192);
  } else record = await readDnsDeployment(directory);
  assert.equal(record.root, root); assert.equal(record.rootIdentity, rootIdentity);
  assert.equal(record.directoryIdentity, ownIdentity);
  if (expectedSha256 !== undefined) assert.equal(record.bundleSha256, expectedSha256);
  if (files !== undefined) assert.deepEqual(dnsClientDeploymentDescriptors(files, record.bundleSha256), record.files, 'client plan changed');
  const save = async (stage) => {
    await context(); record = { ...record, stage }; await writePrivateJournal(directory, record, validateDnsDeployment, checkpoint, 8192);
  };
  const hook = (name) => async (point) => { await checkpoint(`${name}:${point}`); };
  const code = (op) => dnsDeploymentBundle({ root, directory: paths.code, operation: op, source,
    expectedSha256: record.bundleSha256, lockFd, assertInactive: async () => { await context(true); return true; }, checkpoint: hook('code') });
  const config = (op) => dnsDeploymentFiles({ root, directory: paths.files, operation: op, files,
    assertInactive: async () => {
      await context(true);
      // Read-only code inventory does not recursively launch another OS
      // inactivity inspection. Before each client mutation the outer check is
      // fresh, and the exact installed inode/hash inventory is still mandatory.
      if (!(op === 'inspect' && ['removing-code', 'removed'].includes(record.stage))) {
        const bundle = await readDnsBundleJournal(paths.code);
        assert.equal(bundle.stage, 'installed', 'complete unchanged code required for client files');
        assert.equal(bundle.root, root); assert.equal(bundle.bundle.sha256, record.bundleSha256);
        assert.deepEqual(await inspectDnsInstalledBundle(target, process.getuid()), bundle.bundle, 'installed code changed');
      }
      await context();
      return true;
    }, checkpoint: hook('files') });
  const children = async () => {
    await context(); const result = {};
    for (const name of ['code', 'files']) {
      if (await absent(join(paths[name], 'journal.json'))) {
        assert.deepEqual(await readdir(paths[name]), [], 'unjournalled staging requires review'); result[name] = null; continue;
      }
      const child = await (name === 'code' ? readDnsBundleJournal : readDnsDeploymentJournal)(paths[name]);
      assert.equal(child.root, root);
      if (name === 'code') assert.equal(child.bundle.sha256, record.bundleSha256);
      else assert.deepEqual(child.files.map(({ path, mode, sha256 }) => ({ path, mode, sha256 })), record.files, 'child file plan differs');
      result[name] = await (name === 'code' ? code : config)('inspect');
    }
    if (!result.code) {
      assert.ok(record.stage === 'code' && !result.files, 'missing code journal');
      assert.equal(await absent(target), true, 'unjournalled code target');
    }
    if (!result.files) for (const f of record.files) assert.equal(await absent(join(root, f.path)), true, 'unjournalled client target');
    const c = result.code?.stage, f = result.files?.stage;
    if (record.stage === 'code') assert.ok(!result.files && [undefined, 'prepared', 'installed'].includes(c));
    if (record.stage === 'files') assert.ok(c === 'installed' && [undefined, 'installing', 'installed'].includes(f));
    if (record.stage === 'installed') assert.ok(c === 'installed' && f === 'installed');
    if (record.stage === 'detaching-files') assert.ok(c === 'installed' && ['installed', 'detaching', 'detached'].includes(f));
    if (record.stage === 'detached') assert.ok(c === 'installed' && f === 'detached');
    if (record.stage === 'removing-files') assert.ok(['prepared', 'installed'].includes(c) && [undefined, 'installing', 'installed', 'detaching', 'detached', 'removing', 'removed'].includes(f));
    if (record.stage === 'removing-code') assert.ok([undefined, 'removed'].includes(f) && ['prepared', 'installed', 'removing', 'removed'].includes(c));
    if (record.stage === 'removed') assert.ok([undefined, 'removed'].includes(f) && c === 'removed');
    return result;
  };
  let state = await children(); // Refuse drift in EITHER child before next mutation.
  if (operation !== 'inspect') {
    if (operation === 'detach') {
      assert.ok(['installed', 'detaching-files', 'detached'].includes(record.stage), 'detach requires a complete installed deployment');
      if (record.stage === 'installed') await save('detaching-files');
    }
    if (operation === 'remove' && !['removing-files', 'removing-code', 'removed'].includes(record.stage)) {
      assert.ok(state.code, 'no published/prepared code journal to roll back'); await save('removing-files');
    }
    if (record.stage === 'code') {
      assert.ok(state.code || source, 'source required to begin code staging');
      assert.equal((await code(state.code ? 'recover' : 'install')).stage, 'installed');
      await save('files'); state = await children();
    }
    if (record.stage === 'files') {
      assert.ok(state.files || files, 'sensitive client plan required to begin file staging');
      assert.equal((await config(state.files ? 'recover' : 'install')).stage, 'installed'); await save('installed');
    }
    if (record.stage === 'detaching-files') {
      assert.equal((await config('detach')).stage, 'detached'); await save('detached');
      // recover repeats ONLY the recorded partial direction. A separate
      // explicit remove with strict OS authority is required to go further.
    }
    if (record.stage === 'removing-files') {
      if (state.files) assert.equal((await config('remove')).stage, 'removed');
      await save('removing-code');
    }
    if (record.stage === 'removing-code') {
      // Recheck every config target is absent and both child inventories before
      // moving the executable bundle. Never leave opt-in pointing at no code.
      await children();
      assert.equal((await code('remove')).stage, 'removed'); await save('removed');
    }
    state = await children();
  }
  await context(true);
  return { schema: 1, kind: 'clean-vpn-dns-deployment', id: record.id, stage: record.stage,
    code: state.code?.stage ?? null, files: state.files?.stage ?? null, bundleSha256: record.bundleSha256,
    activated: false, postActivationUninstall: false };
}
