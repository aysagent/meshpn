/** Narrow reviewed symlink/localhost-file transition; private fixtures only, no guard release. */
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import { isDeepStrictEqual as same } from 'node:util';
import { readPrivateJournal, writePrivateJournal } from './dns-lifecycle-journal.mjs';

export const RESOLVER_TARGET = '/run/systemd/resolve/stub-resolv.conf';
export const RESOLVER_MANAGED = 'nameserver 127.0.0.1\n';
export const resolverHash = (text) => createHash('sha256').update(text).digest('hex');
const keys = (v, k) => { assert.ok(v && typeof v === 'object' && !Array.isArray(v)); assert.deepEqual(Object.keys(v).sort(), [...k].sort()); };
export function validateResolverContext(v) {
  keys(v, ['scope', 'bootId', 'directoryIdentity']); keys(v.scope, ['net', 'mnt', 'pid']);
  for (const key of ['net', 'mnt', 'pid']) assert.match(v.scope[key], new RegExp(`^${key}:\\[\\d+\\]$`));
  assert.match(v.bootId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.match(v.directoryIdentity, /^\d+:\d+$/); return v;
}
export function validateResolverObject(v) {
  keys(v, ['kind', 'identity', 'uid', 'gid', 'mode', 'value']);
  assert.match(v.identity, /^\d+:\d+$/);
  for (const key of ['uid', 'gid']) assert.ok(Number.isSafeInteger(v[key]) && v[key] >= 0);
  assert.ok(['symlink', 'file'].includes(v.kind));
  assert.equal(v.mode, v.kind === 'symlink' ? 0o777 : 0o644);
  assert.equal(v.value, v.kind === 'symlink' ? RESOLVER_TARGET : resolverHash(RESOLVER_MANAGED)); return v;
}
export function validateResolverObjectJournal(r) {
  keys(r, ['schema', 'backend', 'id', 'context', 'original', 'managed', 'restored', 'start', 'phase']);
  assert.equal(r.schema, 1); assert.equal(r.backend, 'resolver-object-private-fixture'); assert.match(r.id, /^[a-f0-9]{32}$/);
  validateResolverContext(r.context);
  for (const key of ['original', 'managed', 'restored', 'start']) validateResolverObject(r[key]);
  assert.equal(r.restored.kind, r.original.kind); assert.equal(r.restored.value, r.original.value);
  assert.equal(r.restored.mode, r.original.mode); assert.equal(r.managed.kind, 'file');
  for (const key of ['uid', 'gid']) assert.ok([r.managed, r.restored].every((v) => v[key] === r.original[key]));
  assert.equal(new Set([r.original, r.managed, r.restored].map((v) => v.identity)).size, 3);
  assert.ok(['prepared', 'apply-intent', 'active', 'restore-intent', 'restored'].includes(r.phase));
  assert.ok(same(r.start, r.original) || ['restore-intent', 'restored'].includes(r.phase) && same(r.start, r.managed));
  return r;
}
export const readResolverObjectJournal = (dir) => readPrivateJournal(dir, validateResolverObjectJournal, 8192);
export const writeResolverObjectJournal = (dir, r, checkpoint, label = r.phase) =>
  writePrivateJournal(dir, r, validateResolverObjectJournal, checkpoint, 8192, label);
const accepted = (r) => ({ prepared: [r.original], 'apply-intent': [r.original, r.managed], active: [r.managed],
  'restore-intent': [r.start, r.restored], restored: [r.restored] })[r.phase];
async function observe(r, scope, backend) {
  assert.deepEqual(r.context.scope, scope, 'stale resolver namespace');
  const view = await backend.view(); assert.deepEqual(view.context, r.context, 'resolver context changed');
  assert.ok(accepted(r).some((v) => same(v, view.snapshot)), 'resolver ownership conflict');
  await backend.verifySnapshots(r); return view.snapshot;
}
export async function inspectResolverObjectTransaction({ directory, scope, backend }) {
  const r = await readResolverObjectJournal(directory); await observe(r, scope, backend);
  return { mode: 'dry-run', systemSettingsChanged: false, phase: r.phase, id: r.id, readinessVerified: false };
}
export async function resolverObjectTransaction({ directory, operation, scope, backend, checkpoint = async () => {} }) {
  assert.ok(['enable', 'recover', 'disable'].includes(operation));
  await backend.ensureGuard(); await checkpoint('guard-installed');
  let r;
  const save = async (phase) => { r = { ...r, phase }; await writeResolverObjectJournal(directory, r, checkpoint); await checkpoint(phase); };
  if (operation === 'enable') {
    try { await readResolverObjectJournal(directory); throw new Error('journal already exists'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    const prepared = await backend.prepare();
    r = { schema: 1, backend: 'resolver-object-private-fixture', id: randomBytes(16).toString('hex'), ...prepared,
      start: prepared.original, phase: 'prepared' };
    assert.deepEqual(r.context.scope, scope); await save('prepared');
  } else r = await readResolverObjectJournal(directory);
  const current = await observe(r, scope, backend);
  if (operation === 'disable' && !['restore-intent', 'restored'].includes(r.phase)) {
    r = { ...r, start: current }; await save('restore-intent');
  }
  const restore = ['restore-intent', 'restored'].includes(r.phase), name = restore ? 'restored' : 'managed';
  if (!restore) { await backend.probe(); await checkpoint('ready'); await observe(r, scope, backend); }
  if (r.phase === 'prepared') await save('apply-intent');
  if (['apply-intent', 'restore-intent'].includes(r.phase)) {
    const before = await observe(r, scope, backend);
    if (!same(before, r[name])) await backend.select(r, before);
    await checkpoint(restore ? 'restore:set' : 'apply:set');
    assert.deepEqual(await observe(r, scope, backend), r[name]);
    await save(restore ? 'restored' : 'active');
  }
  if (!restore) await backend.probe();
  await observe(r, scope, backend);
  // The enclosing DNS integration owns guard lifetime. Exact link/file rollback
  // is NOT proof of healthy baseline or authority to release.
  return { status: restore ? 'restored' : 'active', id: r.id, protectionRetained: true };
}
