/** Paired private-fixture journals, one outer flock. Never releases the DNS guard. */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { readPrivateJournal, writePrivateJournal } from './dns-lifecycle-journal.mjs';
import { dnsmasqTransaction, readDnsmasqJournal, writeDnsmasqJournal, validateDnsmasqJournal, inspectDnsmasqTransaction } from './dnsmasq-journal.mjs';
import { resolverObjectTransaction, readResolverObjectJournal, writeResolverObjectJournal, validateResolverObjectJournal, inspectResolverObjectTransaction } from './dns-resolver-object-journal.mjs';

export const RADXA_METHODS = Object.freeze({ dnsmasq: ['view', 'prepare', 'verifySnapshots', 'select', 'activate', 'probe'],
  resolver: ['view', 'prepare', 'verifySnapshots', 'select', 'probe'] });
export const radxaMethod = (kind, name) => `${kind}${name[0].toUpperCase()}${name.slice(1)}`;
export function pairRadxaBackends(dnsmasq, resolver) {
  return { ensureGuard: dnsmasq.ensureGuard, ...Object.fromEntries(Object.entries(RADXA_METHODS).flatMap(([kind, methods]) =>
    methods.map((name) => [radxaMethod(kind, name), (...args) => ({ dnsmasq, resolver })[kind][name](...args)]))) };
}
const phases = ['dnsmasq', 'resolver', 'active', 'restore-resolver', 'restore-dnsmasq', 'restored'];
function validate(r) {
  assert.deepEqual(Object.keys(r).sort(), ['schema', 'backend', 'id', 'phase', 'dnsmasq', 'resolver'].sort());
  assert.equal(r.schema, 1); assert.equal(r.backend, 'radxa-paired-private-fixture');
  assert.match(r.id, /^[a-f0-9]{32}$/); assert.ok(phases.includes(r.phase));
  validateDnsmasqJournal(r.dnsmasq); validateResolverObjectJournal(r.resolver);
  assert.equal(r.dnsmasq.id, r.id); assert.equal(r.resolver.id, r.id);
  assert.equal(r.dnsmasq.direction, 'apply'); assert.equal(r.dnsmasq.cursor, 0);
  assert.equal(r.dnsmasq.pending, false); assert.equal(r.dnsmasq.stage, 'running');
  assert.deepEqual(r.dnsmasq.start, r.dnsmasq.original);
  assert.equal(r.resolver.phase, 'prepared'); assert.deepEqual(r.resolver.start, r.resolver.original);
  assert.deepEqual(r.dnsmasq.context.scope, r.resolver.context.scope);
  assert.equal(r.dnsmasq.context.bootId, r.resolver.context.bootId);
  assert.notEqual(r.dnsmasq.context.directoryIdentity, r.resolver.context.directoryIdentity);
  return r;
}
export const readRadxaJournal = (directory) => readPrivateJournal(join(directory, 'radxa'), validate, 147456);
const write = (dir, r, hook, label) => writePrivateJournal(join(dir, 'radxa'), r, validate, hook, 147456, label);
const paths = (dir) => ({ dnsmasq: dir, resolver: join(dir, 'resolver-etc') });
function children(backend) {
  return Object.fromEntries(Object.entries(RADXA_METHODS).map(([kind, methods]) => [kind, {
    ensureGuard: backend.ensureGuard, removeGuard: async () => {},
    ...Object.fromEntries(methods.map((name) => [name, (...args) => backend[radxaMethod(kind, name)](...args)])),
  }]));
}
async function observe(directory, scope, backend, r) {
  assert.deepEqual(r.dnsmasq.context.scope, scope);
  const p = paths(directory), b = children(backend);
  const d = await readDnsmasqJournal(p.dnsmasq), s = await readResolverObjectJournal(p.resolver);
  const immutable = (record, dynamic) => Object.fromEntries(Object.entries(record).filter(([k]) => !dynamic.includes(k)));
  assert.deepEqual(immutable(d, ['start', 'direction', 'cursor', 'pending', 'stage']),
    immutable(r.dnsmasq, ['start', 'direction', 'cursor', 'pending', 'stage']), 'dnsmasq journal replaced');
  assert.deepEqual(immutable(s, ['start', 'phase']), immutable(r.resolver, ['start', 'phase']), 'resolver journal replaced');
  const dActive = d.direction === 'apply' && d.stage === 'complete';
  if (['dnsmasq', 'resolver', 'active', 'restore-resolver'].includes(r.phase)) assert.equal(d.direction, 'apply');
  if (['resolver', 'active'].includes(r.phase)) assert.ok(dActive);
  if (r.phase === 'dnsmasq') assert.equal(s.phase, 'prepared');
  if (r.phase === 'resolver') assert.ok(['prepared', 'apply-intent', 'active'].includes(s.phase));
  if (r.phase === 'active') assert.equal(s.phase, 'active');
  if (['restore-dnsmasq', 'restored'].includes(r.phase)) assert.equal(s.phase, 'restored');
  if (r.phase === 'restored') assert.equal(d.stage, 'released');
  await inspectDnsmasqTransaction({ directory: p.dnsmasq, scope, backend: b.dnsmasq });
  await inspectResolverObjectTransaction({ directory: p.resolver, scope, backend: b.resolver });
}
export async function inspectRadxaTransaction({ directory, scope, backend }) {
  const r = await readRadxaJournal(directory); await observe(directory, scope, backend, r);
  return { mode: 'dry-run', id: r.id, phase: r.phase, readinessVerified: false, systemSettingsChanged: false };
}
export async function radxaDnsTransaction({ directory, operation, scope, backend, checkpoint = async () => {} }) {
  assert.ok(['enable', 'recover', 'disable'].includes(operation));
  await backend.ensureGuard(); await checkpoint('guard-installed');
  const p = paths(directory), b = children(backend); let r;
  const save = async (phase) => { r = { ...r, phase }; await write(directory, r, checkpoint, phase); await checkpoint(phase); };
  if (operation === 'enable') {
    // Orphan child journals/snapshots are evidence: never adopt or overwrite them.
    for (const read of [() => readRadxaJournal(directory), () => readDnsmasqJournal(p.dnsmasq), () => readResolverObjectJournal(p.resolver)]) {
      try { await read(); throw new Error('journal already exists'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    }
    const id = randomBytes(16).toString('hex'), d = await b.dnsmasq.prepare(), s = await b.resolver.prepare();
    r = { schema: 1, backend: 'radxa-paired-private-fixture', id, phase: 'dnsmasq',
      dnsmasq: { schema: 1, backend: 'dnsmasq-private-fixture', id, ...d, start: d.original, direction: 'apply', cursor: 0, pending: false, stage: 'running' },
      resolver: { schema: 1, backend: 'resolver-object-private-fixture', id, ...s, start: s.original, phase: 'prepared' } };
    validate(r); assert.deepEqual(r.dnsmasq.context.scope, scope);
    await writeDnsmasqJournal(p.dnsmasq, r.dnsmasq, checkpoint, 'seed-dnsmasq');
    await writeResolverObjectJournal(p.resolver, r.resolver, checkpoint, 'seed-resolver');
    await save('dnsmasq');
  } else r = await readRadxaJournal(directory);
  const check = () => observe(directory, scope, backend, r);
  await check();
  if (operation === 'disable' && ['dnsmasq', 'resolver', 'active'].includes(r.phase)) await save('restore-resolver');
  const run = async (kind, op) => {
    await check();
    await (kind === 'dnsmasq' ? dnsmasqTransaction : resolverObjectTransaction)({ directory: p[kind], operation: op, scope, backend: b[kind],
      checkpoint: (point) => checkpoint(`${kind}:${point}`) });
    await check();
  };
  if (['dnsmasq', 'resolver', 'active'].includes(r.phase)) {
    // Reconcile/recheck the daemon even after its file transaction completed.
    await run('dnsmasq', 'recover');
    if (r.phase === 'dnsmasq') await save('resolver');
    await run('resolver', 'recover');
    if (r.phase !== 'active') await save('active');
    return { status: 'active', id: r.id, protectionRetained: true };
  }
  if (r.phase === 'restore-resolver') { await run('resolver', 'disable'); await save('restore-dnsmasq'); }
  if (r.phase === 'restore-dnsmasq') { await run('dnsmasq', 'disable'); await save('restored'); }
  // File rollback can outlive its daemon. Recover DHCP/local DNS under guard
  // even after the outer journal already acknowledged restoration.
  await run('dnsmasq', 'disable');
  await check();
  // Exact rollback to a dangling link is not healthy baseline/readiness proof.
  return { status: 'restored', id: r.id, protectionRetained: true };
}
