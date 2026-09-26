/** One controller/lock for link ownership, address/UP and resolved settings. Namespace only. */
import assert from 'node:assert/strict';
import { isDeepStrictEqual as same } from 'node:util';
import { randomBytes } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { readPrivateJournal, writePrivateJournal, syncDirectory } from './dns-lifecycle-journal.mjs';
import { ownedLinkTransaction, readOwnedLinkJournal, writeOwnedLinkJournal, validateOwnedLinkContext, assertOwnedEmptyLink } from './dns-owned-link-journal.mjs';

export const COUPLED_STEPS = Object.freeze(['DefaultRouteOff', 'addrgen', 'address', 'up', 'DNSEx', 'Domains', 'DefaultRouteOn']);
const keys = (v, k) => { assert.ok(v && typeof v === 'object'); assert.deepEqual(Object.keys(v).sort(), [...k].sort()); };
export function coupledExpected(record, level = record.level) {
  assert.ok(Number.isInteger(level) && level >= 0 && level <= COUPLED_STEPS.length);
  const s = structuredClone(record.original);
  const apply = [() => { s.dns.DefaultRoute = false; }, () => { s.addrgen = 'none'; },
    () => { s.addresses = ['inet:192.0.2.1/32']; }, () => { s.up = true; },
    () => { s.dns.DNSEx = [[2, [127, 0, 0, 1], record.port, '']]; },
    () => { s.dns.Domains = [['.', true]]; }, () => { s.dns.DefaultRoute = true; }];
  for (const fn of apply.slice(0, level)) fn(); return s;
}
export function validateCoupledJournal(r) {
  keys(r, ['schema', 'backend', 'id', 'context', 'name', 'port', 'phase', 'original', 'level', 'pending', 'direction']);
  assert.equal(r.schema, 1); assert.equal(r.backend, 'coupled-dns-namespace');
  assert.match(r.id, /^[a-f0-9]{32}$/); validateOwnedLinkContext(r.context);
  assert.equal(r.name, `cvdns${r.id.slice(0, 8)}`); assert.ok(Number.isInteger(r.port) && r.port >= 1024 && r.port <= 65535);
  assert.ok(['link', 'settings', 'unlink', 'released'].includes(r.phase));
  assert.ok(['apply', 'restore'].includes(r.direction)); assert.equal(typeof r.pending, 'boolean');
  assert.ok(Number.isInteger(r.level) && r.level >= 0 && r.level <= COUPLED_STEPS.length);
  if (r.original !== null) {
    const { addrgen, ...link } = r.original;
    assert.ok(['eui64', 'none', 'stable_secret', 'random'].includes(addrgen));
    assertOwnedEmptyLink({ ...r, ifindex: link.ifindex }, link);
  }
  if (r.phase === 'settings') {
    assert.ok(r.original); assert.ok(!r.pending || (r.direction === 'apply' ? r.level < 7 : r.level > 0));
  } else { assert.equal(r.level, 0); assert.equal(r.pending, false); }
  if (r.phase === 'link') { assert.equal(r.original, null); assert.equal(r.direction, 'apply'); }
  if (['unlink', 'released'].includes(r.phase)) assert.equal(r.direction, 'restore');
  return r;
}
export const readCoupledJournal = (directory) => readPrivateJournal(directory, validateCoupledJournal, 16384);
export const writeCoupledJournal = (directory, record, checkpoint, label = record.phase) =>
  writePrivateJournal(directory, record, validateCoupledJournal, checkpoint, 16384, label);

export async function coupledDnsTransaction({ directory, operation, scope, backend, checkpoint = async () => {} }) {
  assert.ok(['enable', 'recover', 'disable'].includes(operation));
  await backend.ensureGuard(); await checkpoint('guard-installed');
  const childDirectory = join(directory, 'link'); let r;
  const save = async (label) => { await writeCoupledJournal(directory, r, checkpoint, label); await checkpoint(label); };
  if (operation === 'enable') {
    try { await readCoupledJournal(directory); throw new Error('journal already exists'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    const context = validateOwnedLinkContext(await backend.context()); assert.deepEqual(context.scope, scope);
    const id = randomBytes(16).toString('hex'), port = await backend.adapterPort();
    r = { schema: 1, backend: 'coupled-dns-namespace', id, context, name: `cvdns${id.slice(0, 8)}`, port,
      phase: 'link', original: null, level: 0, pending: false, direction: 'apply' };
    validateCoupledJournal(r); assert.equal(await backend.view(r.name), null);
    // Both journals are durable before any kernel mutation. Existing child dir is a hard stop.
    await mkdir(childDirectory, { mode: 0o700 }); await syncDirectory(directory);
    await writeOwnedLinkJournal(childDirectory, { schema: 1, backend: 'owned-dns-link-namespace', id, context,
      name: r.name, ifindex: null, stage: 'prepared' });
    await save('prepared');
  } else r = await readCoupledJournal(directory);
  assert.deepEqual(r.context.scope, scope, 'stale namespace');
  const contextCheck = async () => assert.deepEqual(await backend.context(), r.context, 'coupled context changed');
  const childCheck = async () => {
    const child = await readOwnedLinkJournal(childDirectory);
    assert.equal(child.id, r.id); assert.equal(child.name, r.name); assert.deepEqual(child.context, r.context);
    if (r.original) assert.equal(child.ifindex, r.original.ifindex);
    return child;
  };
  const view = async () => { await contextCheck(); const state = await backend.view(r.name); await contextCheck(); return state; };
  await contextCheck(); await childCheck();
  const linkBackend = { ...backend, view: backend.linkView, releaseGuard: async () => {} };
  const childRun = async (op) => ownedLinkTransaction({ directory: childDirectory, operation: op, scope, backend: linkBackend,
    checkpoint: (p) => checkpoint(`link:${p}`) });
  if (r.phase === 'link') {
    if (operation === 'disable') { r = { ...r, phase: 'unlink', direction: 'restore' }; await save('unlink-intent'); }
    else {
      assert.equal(await backend.adapterPort(), r.port); await backend.probe(); await contextCheck();
      await childRun('recover'); await checkpoint('link-ready');
      const child = await childCheck(), original = await view();
      assert.ok(original); const { addrgen, ...empty } = original;
      assertOwnedEmptyLink(child, empty);
      r = { ...r, phase: 'settings', original }; await save('settings-prepared');
    }
  }
  if (r.phase === 'settings') {
    assert.equal((await childCheck()).stage, 'created', 'child lifecycle changed');
    const observe = async () => {
      const current = await view(), before = coupledExpected(r);
      const after = r.pending ? coupledExpected(r, r.level + (r.direction === 'apply' ? 1 : -1)) : before;
      assert.ok(same(current, before) || (r.pending && same(current, after)), 'coupled ownership conflict'); return current;
    };
    let current = await observe();
    if (operation === 'disable' && r.direction === 'apply') {
      const level = r.pending && same(current, coupledExpected(r, r.level + 1)) ? r.level + 1 : r.level;
      r = { ...r, direction: 'restore', level, pending: false }; await save('restore-intent');
    }
    if (r.direction === 'apply') {
      assert.equal(await backend.adapterPort(), r.port, 'adapter endpoint changed');
      await backend.probe(); await observe();
    }
    while (r.direction === 'apply' ? r.level < 7 : r.level > 0) {
      const index = r.direction === 'apply' ? r.level : r.level - 1;
      const label = `${r.direction}:${COUPLED_STEPS[index]}`, next = r.level + (r.direction === 'apply' ? 1 : -1);
      await observe();
      if (!r.pending) { r = { ...r, pending: true }; await save(`${label}:intent`); }
      current = await observe(); const target = coupledExpected(r, next), before = coupledExpected(r);
      // Explicit DefaultRoute pin is required even when its automatic value already reads false.
      if (!same(current, target) || same(before, target)) {
        await backend.set(r.context, current, COUPLED_STEPS[index], target); await checkpoint(`${label}:set`);
      }
      assert.deepEqual(await observe(), target, 'coupled setter read-back');
      r = { ...r, level: next, pending: false }; await save(`${label}:ack`);
    }
    await observe();
    if (r.direction === 'apply') { await checkpoint('active'); return { status: 'active', id: r.id, name: r.name }; }
    r = { ...r, phase: 'unlink' }; await save('unlink-intent');
  }
  if (r.phase === 'unlink') {
    await contextCheck(); await childCheck();
    const remaining = await view();
    if (r.original && remaining !== null) assert.deepEqual(remaining, r.original, 'link changed after settings release');
    await childRun('disable'); await checkpoint('link-released');
    assert.equal(await view(), null); r = { ...r, phase: 'released' }; await save('release-intent');
  }
  assert.equal(r.phase, 'released'); assert.equal((await childCheck()).stage, 'released');
  assert.equal(await view(), null);
  await backend.releaseGuard(r.context, r.name); await checkpoint('guard-removed');
  return { status: 'released', id: r.id };
}
