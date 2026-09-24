/** Resolved-specific write-ahead intents. Namespace experiment, NOT a host installer. */
import assert from 'node:assert/strict';
import { isDeepStrictEqual } from 'node:util';
import { randomBytes } from 'node:crypto';
import { validateResolvedSettings } from './dns-resolved-backend.mjs';
import { readPrivateJournal, writePrivateJournal } from './dns-lifecycle-journal.mjs';

export const RESOLVED_PROPERTIES = Object.freeze(['DNSEx', 'Domains', 'DefaultRoute']);
const MAX_BYTES = 65536;
const keys = (value, names) => {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...names].sort());
};
export function validateResolvedContext(context) {
  keys(context, ['scope', 'busId', 'owner', 'link']); keys(context.scope, ['net', 'mnt', 'pid']);
  for (const key of ['net', 'mnt', 'pid']) assert.match(context.scope[key], new RegExp(`^${key}:\\[\\d+\\]$`));
  assert.match(context.busId, /^[a-f0-9]{32}$/); assert.match(context.owner, /^:\d+\.\d+$/);
  keys(context.link, ['ifindex', 'ifname', 'address']);
  assert.ok(Number.isSafeInteger(context.link.ifindex) && context.link.ifindex > 1);
  assert.match(context.link.ifname, /^[a-zA-Z0-9_.-]{1,15}$/);
  assert.match(context.link.address, /^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/); return context;
}
export const managedResolvedSettings = (port) => {
  assert.ok(Number.isInteger(port) && port >= 1024 && port <= 65535);
  return { DNSEx: [[2, [127, 0, 0, 1], port, '']], Domains: [['.', true]], DefaultRoute: true };
};
function prefix(start, target, cursor) {
  const state = structuredClone(start);
  for (const property of RESOLVED_PROPERTIES.slice(0, cursor)) state[property] = structuredClone(target[property]);
  return state;
}
export function resolvedExpected(record, afterPending = false) {
  return prefix(record.start, record.direction === 'apply' ? record.managed : record.original,
    record.cursor + (afterPending && record.pending ? 1 : 0));
}
export function validateResolvedJournal(record) {
  keys(record, ['schema', 'backend', 'id', 'context', 'original', 'managed', 'start', 'direction', 'cursor', 'pending', 'stage']);
  assert.equal(record.schema, 1); assert.equal(record.backend, 'resolved-namespace');
  assert.match(record.id, /^[a-f0-9]{32}$/); validateResolvedContext(record.context);
  for (const key of ['original', 'managed', 'start']) validateResolvedSettings(record[key]);
  assert.ok(record.original.DNSEx.length > 0, 'empty original DNS');
  assert.deepEqual(record.managed, managedResolvedSettings(record.managed.DNSEx[0]?.[2]));
  assert.ok(['apply', 'restore'].includes(record.direction));
  assert.ok(Number.isInteger(record.cursor) && record.cursor >= 0 && record.cursor <= 3);
  assert.equal(typeof record.pending, 'boolean'); assert.ok(['running', 'complete', 'released'].includes(record.stage));
  if (record.stage === 'running') assert.ok(record.cursor < 3);
  else { assert.equal(record.cursor, 3); assert.equal(record.pending, false); }
  if (record.stage === 'released') assert.equal(record.direction, 'restore');
  if (record.direction === 'apply') assert.deepEqual(record.start, record.original);
  else assert.ok([0, 1, 2, 3].some((n) => isDeepStrictEqual(record.start, prefix(record.original, record.managed, n))), 'unreachable restore start');
  return record;
}
export const readResolvedJournal = (directory) => readPrivateJournal(directory, validateResolvedJournal, MAX_BYTES);
export const writeResolvedJournal = (directory, record, checkpoint, label = 'journal') =>
  writePrivateJournal(directory, record, validateResolvedJournal, checkpoint, MAX_BYTES, label);

// The process launcher owns flock. backend offers context-checked reads/writes and an independent guard.
export async function resolvedTransaction({ directory, operation, scope, backend, checkpoint = async () => {} }) {
  assert.ok(['enable', 'recover', 'disable'].includes(operation));
  await backend.ensureGuard(); await checkpoint('guard-installed');
  let record;
  const save = async (label) => { await writeResolvedJournal(directory, record, checkpoint, label); };
  if (operation === 'enable') {
    try { await readResolvedJournal(directory); throw new Error('journal already exists'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    const view = await backend.view(); validateResolvedContext(view.context); validateResolvedSettings(view.settings);
    assert.deepEqual(view.context.scope, scope);
    record = { schema: 1, backend: 'resolved-namespace', id: randomBytes(16).toString('hex'), context: view.context,
      original: structuredClone(view.settings), managed: managedResolvedSettings(await backend.adapterPort()),
      start: structuredClone(view.settings), direction: 'apply', cursor: 0, pending: false, stage: 'running' };
    await save('prepared'); await checkpoint('prepared');
  } else record = await readResolvedJournal(directory);
  assert.deepEqual(record.context.scope, scope, 'stale namespace scope');
  const observe = async () => {
    const view = await backend.view(); assert.deepEqual(view.context, record.context, 'resolved context changed');
    validateResolvedSettings(view.settings);
    const before = resolvedExpected(record), after = resolvedExpected(record, true);
    assert.ok(isDeepStrictEqual(view.settings, before) || (record.pending && isDeepStrictEqual(view.settings, after)), 'resolved ownership conflict');
    return view.settings;
  };
  let current = await observe();
  if (operation === 'disable' && record.direction === 'apply') {
    // Persist authorization to restore BEFORE changing even the first property.
    record = { ...record, direction: 'restore', start: structuredClone(current), cursor: 0, pending: false, stage: 'running' };
    await save('restore-start'); await checkpoint('restore-start');
  }
  if (record.direction === 'apply') {
    assert.equal(await backend.adapterPort(), record.managed.DNSEx[0][2], 'adapter endpoint changed');
    await backend.probe(); await checkpoint('ready'); await observe();
  }
  while (record.cursor < 3) {
    const property = RESOLVED_PROPERTIES[record.cursor], label = `${record.direction}:${property}`;
    current = await observe();
    if (!record.pending) { record = { ...record, pending: true }; await save(`${label}:intent`); }
    await checkpoint(`${label}:intent`);
    current = await observe();
    const before = resolvedExpected(record), after = resolvedExpected(record, true);
    if (!isDeepStrictEqual(current, after)) {
      await backend.set(record.context, property, after[property], before);
      await checkpoint(`${label}:set`);
    } else await checkpoint(`${label}:already-applied`);
    const result = await observe(); assert.deepEqual(result, after, 'setter read-back mismatch');
    record = { ...record, cursor: record.cursor + 1, pending: false, stage: record.cursor === 2 ? 'complete' : 'running' };
    await save(`${label}:ack`); await checkpoint(`${label}:ack`);
  }
  await observe();
  if (record.direction === 'apply') { await checkpoint('active'); return { status: 'active', id: record.id }; }
  await checkpoint('restore-complete'); await observe();
  // Backend rechecks context + exact snapshot at the guard-removal boundary too.
  await backend.removeGuard(record.context, record.original); await checkpoint('guard-removed');
  record = { ...record, stage: 'released' }; await save('released'); await checkpoint('released');
  return { status: 'released', id: record.id };
}
