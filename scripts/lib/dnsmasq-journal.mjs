/** Write-ahead controller for the private Radxa fixture. NOT a host installer. */
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { readPrivateJournal, writePrivateJournal } from './dns-lifecycle-journal.mjs';
import { compileRadxaDnsmasqLabConfig } from './dnsmasq-lab-config.mjs';

const MAX_BYTES = 131072;
const keys = (value, names) => {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...names].sort());
};
export const dnsmasqHash = (text) => createHash('sha256').update(text).digest('hex');
export function validateDnsmasqContext(context) {
  keys(context, ['scope', 'bootId', 'directoryIdentity', 'executableSha256', 'link']);
  keys(context.scope, ['net', 'mnt', 'pid']);
  for (const key of ['net', 'mnt', 'pid']) assert.match(context.scope[key], new RegExp(`^${key}:\\[\\d+\\]$`));
  assert.match(context.bootId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.match(context.directoryIdentity, /^\d+:\d+$/);
  assert.match(context.executableSha256, /^[a-f0-9]{64}$/);
  keys(context.link, ['ifindex', 'ifname', 'address']);
  assert.ok(Number.isSafeInteger(context.link.ifindex) && context.link.ifindex > 1);
  assert.equal(context.link.ifname, 'usb0');
  assert.match(context.link.address, /^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/);
  return context;
}
export function validateDnsmasqSnapshot(value) {
  keys(value, ['identity', 'sha256']);
  assert.match(value.identity, /^\d+:\d+$/); assert.match(value.sha256, /^[a-f0-9]{64}$/);
  return value;
}
export function validateDnsmasqJournal(record) {
  keys(record, ['schema', 'backend', 'id', 'context', 'baseline', 'port', 'original', 'managed', 'restored',
    'start', 'direction', 'cursor', 'pending', 'stage']);
  assert.equal(record.schema, 1); assert.equal(record.backend, 'dnsmasq-private-fixture');
  assert.match(record.id, /^[a-f0-9]{32}$/); validateDnsmasqContext(record.context);
  const plan = compileRadxaDnsmasqLabConfig(record.baseline, { port: record.port, normalizeDhcpDns: true });
  for (const key of ['original', 'managed', 'restored', 'start']) validateDnsmasqSnapshot(record[key]);
  assert.equal(record.original.sha256, dnsmasqHash(record.baseline));
  assert.equal(record.restored.sha256, record.original.sha256);
  assert.equal(record.managed.sha256, dnsmasqHash(plan.managed));
  assert.equal(new Set(['original', 'managed', 'restored'].map((key) => record[key].identity)).size, 3);
  assert.ok(['apply', 'restore'].includes(record.direction));
  assert.ok(Number.isInteger(record.cursor) && record.cursor >= 0 && record.cursor <= 2);
  assert.equal(typeof record.pending, 'boolean'); assert.ok(['running', 'complete', 'released'].includes(record.stage));
  if (record.stage === 'running') assert.ok(record.cursor < 2);
  else { assert.equal(record.cursor, 2); assert.equal(record.pending, false); }
  if (record.stage === 'released') assert.equal(record.direction, 'restore');
  assert.ok(isDeepStrictEqual(record.start, record.original)
    || record.direction === 'restore' && isDeepStrictEqual(record.start, record.managed), 'unreachable start');
  return record;
}
export const readDnsmasqJournal = (directory) => readPrivateJournal(directory, validateDnsmasqJournal, MAX_BYTES);
export const writeDnsmasqJournal = (directory, record, checkpoint, label = 'journal') =>
  writePrivateJournal(directory, record, validateDnsmasqJournal, checkpoint, MAX_BYTES, label);
const target = (record) => record[record.direction === 'apply' ? 'managed' : 'restored'];
function accepted(record) {
  if (record.cursor > 0) return [target(record)];
  return record.pending ? [record.start, target(record)] : [record.start];
}
async function observe(record, scope, backend) {
  assert.deepEqual(record.context.scope, scope, 'stale namespace scope');
  const view = await backend.view();
  assert.deepEqual(view.context, record.context, 'dnsmasq context changed');
  assert.ok(accepted(record).some((snapshot) => isDeepStrictEqual(snapshot, view.snapshot)), 'dnsmasq ownership conflict');
  await backend.verifySnapshots(record);
  return view.snapshot;
}

/** No guard, setters, probes, journal writes or daemon actions. */
export async function inspectDnsmasqTransaction({ directory, scope, backend }) {
  const record = await readDnsmasqJournal(directory);
  await observe(record, scope, backend);
  return { mode: 'dry-run', systemSettingsChanged: false, id: record.id, direction: record.direction,
    cursor: record.cursor, pending: record.pending, stage: record.stage,
    next: record.direction === 'apply' ? 'verify-adapter-and-reconcile-managed-daemon' : 'finish-explicit-restore',
    daemonStateVerified: false };
}

// Caller owns a process-lifetime lock. No shell commands or paths are read from the journal.
export async function dnsmasqTransaction({ directory, operation, scope, backend, checkpoint = async () => {} }) {
  assert.ok(['enable', 'recover', 'disable'].includes(operation));
  await backend.ensureGuard(); await checkpoint('guard-installed');
  let record;
  const save = (label) => writeDnsmasqJournal(directory, record, checkpoint, label);
  if (operation === 'enable') {
    try { await readDnsmasqJournal(directory); throw new Error('journal already exists'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    const prepared = await backend.prepare();
    record = { schema: 1, backend: 'dnsmasq-private-fixture', id: randomBytes(16).toString('hex'), ...prepared,
      start: prepared.original, direction: 'apply', cursor: 0, pending: false, stage: 'running' };
    validateDnsmasqJournal(record); assert.deepEqual(record.context.scope, scope);
    await save('prepared'); await checkpoint('prepared');
  } else record = await readDnsmasqJournal(directory);
  let current = await observe(record, scope, backend);
  if (operation === 'disable' && record.direction === 'apply') {
    record = { ...record, start: current, direction: 'restore', cursor: 0, pending: false, stage: 'running' };
    await save('restore-start'); await checkpoint('restore-start');
  }
  if (record.direction === 'apply') {
    await backend.probe(record.port); await checkpoint('ready'); await observe(record, scope, backend);
  }
  while (record.cursor < 2) {
    const step = record.cursor === 0 ? 'config' : 'daemon', label = `${record.direction}:${step}`;
    current = await observe(record, scope, backend);
    if (!record.pending) { record = { ...record, pending: true }; await save(`${label}:intent`); }
    await checkpoint(`${label}:intent`); current = await observe(record, scope, backend);
    if (step === 'config') {
      if (!isDeepStrictEqual(current, target(record))) await backend.select(record);
    } else {
      await backend.activate(record);
      if (record.direction === 'apply') await backend.probe(record.port);
    }
    await checkpoint(`${label}:set`);
    assert.deepEqual(await observe(record, scope, backend), target(record), 'dnsmasq read-back mismatch');
    record = { ...record, cursor: record.cursor + 1, pending: false, stage: record.cursor === 1 ? 'complete' : 'running' };
    await save(`${label}:ack`); await checkpoint(`${label}:ack`);
  }
  // A complete file journal does not prove that the daemon is alive or loaded it.
  // Backend checks/reconciles the owned process even on a repeated recovery.
  await observe(record, scope, backend); await backend.activate(record);
  if (record.direction === 'apply') await backend.probe(record.port);
  await observe(record, scope, backend);
  if (record.direction === 'apply') { await checkpoint('active'); return { status: 'active', id: record.id }; }
  await checkpoint('restore-complete'); await observe(record, scope, backend);
  await backend.removeGuard(record); await checkpoint('guard-removed');
  record = { ...record, stage: 'released' }; await save('released'); await checkpoint('released');
  return { status: 'released', id: record.id };
}
