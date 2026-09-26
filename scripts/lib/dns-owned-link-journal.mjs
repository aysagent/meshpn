/** Durable empty dummy-link lifecycle. Namespace experiment, NOT host deployment. */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readPrivateJournal, writePrivateJournal } from './dns-lifecycle-journal.mjs';

const fields = (value, names) => {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...names].sort());
};
export function validateOwnedLinkContext(value) {
  fields(value, ['scope', 'bootId', 'busId', 'owner']); fields(value.scope, ['net', 'mnt', 'pid']);
  for (const key of ['net', 'mnt', 'pid']) assert.match(value.scope[key], new RegExp(`^${key}:\\[\\d+\\]$`));
  assert.match(value.bootId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.match(value.busId, /^[a-f0-9]{32}$/); assert.match(value.owner, /^:\d+\.\d+$/); return value;
}
export function ownedLinkSpec(record, stamped = true) {
  return { name: record.name, kind: 'dummy', mac: `02:${record.id.slice(8, 18).match(/../g).join(':')}`,
    alias: stamped ? `clean-vpn-dns:${record.id}` : '', mtu: 1500, up: false, master: null, addresses: [] };
}
export function validateOwnedLinkJournal(record) {
  fields(record, ['schema', 'backend', 'id', 'context', 'name', 'ifindex', 'stage']);
  assert.equal(record.schema, 1); assert.equal(record.backend, 'owned-dns-link-namespace');
  assert.match(record.id, /^[a-f0-9]{32}$/); validateOwnedLinkContext(record.context);
  assert.match(record.name, /^cvdns[a-f0-9]{8}$/);
  assert.equal(record.name, `cvdns${record.id.slice(0, 8)}`);
  assert.ok(['prepared', 'create-intent', 'unstamped', 'stamp-intent', 'created', 'delete-intent', 'deleted', 'released'].includes(record.stage));
  if (['prepared', 'create-intent'].includes(record.stage)) assert.equal(record.ifindex, null);
  else if (record.ifindex === null) assert.ok(['deleted', 'released'].includes(record.stage));
  else assert.ok(Number.isSafeInteger(record.ifindex) && record.ifindex > 1);
  return record;
}
export const readOwnedLinkJournal = (directory) => readPrivateJournal(directory, validateOwnedLinkJournal);
export const writeOwnedLinkJournal = (directory, record, checkpoint, label = record.stage) =>
  writePrivateJournal(directory, record, validateOwnedLinkJournal, checkpoint, 8192, label);

export function assertOwnedEmptyLink(record, current, stamped = true) {
  assert.ok(current, 'owned link missing');
  fields(current, ['ifindex', ...Object.keys(ownedLinkSpec(record)), 'dns']);
  assert.ok(Number.isSafeInteger(current.ifindex) && current.ifindex > 1);
  if (record.ifindex !== null) assert.equal(current.ifindex, record.ifindex, 'link incarnation changed');
  const { ifindex, dns, ...spec } = current;
  assert.deepEqual(spec, ownedLinkSpec(record, stamped), 'link ownership conflict');
  fields(dns, ['DNSEx', 'Domains', 'DefaultRoute']);
  assert.deepEqual(dns.DNSEx, [], 'configured DNS link must be released separately');
  assert.deepEqual(dns.Domains, [], 'configured DNS domains must be released separately');
  // An empty link's automatic DefaultRoute is not a DNS route (it has no server).
  assert.equal(typeof dns.DefaultRoute, 'boolean');
  return ifindex;
}

/** Caller holds stable process-lifetime flock; backend independently checks context/state. */
export async function ownedLinkTransaction({ directory, operation, scope, backend, checkpoint = async () => {} }) {
  assert.ok(['enable', 'recover', 'disable'].includes(operation));
  await backend.ensureGuard(); await checkpoint('guard-installed');
  let record;
  const save = async (stage) => { record = { ...record, stage }; await writeOwnedLinkJournal(directory, record, checkpoint); await checkpoint(stage); };
  if (operation === 'enable') {
    try { await readOwnedLinkJournal(directory); throw new Error('journal already exists'); }
    catch (e) { if (e.code !== 'ENOENT') throw e; }
    const context = validateOwnedLinkContext(await backend.context()); assert.deepEqual(context.scope, scope);
    const id = randomBytes(16).toString('hex');
    record = { schema: 1, backend: 'owned-dns-link-namespace', id, context, name: `cvdns${id.slice(0, 8)}`, ifindex: null, stage: 'prepared' };
    assert.equal(await backend.view(record.name), null, 'name already occupied');
    await save('prepared');
  } else record = await readOwnedLinkJournal(directory);
  assert.deepEqual(record.context.scope, scope, 'stale namespace scope');
  const observe = async () => {
    assert.deepEqual(await backend.context(), record.context, 'link context changed');
    const current = await backend.view(record.name);
    assert.deepEqual(await backend.context(), record.context, 'link context changed during read');
    return current;
  };
  let current = await observe();
  if (record.stage === 'prepared') {
    assert.equal(current, null, 'link exists without create intent');
    // Disabling before creation need not create/delete a link just to unwind.
    if (operation === 'disable') {
      await save('deleted');
    } else await save('create-intent');
  }
  if (record.stage === 'create-intent') {
    current = await observe();
    if (current === null && operation === 'disable') await save('deleted');
    else {
      if (current === null) {
        await backend.create(record.context, ownedLinkSpec(record, false)); await checkpoint('link-created');
        current = await observe();
      }
      // Our 5.4 fixture did not retain alias passed to ip link add. Name + independent MAC
      // bits identify this pending creation; alias has its own durable step.
      const ifindex = assertOwnedEmptyLink(record, current, false);
      record = { ...record, ifindex }; await save('unstamped');
    }
  }
  if (record.stage === 'unstamped') {
    assertOwnedEmptyLink(record, await observe(), false); await save('stamp-intent');
  }
  if (record.stage === 'stamp-intent') {
    current = await observe(); assert.ok(current, 'owned link missing');
    if (current.alias === '') {
      assertOwnedEmptyLink(record, current, false);
      await backend.stamp(record.context, current, ownedLinkSpec(record).alias); await checkpoint('link-stamped');
    }
    assertOwnedEmptyLink(record, await observe()); await save('created');
  }
  if (record.stage === 'created') {
    assertOwnedEmptyLink(record, await observe());
    if (operation !== 'disable') { await checkpoint('active'); return { status: 'created', id: record.id, name: record.name, ifindex: record.ifindex }; }
    await save('delete-intent');
  }
  if (record.stage === 'delete-intent') {
    current = await observe();
    if (current !== null) {
      assertOwnedEmptyLink(record, current);
      await backend.remove(record.context, current); await checkpoint('link-deleted');
    }
    assert.equal(await observe(), null, 'delete read-back mismatch'); await save('deleted');
  }
  assert.ok(['deleted', 'released'].includes(record.stage));
  assert.equal(await observe(), null, 'deleted name reused');
  await backend.releaseGuard(record.context, record.name); await checkpoint('guard-removed');
  await save('released'); return { status: 'released', id: record.id };
}
