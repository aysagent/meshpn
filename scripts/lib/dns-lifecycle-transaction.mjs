/** Experimental journalled controller; receives ONLY a namespace fixture backend. */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readDnsJournal, writeDnsJournal } from './dns-lifecycle-journal.mjs';

export function sameDnsObject(a, b) { return Boolean(a && b && a.identity === b.identity && a.sha256 === b.sha256); }
export function expectedDnsObjects(record) {
  switch (record.stage) {
    case 'prepared': return [record.original];
    case 'applying': return [record.original, record.managed];
    case 'active': return [record.managed];
    case 'restoring': return [record.original, record.managed, record.restored];
    case 'restored': case 'released': return [record.restored];
    default: throw new Error('invalid journal stage');
  }
}

export async function dnsTransaction({ directory, scope, operation, backend, checkpoint = async () => {} }) {
  assert.ok(['enable', 'recover', 'disable'].includes(operation));
  // Missing/corrupt journal is NEVER permission to restore/unblock DNS.
  await backend.ensureGuard(); await checkpoint('guard-installed');
  let record;
  const save = async (stage) => {
    record = { ...record, stage }; await writeDnsJournal(directory, record, checkpoint);
  };
  if (operation === 'enable') {
    try { await readDnsJournal(directory); throw new Error('journal already exists'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    const snapshots = await backend.prepare();
    record = { schema: 1, backend: 'namespace-fixture', id: randomBytes(16).toString('hex'), scope,
      stage: 'prepared', ...snapshots };
    await save('prepared'); await checkpoint('prepared');
  } else record = await readDnsJournal(directory);
  assert.deepEqual(record.scope, scope, 'stale namespace scope: manual recovery required');
  const check = async () => {
    const current = await backend.current();
    assert.ok(expectedDnsObjects(record).some((value) => sameDnsObject(value, current)), 'DNS ownership conflict');
  };
  await check();
  await backend.verifySnapshots(record);
  if (operation === 'disable' || ['restoring', 'restored', 'released'].includes(record.stage)) {
    // Restore intent is durable authorization to finish a previously explicit disable.
    if (!['restoring', 'restored', 'released'].includes(record.stage)) await save('restoring');
    await checkpoint('restore-intent');
    if (record.stage === 'restoring') {
      await backend.select('restored', record, expectedDnsObjects(record));
      await checkpoint('restored-dns'); await save('restored');
    }
    await checkpoint('restore-committed');
    await check();
    await backend.removeGuard(); await checkpoint('guard-removed');
    await save('released'); await checkpoint('released');
    return { status: 'released', id: record.id };
  }
  await backend.probe(); await checkpoint('ready');
  await check();
  if (record.stage !== 'active') {
    await save('applying'); await checkpoint('apply-intent');
    await backend.select('managed', record, expectedDnsObjects(record));
    await checkpoint('applied'); await save('active');
  }
  await checkpoint('active'); return { status: 'active', id: record.id };
}
