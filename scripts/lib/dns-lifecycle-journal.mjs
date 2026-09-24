/** Bounded durable storage for the namespace experiment, not a host backend. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { open, lstat, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

export const JOURNAL_STAGES = ['prepared', 'applying', 'active', 'restoring', 'restored', 'released'];
const MAX_BYTES = 8192;
function keys(value, names) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value), 'journal object required');
  assert.deepEqual(Object.keys(value).sort(), [...names].sort(), 'journal fields');
}
export function validateDnsJournal(value) {
  keys(value, ['schema', 'backend', 'id', 'scope', 'stage', 'original', 'managed', 'restored']);
  assert.equal(value.schema, 1); assert.equal(value.backend, 'namespace-fixture');
  assert.match(value.id, /^[a-f0-9]{32}$/); assert.ok(JOURNAL_STAGES.includes(value.stage));
  keys(value.scope, ['net', 'mnt', 'pid']);
  for (const key of ['net', 'mnt', 'pid']) assert.match(value.scope[key], new RegExp(`^${key}:\\[\\d+\\]$`));
  for (const key of ['original', 'managed', 'restored']) {
    keys(value[key], ['identity', 'sha256']);
    assert.match(value[key].identity, /^\d+:\d+$/); assert.match(value[key].sha256, /^[a-f0-9]{64}$/);
  }
  assert.equal(value.original.sha256, value.restored.sha256, 'restore must reproduce original bytes');
  return value;
}

export async function privateJournalDirectory(directory) {
  const stat = await lstat(directory);
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink(), 'private journal directory required');
  assert.equal(stat.uid, process.getuid()); assert.equal(stat.mode & 0o777, 0o700);
}
export async function syncDirectory(directory) {
  const fd = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await fd.sync(); } finally { await fd.close(); }
}

export async function readPrivateJournal(directory, validate, maxBytes = MAX_BYTES) {
  await privateJournalDirectory(directory);
  const fd = await open(join(directory, 'journal.json'), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await fd.stat();
    assert.ok(stat.isFile() && stat.nlink === 1 && stat.uid === process.getuid(), 'private regular journal required');
    assert.equal(stat.mode & 0o777, 0o600);
    assert.ok(stat.size > 0 && stat.size <= maxBytes, 'journal size limit');
    const buffer = Buffer.alloc(maxBytes + 1);
    const { bytesRead } = await fd.read(buffer, 0, buffer.length, 0);
    assert.equal(bytesRead, stat.size, 'journal changed or oversized');
    return validate(JSON.parse(buffer.subarray(0, bytesRead).toString('utf8')));
  } finally { await fd.close(); }
}

// Caller holds a process-lifetime flock on the private, stable lock inode.
// A killed writer may leave a temp file. Readers NEVER use it as recovery input.
export async function writePrivateJournal(directory, value, validate, checkpoint = async () => {}, maxBytes = MAX_BYTES, label = value.stage) {
  validate(value); await privateJournalDirectory(directory);
  const body = `${JSON.stringify(value)}\n`; assert.ok(Buffer.byteLength(body) <= maxBytes);
  const temporary = join(directory, `journal-${randomBytes(12).toString('hex')}.tmp`);
  const fd = await open(temporary, 'wx', 0o600);
  try { await fd.writeFile(body); await fd.sync(); } finally { await fd.close(); }
  await checkpoint(`${label}:file-synced`);
  await rename(temporary, join(directory, 'journal.json'));
  await checkpoint(`${label}:renamed`);
  await syncDirectory(directory);
  await checkpoint(`${label}:dir-synced`);
}

export const readDnsJournal = (directory) => readPrivateJournal(directory, validateDnsJournal);
export const writeDnsJournal = (directory, value, checkpoint) => writePrivateJournal(directory, value, validateDnsJournal, checkpoint);
