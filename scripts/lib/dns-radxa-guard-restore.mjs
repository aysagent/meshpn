/** Exact paired rollback proof; caller owns the shared DNS/guard flock.
 * No DNS queries or setters. A dangling stub is never a releasable baseline. */
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { readRadxaJournal, inspectRadxaTransaction } from './dns-radxa-journal.mjs';
import { readDnsmasqJournal } from './dnsmasq-journal.mjs';
import { readResolverObjectJournal } from './dns-resolver-object-journal.mjs';

export async function verifyRadxaGuardRestore({ directory, scope, backend, verifyDaemon }) {
  const records = async () => ({ root: await readRadxaJournal(directory), dnsmasq: await readDnsmasqJournal(directory),
    resolver: await readResolverObjectJournal(join(directory, 'resolver-etc')) });
  const before = await records();
  assert.equal(before.root.phase, 'restored');
  assert.equal(before.dnsmasq.direction, 'restore'); assert.equal(before.dnsmasq.stage, 'released');
  assert.equal(before.dnsmasq.cursor, 2); assert.equal(before.dnsmasq.pending, false);
  assert.equal(before.resolver.phase, 'restored');
  assert.equal(before.resolver.original.kind, 'file', 'reviewed localhost-file baseline required');
  assert.equal(before.resolver.restored.kind, 'file');
  // Validators enforce the exact localhost bytes; inspection verifies child
  // bindings, snapshots, executable/USB/namespace/boot context and live files.
  await inspectRadxaTransaction({ directory, scope, backend });
  assert.equal(typeof verifyDaemon, 'function', 'loaded baseline daemon proof required');
  assert.equal(await verifyDaemon(before.dnsmasq), true, 'loaded baseline daemon proof required');
  await inspectRadxaTransaction({ directory, scope, backend });
  assert.deepEqual(await records(), before, 'Radxa journals changed during proof');
  return true;
}
