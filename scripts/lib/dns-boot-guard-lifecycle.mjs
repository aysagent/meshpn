/** Shared boot policy + guard journal lifecycle. Caller holds the SAME stable
 * lock across this code and every DNS setter; no auto-adoption of stale epochs. */
import assert from 'node:assert/strict';
import { dnsGuardTransaction, readDnsGuardJournal } from './dns-client-guard-journal.mjs';
import { readResolvedJournal } from './dns-resolved-journal.mjs';

export function createBootGuardLifecycle({ directory, boot, backend, restoring = false, allowBind = false, checkpoint }) {
  assert.equal(typeof restoring, 'boolean'); assert.equal(typeof allowBind, 'boolean');
  const run = (operation) => dnsGuardTransaction({ directory, operation, backend, checkpoint });
  return {
    async prepare() {
      let record;
      try { record = await readDnsGuardJournal(directory); }
      catch (error) {
        // Even a corrupt/missing journal must not stop the independent boot
        // policy protecting DNS before a controller refuses to continue.
        await boot.guard.ensure();
        if (error.code !== 'ENOENT') throw error;
      }
      if (restoring && record && ['releasing', 'released'].includes(record.stage)) {
        try {
          // Resume a partial release ONLY while DNS is already fully restored.
          // Never briefly install/apply managed DNS on this recovery path.
          assert.equal(await backend.authorizeRelease(record), true, 'verified restored baseline required');
          return await run('inspect');
        } catch (error) { await boot.guard.ensure(); throw error; }
      }
      await boot.guard.ensure();
      if (!record) assert.equal(allowBind, true, 'explicit new guard binding required');
      return run(record ? 'start' : 'bind-boot');
    },
    release: () => run('disable'),
  };
}

// For the resolved controller: durable restore-complete + exact current owner,
// link, namespace and settings. This is NOT a baseline health/network probe.
export async function verifyResolvedGuardRestore({ directory, backend }) {
  const record = await readResolvedJournal(directory);
  assert.equal(record.direction, 'restore'); assert.ok(['complete', 'released'].includes(record.stage));
  assert.equal(record.cursor, 3); assert.equal(record.pending, false);
  const view = await backend.view();
  assert.deepEqual(view.context, record.context, 'resolved restore context changed');
  assert.deepEqual(view.settings, record.original, 'resolved restored baseline changed');
  assert.deepEqual(await readResolvedJournal(directory), record, 'resolved restore journal changed during proof');
  return true;
}
