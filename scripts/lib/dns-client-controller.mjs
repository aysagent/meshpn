/** Shared client transaction controller. OS authority, fixed paths and the
 * process-lifetime DNS/guard lock belong to the caller's backend factories.
 * This module neither installs services nor grants live-host authority. */
import assert from 'node:assert/strict';
import { lstat, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { privateJournalDirectory } from './dns-lifecycle-journal.mjs';
import { coupledDnsTransaction, readCoupledJournal } from './dns-coupled-journal.mjs';
import { radxaDnsTransaction, readRadxaJournal } from './dns-radxa-journal.mjs';
import { verifyCoupledGuardRestore } from './dns-boot-guard-lifecycle.mjs';
import { verifyRadxaGuardRestore } from './dns-radxa-guard-restore.mjs';

const profiles = {
  vps2: {
    journals: ['journal.json', 'link/journal.json'], read: readCoupledJournal,
    transaction: coupledDnsTransaction, restored: verifyCoupledGuardRestore,
    canStart: (r) => r.direction === 'apply' && ['link', 'settings'].includes(r.phase),
  },
  radxa: {
    journals: ['radxa/journal.json', 'journal.json', 'resolver-etc/journal.json'], read: readRadxaJournal,
    transaction: radxaDnsTransaction, restored: verifyRadxaGuardRestore,
    canStart: (r) => ['dnsmasq', 'resolver', 'active'].includes(r.phase),
  },
};
const exists = async (path) => {
  // A dangling symlink is existing state, never permission for a fresh bind.
  try { await lstat(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; }
};
export async function dnsClientStateExists(client, directory) {
  assert.ok(Object.hasOwn(profiles, client), 'unsupported DNS client');
  return (await Promise.all(profiles[client].journals.map((name) => exists(join(directory, name))))).some(Boolean);
}

export async function createDnsClientController({ client, command, directory, createGuard, createContext, checkpoint = async () => {} }) {
  assert.ok(Object.hasOwn(profiles, client), 'unsupported DNS client');
  assert.ok(['start', 'disable'].includes(command), 'explicit start or disable required');
  assert.equal(typeof createGuard, 'function'); assert.equal(typeof createContext, 'function');
  const profile = profiles[client]; let guard, used = false;
  const context = async () => {
    assert.ok(guard, 'guard lifecycle must be constructed first');
    const value = await createContext({ ensureGuard: () => guard.prepare(), releaseGuard: () => guard.release() });
    assert.ok(value && value.scope && value.backend, 'DNS backend context required'); return value;
  };
  // The release verifier is chosen here, not supplied as an arbitrary true
  // callback by the service wrapper. It re-reads durable journals and live OS
  // state on every release step through the guard lifecycle.
  guard = await createGuard({ client, restoring: command === 'disable',
    dnsStateExists: () => dnsClientStateExists(client, directory),
    authorizeRelease: async () => {
      const { scope, backend, verifyDaemon } = await context();
      return profile.restored({ directory, scope, backend, verifyDaemon });
    } });
  assert.ok(guard && typeof guard.prepare === 'function' && typeof guard.release === 'function');
  return { guard,
    async run() {
      assert.equal(used, false, 'one command per controller instance'); used = true;
      await guard.prepare();
      // Storage and every OS DNS setter follow successful protection. Authority
      // to create this fixed directory was checked by createGuard's entrypoint.
      await mkdir(directory, { recursive: true, mode: 0o700 }); await privateJournalDirectory(directory);
      const { scope, backend } = await context();
      const present = await exists(join(directory, profile.journals[0]));
      const operation = command === 'disable' ? 'disable' : present ? 'recover' : 'enable';
      if (operation === 'recover') assert.ok(profile.canStart(await profile.read(directory)),
        'restoring/released DNS journal requires explicit disable or reviewed new epoch');
      const result = await profile.transaction({ directory, operation, scope, backend, checkpoint });
      // Coupled backend releases only after its owned link child is released.
      // The Radxa paired coordinator deliberately never releases protection;
      // this outer lifecycle proves both restored files and the loaded daemon.
      if (client === 'radxa' && command === 'disable') await guard.release();
      return { schema: 1, kind: 'clean-vpn-dns-client-controller', client, command, ...result,
        protectionRetained: command !== 'disable' };
    } };
}
