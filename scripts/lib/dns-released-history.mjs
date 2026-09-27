/** Read-only released-journal evidence. No state adoption, deletion or authority
 * to stop services/release rules. The caller separately checks the real OS. */
import assert from 'node:assert/strict';
import { lstat } from 'node:fs/promises';
import { join, resolve, parse } from 'node:path';
import { readCoupledJournal, validateCoupledJournal } from './dns-coupled-journal.mjs';
import { readOwnedLinkJournal, validateOwnedLinkJournal, validateOwnedLinkContext } from './dns-owned-link-journal.mjs';
import { readDnsGuardJournal, validateDnsGuardJournal } from './dns-client-guard-journal.mjs';
import { compileDnsClientGuard } from './dns-client-guard.mjs';

export function assertReleasedDnsHistory({ transaction, link, guard }, { input, context, firewallBackend, guardIdentity }) {
  validateCoupledJournal(transaction); validateOwnedLinkJournal(link); validateDnsGuardJournal(guard);
  validateOwnedLinkContext(context); compileDnsClientGuard(input); assert.equal(input.client, 'vps2');
  assert.ok(['legacy', 'nf_tables'].includes(firewallBackend)); assert.match(guardIdentity, /^\d+:\d+$/);
  assert.equal(transaction.phase, 'released'); assert.equal(transaction.direction, 'restore');
  assert.equal(transaction.pending, false); assert.equal(transaction.level, 0);
  assert.equal(link.stage, 'released'); assert.equal(link.id, transaction.id); assert.equal(link.name, transaction.name);
  assert.deepEqual(link.context, transaction.context); assert.deepEqual(transaction.context, context, 'stale released DNS context');
  if (transaction.original) assert.equal(link.ifindex, transaction.original.ifindex);
  assert.equal(guard.stage, 'released'); assert.deepEqual(guard.input, input, 'released guard policy differs');
  assert.deepEqual(guard.context, { bootId: context.bootId, netns: context.scope.net,
    directoryIdentity: guardIdentity, firewall: { ipv4: firewallBackend, ipv6: firewallBackend }, usb: null });
}

/** Root-owned ancestry, bounded no-follow readers, and before/after metadata.
 * The generic directory is for isolated fixtures; the installed collector uses
 * only /var/lib/clean-vpn/dns-v1. Absence/partial history is never accepted. */
export async function readReleasedDnsHistory({ directory, input, context, firewallBackend }) {
  assert.equal(process.getuid(), 0); assert.equal(resolve(directory), directory); assert.notEqual(directory, '/');
  const parts = directory.slice(1).split('/'), parents = ['/'];
  for (const part of parts) parents.push(join(parents.at(-1), part));
  const owned = [directory, join(directory, 'transaction'), join(directory, 'transaction/link'), join(directory, 'guard')];
  const directories = [...new Set([...parents, ...owned])];
  const files = owned.slice(1).map((p) => join(p, 'journal.json'));
  const snapshot = async () => {
    const result = {};
    for (const path of [...directories, ...files]) {
      const s = await lstat(path, { bigint: true });
      assert.equal(s.uid, 0n); assert.equal(s.mode & 0o022n, 0n);
      if (directories.includes(path)) {
        assert.ok(s.isDirectory(), 'journal ancestor must be a directory');
        if (owned.includes(path)) assert.equal(s.mode & 0o7777n, 0o700n);
      } else {
        assert.ok(s.isFile() && s.nlink === 1n); assert.equal(s.mode & 0o7777n, 0o600n);
        assert.ok(s.size > 0n && s.size <= (parse(path).dir === join(directory, 'transaction') ? 16384n : 8192n));
      }
      // Parent contents may legitimately change (e.g. another /var/lib user).
      // Pin their incarnation, not unrelated directory ctime changes.
      result[path] = { dev: s.dev.toString(), ino: s.ino.toString(), mode: s.mode.toString(),
        ...(owned.includes(path) || files.includes(path) ? { ctime: s.ctimeNs.toString(), size: s.size.toString() } : {}) };
    }
    return result;
  };
  const before = await snapshot(), guardStat = before[join(directory, 'guard')];
  const history = { transaction: await readCoupledJournal(join(directory, 'transaction')),
    link: await readOwnedLinkJournal(join(directory, 'transaction/link')), guard: await readDnsGuardJournal(join(directory, 'guard')) };
  assertReleasedDnsHistory(history, { input, context, firewallBackend, guardIdentity: `${guardStat.dev}:${guardStat.ino}` });
  assert.deepEqual(await snapshot(), before, 'released DNS history changed during read');
  return { history, metadata: before };
}
