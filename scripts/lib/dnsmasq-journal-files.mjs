/** Private fixture files only. Caller supplies namespace guard and owned daemon operations. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { open, lstat, rename, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { privateJournalDirectory, syncDirectory } from './dns-lifecycle-journal.mjs';
import { dnsmasqHash, validateDnsmasqContext } from './dnsmasq-journal.mjs';
import { compileRadxaDnsmasqLabConfig } from './dnsmasq-lab-config.mjs';

async function privateConfig(path) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await fd.stat({ bigint: true });
    assert.ok(stat.isFile() && stat.nlink === 1n && stat.uid === BigInt(process.getuid()), 'private config required');
    assert.equal(stat.mode & 0o7777n, 0o600n);
    assert.ok(stat.size > 0n && stat.size <= 32768n, 'config size');
    const bytes = Buffer.alloc(32769), { bytesRead } = await fd.read(bytes, 0, bytes.length, 0);
    assert.equal(BigInt(bytesRead), stat.size, 'config changed or oversized');
    const text = bytes.subarray(0, bytesRead).toString('utf8');
    assert.ok(Buffer.from(text).equals(bytes.subarray(0, bytesRead)), 'invalid UTF-8');
    const after = await fd.stat({ bigint: true });
    assert.equal(after.ctimeNs, stat.ctimeNs, 'config changed during read');
    return { text, snapshot: { identity: `${stat.dev}:${stat.ino}`, sha256: dnsmasqHash(text) } };
  } finally { await fd.close(); }
}

export async function createDnsmasqJournalFiles({ directory, identity, port, normalizeDhcpDns = false,
  ensureGuard, removeGuard, probe, activate, checkpoint = async () => {} }) {
  await privateJournalDirectory(directory);
  assert.equal(await realpath(directory), resolve(directory), 'symlink directory ancestry forbidden');
  const stat = await lstat(directory, { bigint: true }), directoryIdentity = `${stat.dev}:${stat.ino}`;
  const context = async () => {
    await privateJournalDirectory(directory);
    assert.equal(await realpath(directory), resolve(directory), 'directory path changed');
    const latest = await lstat(directory, { bigint: true });
    assert.equal(`${latest.dev}:${latest.ino}`, directoryIdentity, 'directory replaced');
    return validateDnsmasqContext({ ...await identity(), directoryIdentity });
  };
  const paths = Object.fromEntries(['config', 'managed', 'restored'].map((name) =>
    [name, join(directory, name === 'config' ? 'dnsmasq.conf' : `${name}.conf`)]));
  const view = async () => ({ context: await context(), snapshot: (await privateConfig(paths.config)).snapshot });
  async function match(record, expected) {
    const current = await view(); assert.deepEqual(current.context, record.context, 'dnsmasq context changed');
    assert.deepEqual(current.snapshot, expected, 'dnsmasq ownership conflict'); return current;
  }
  const backend = {
    ensureGuard, view,
    async prepare() {
      assert.equal(normalizeDhcpDns, true, 'explicit DHCP DNS normalization required');
      const before = await view(), original = await privateConfig(paths.config);
      assert.deepEqual(original.snapshot, before.snapshot);
      const plan = compileRadxaDnsmasqLabConfig(original.text, { port, normalizeDhcpDns });
      const prepared = { context: before.context, baseline: original.text, port, original: original.snapshot };
      // Exclusive creation: orphan files are evidence, never silently adopted or overwritten.
      for (const name of ['managed', 'restored']) {
        const fd = await open(paths[name], 'wx', 0o600);
        try { await fd.writeFile(name === 'managed' ? plan.managed : plan.baseline); await fd.sync(); }
        finally { await fd.close(); }
        prepared[name] = (await privateConfig(paths[name])).snapshot;
        await checkpoint(`snapshot:${name}:file-synced`);
      }
      await syncDirectory(directory); await checkpoint('snapshots:dir-synced');
      await match(prepared, prepared.original); return prepared;
    },
    async verifySnapshots(record) {
      const current = await view(); assert.deepEqual(current.context, record.context, 'dnsmasq context changed');
      for (const name of ['managed', 'restored']) {
        if (current.snapshot.identity === record[name].identity) {
          assert.deepEqual(current.snapshot, record[name]); continue;
        }
        // Once restore is selected, the replaced managed inode is intentionally gone.
        if (name === 'managed' && current.snapshot.identity === record.restored.identity) continue;
        assert.deepEqual((await privateConfig(paths[name])).snapshot, record[name], 'snapshot changed');
      }
    },
    async probe(expectedPort) { assert.equal(expectedPort, port, 'adapter endpoint changed'); await probe(); },
    async select(record) {
      assert.equal(record.pending, true); assert.equal(record.cursor, 0);
      const name = record.direction === 'apply' ? 'managed' : 'restored';
      await backend.verifySnapshots(record); await match(record, record.start);
      assert.deepEqual((await privateConfig(paths[name])).snapshot, record[name]);
      // The directory is exclusively owned and caller holds flock. This is not
      // a kernel compare-and-swap against hostile same-uid writers.
      await rename(paths[name], paths.config); await checkpoint(`${record.direction}:config:renamed`);
      await syncDirectory(directory); await checkpoint(`${record.direction}:config:dir-synced`);
      await match(record, record[name]);
    },
    async activate(record) {
      const selected = record[record.direction === 'apply' ? 'managed' : 'restored'];
      await match(record, selected); await activate(record, paths.config); await match(record, selected);
    },
    async removeGuard(record) {
      assert.equal(record.direction, 'restore'); assert.equal(record.cursor, 2); assert.equal(record.pending, false);
      await match(record, record.restored); await removeGuard();
    },
  };
  return backend;
}
