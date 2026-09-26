import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, writeFile, rename, rm, chmod, symlink, link, readdir, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { dnsmasqTransaction, inspectDnsmasqTransaction, readDnsmasqJournal, writeDnsmasqJournal,
  validateDnsmasqJournal } from './lib/dnsmasq-journal.mjs';
import { createDnsmasqJournalFiles } from './lib/dnsmasq-journal-files.mjs';

const baseline = await readFile(new URL('./fixtures/dns-clients/radxa-dnsmasq.conf', import.meta.url), 'utf8');
const scope = { net: 'net:[1]', mnt: 'mnt:[2]', pid: 'pid:[3]' };
const crash = (point) => async (current) => { if (current === point) throw new Error('interruption'); };
async function fixture(t, { normalize = true } = {}) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'meshpn-dnsmasq-journal-test-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = join(directory, 'dnsmasq.conf'); await writeFile(file, baseline, { mode: 0o600 });
  const state = { guard: false, ready: true, starts: 0, probes: 0, loaded: null, activationFails: false,
    identity: { scope: structuredClone(scope), bootId: '12345678-1234-1234-1234-123456789abc',
      executableSha256: 'a'.repeat(64), link: { ifindex: 2, ifname: 'usb0', address: '02:00:00:00:00:01' } } };
  let hook = async () => {};
  const backend = await createDnsmasqJournalFiles({ directory, port: 1053, normalizeDhcpDns: normalize,
    identity: async () => structuredClone(state.identity), checkpoint: (point) => hook(point),
    ensureGuard: async () => { state.guard = true; },
    removeGuard: async () => {
      assert.equal(await readFile(file, 'utf8'), baseline);
      assert.equal((await readDnsmasqJournal(directory)).direction, 'restore'); state.guard = false;
    },
    probe: async () => { state.probes++; assert.ok(state.guard); assert.ok(state.ready, 'not ready'); },
    activate: async (record) => {
      assert.ok(state.guard); assert.ok(!state.activationFails, 'daemon unavailable');
      const persisted = await readDnsmasqJournal(directory);
      assert.equal(persisted.id, record.id); assert.ok(persisted.cursor === 2 || persisted.cursor === 1 && persisted.pending);
      const snapshot = (await backend.view()).snapshot;
      if (snapshot.identity !== state.loaded) { state.loaded = snapshot.identity; state.starts++; }
    } });
  return { directory, file, state, backend,
    run: (operation, checkpoint = async () => {}) => {
      hook = checkpoint; return dnsmasqTransaction({ directory, operation, scope, backend, checkpoint });
    }, inspect: () => inspectDnsmasqTransaction({ directory, scope, backend }) };
}

test('dnsmasq private file lifecycle preserves exact baseline, stable id and daemon reconciliation', async (t) => {
  const f = await fixture(t), original = await f.backend.view();
  const active = await f.run('enable'); assert.equal(active.status, 'active'); assert.ok(f.state.guard);
  const record = await readDnsmasqJournal(f.directory);
  assert.equal(record.baseline, baseline); assert.deepEqual(record.original, original.snapshot);
  assert.match(await readFile(f.file, 'utf8'), /server=127.0.0.1#1053/);
  assert.equal(f.state.starts, 1); assert.deepEqual(await f.run('recover'), active); assert.equal(f.state.starts, 1);
  f.state.loaded = null; await f.run('recover'); assert.equal(f.state.starts, 2);
  await assert.rejects(f.run('enable'), /already exists/);
  const released = await f.run('disable'); assert.equal(released.status, 'released'); assert.equal(released.id, active.id);
  assert.equal(f.state.guard, false); assert.equal(await readFile(f.file, 'utf8'), baseline);
  assert.deepEqual(await f.run('recover'), released); assert.equal(f.state.guard, false);
});
for (const direction of ['apply', 'restore']) {
  const points = direction === 'apply' ? ['prepared', 'ready', 'active'] : ['restore-start', 'restore-complete', 'guard-removed', 'released'];
  for (const step of ['config', 'daemon']) {
    for (const point of ['intent', 'set', 'ack']) points.push(`${direction}:${step}:${point}`);
    for (const boundary of ['intent', 'ack']) for (const flush of ['file-synced', 'renamed', 'dir-synced']) {
      points.push(`${direction}:${step}:${boundary}:${flush}`);
    }
  }
  points.push(`${direction}:config:renamed`, `${direction}:config:dir-synced`);
  for (const point of points) test(`dnsmasq journal recovery after ${point}`, async (t) => {
    const f = await fixture(t); if (direction === 'restore') await f.run('enable');
    await assert.rejects(f.run(direction === 'apply' ? 'enable' : 'disable', crash(point)), /interruption/);
    const id = (await readDnsmasqJournal(f.directory)).id;
    const recovered = await f.run('recover'); assert.equal(recovered.id, id);
    assert.equal(recovered.status, direction === 'apply' ? 'active' : 'released');
    assert.equal(f.state.guard, direction === 'apply');
    assert.equal(f.state.starts, direction === 'apply' ? 1 : 2);
    if (direction === 'restore') assert.equal(await readFile(f.file, 'utf8'), baseline);
  });
}
for (const point of ['prepared', 'apply:config:intent', 'apply:config:renamed', 'apply:daemon:intent']) {
  test(`explicit disable from partial enable: ${point}`, async (t) => {
    const f = await fixture(t); await assert.rejects(f.run('enable', crash(point)), /interruption/);
    f.state.ready = false; assert.equal((await f.run('disable')).status, 'released');
    assert.equal(await readFile(f.file, 'utf8'), baseline); assert.equal(f.state.guard, false);
  });
}
test('dry-run reads only; readiness failure changes neither file nor daemon', async (t) => {
  const f = await fixture(t); f.state.ready = false;
  await assert.rejects(f.run('enable'), /not ready/);
  const files = await readdir(f.directory), journal = await readFile(join(f.directory, 'journal.json'));
  f.state.guard = false;
  const report = await f.inspect(); assert.equal(report.mode, 'dry-run'); assert.equal(report.daemonStateVerified, false);
  assert.equal(f.state.guard, false); assert.equal(f.state.probes, 1); assert.equal(f.state.starts, 0);
  assert.equal(await readFile(f.file, 'utf8'), baseline);
  assert.deepEqual(await readdir(f.directory), files); assert.deepEqual(await readFile(join(f.directory, 'journal.json')), journal);
  f.state.ready = true; await f.run('recover'); assert.ok(f.state.guard);
});
test('daemon failure leaves guard and intent; recovery reloads only owned config', async (t) => {
  const f = await fixture(t); f.state.activationFails = true;
  await assert.rejects(f.run('enable'), /daemon unavailable/);
  const record = await readDnsmasqJournal(f.directory); assert.equal(record.cursor, 1); assert.equal(record.pending, true);
  assert.ok(f.state.guard); f.state.activationFails = false; assert.equal((await f.run('recover')).status, 'active');
});
test('guard failure prevents preparation and daemon work', async (t) => {
  const f = await fixture(t);
  f.backend.ensureGuard = async () => { throw new Error('guard refused'); };
  await assert.rejects(f.run('enable'), /guard refused/);
  assert.deepEqual(await readdir(f.directory), ['dnsmasq.conf']);
  assert.equal(await readFile(f.file, 'utf8'), baseline); assert.equal(f.state.starts, 0);
});
test('readiness lost during daemon activation leaves guarded pending operation', async (t) => {
  const f = await fixture(t), activate = f.backend.activate;
  f.backend.activate = async (...args) => { await activate(...args); f.state.ready = false; };
  await assert.rejects(f.run('enable'), /not ready/); assert.ok(f.state.guard);
  const record = await readDnsmasqJournal(f.directory); assert.equal(record.cursor, 1); assert.equal(record.pending, true);
  f.backend.activate = activate; f.state.ready = true;
  assert.equal((await f.run('recover')).status, 'active'); assert.equal(f.state.starts, 1);
});
for (const kind of ['oversized', 'public-mode', 'symlink', 'hardlink', 'public-directory']) {
  test(`dnsmasq journal refuses unsafe storage: ${kind}`, async (t) => {
    const f = await fixture(t); await f.run('enable'); const path = join(f.directory, 'journal.json');
    if (kind === 'oversized') await writeFile(path, ' '.repeat(131073));
    if (kind === 'public-mode') await chmod(path, 0o644);
    if (kind === 'symlink') { await rename(path, join(f.directory, 'foreign.json')); await symlink('foreign.json', path); }
    if (kind === 'hardlink') await link(path, join(f.directory, 'alias'));
    if (kind === 'public-directory') await chmod(f.directory, 0o755);
    const current = await readFile(f.file); await assert.rejects(f.run('recover'));
    assert.deepEqual(await readFile(f.file), current); assert.ok(f.state.guard);
  });
}
for (const point of ['snapshot:managed:file-synced', 'snapshots:dir-synced', 'prepared:file-synced']) {
  test(`uncommitted preparation is not recovery authority: ${point}`, async (t) => {
    const f = await fixture(t); await assert.rejects(f.run('enable', crash(point)), /interruption/);
    await assert.rejects(f.run('recover'), { code: 'ENOENT' }); assert.ok(f.state.guard);
    assert.equal(await readFile(f.file, 'utf8'), baseline);
    await assert.rejects(f.run('enable'), { code: 'EEXIST' });
  });
}
for (const flush of ['file-synced', 'renamed', 'dir-synced']) test(`committed restore direction at ${flush}`, async (t) => {
  const f = await fixture(t); await f.run('enable');
  await assert.rejects(f.run('disable', crash(`restore-start:${flush}`)), /interruption/);
  assert.equal((await f.run('recover')).status, flush === 'file-synced' ? 'active' : 'released');
});
for (const change of ['boot', 'link', 'scope', 'executable', 'text', 'same-text-inode', 'restored', 'symlink', 'hardlink', 'mode', 'journal']) {
  test(`foreign/stale state refuses writes and keeps guard: ${change}`, async (t) => {
    const f = await fixture(t); await f.run('enable');
    if (change === 'boot') f.state.identity.bootId = '00000000-0000-0000-0000-000000000000';
    if (change === 'link') f.state.identity.link.ifindex++;
    if (change === 'scope') f.state.identity.scope.net = 'net:[7]';
    if (change === 'executable') f.state.identity.executableSha256 = 'b'.repeat(64);
    if (change === 'text') await writeFile(f.file, 'foreign config\n');
    if (change === 'same-text-inode') {
      const other = join(f.directory, 'foreign.conf'); await writeFile(other, await readFile(f.file), { mode: 0o600 });
      await rename(other, f.file);
    }
    if (change === 'restored') await writeFile(join(f.directory, 'restored.conf'), 'foreign snapshot\n');
    if (change === 'symlink') { await rename(f.file, join(f.directory, 'foreign.conf')); await symlink('foreign.conf', f.file); }
    if (change === 'hardlink') await link(f.file, join(f.directory, 'alias'));
    if (change === 'mode') await chmod(f.file, 0o644);
    if (change === 'journal') await writeFile(join(f.directory, 'journal.json'), '{broken');
    const before = await readFile(f.file), journal = await readFile(join(f.directory, 'journal.json')), starts = f.state.starts;
    await assert.rejects(f.run('recover')); await assert.rejects(f.run('disable'));
    assert.ok(f.state.guard); assert.equal(f.state.starts, starts);
    assert.deepEqual(await readFile(f.file), before); assert.deepEqual(await readFile(join(f.directory, 'journal.json')), journal);
  });
}
test('conflict at guard release retains guard; normalization permission is explicit', async (t) => {
  const f = await fixture(t); await f.run('enable');
  await assert.rejects(f.run('disable', async (point) => {
    if (point === 'restore-complete') await writeFile(f.file, 'foreign');
  }), /ownership conflict/); assert.ok(f.state.guard);
  const unapproved = await fixture(t, { normalize: false });
  await assert.rejects(unapproved.run('enable'), /explicit/);
  assert.deepEqual(await readdir(unapproved.directory), ['dnsmasq.conf']);
});
test('strict journal schema rejects commands, arbitrary config, identities and unreachable state', async (t) => {
  const f = await fixture(t); await f.run('enable'); const record = await readDnsmasqJournal(f.directory);
  for (const mutate of [(r) => { r.command = '/bin/true'; }, (r) => { r.schema++; }, (r) => { r.backend = 'host'; },
    (r) => { r.baseline += 'conf-file=/etc/dnsmasq.conf\n'; }, (r) => { r.port = 53; },
    (r) => { r.managed.identity = r.original.identity; }, (r) => { r.original.sha256 = '0'.repeat(64); },
    (r) => { r.cursor = 3; }, (r) => { r.pending = true; }, (r) => { r.stage = 'released'; },
    (r) => { r.start = r.managed; }, (r) => { r.context.link.ifname = 'eth0'; }]) {
    const value = structuredClone(record); mutate(value); assert.throws(() => validateDnsmasqJournal(value));
  }
  record.context.scope.net = 'net:[123]'; await writeDnsmasqJournal(f.directory, record);
  await assert.rejects(f.run('recover'), /stale namespace/);
});
