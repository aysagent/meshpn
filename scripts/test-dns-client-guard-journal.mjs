import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm, readFile, writeFile, chmod, rename, symlink, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { dnsGuardTransaction, readDnsGuardJournal, validateDnsGuardJournal, createDnsGuardJournalBackend } from './lib/dns-client-guard-journal.mjs';
import { compileDnsClientGuard } from './lib/dns-client-guard.mjs';

async function fixture(t, client = 'vps2') {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-guard-journal-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const config = { schema: 1, client, ...(client === 'radxa' ? { usbInterface: 'usb0', usbAddress: '192.168.7.1' } : {}) };
  const state = { families: ['absent', 'absent'], writes: 0, authorized: true,
    context: { bootId: '11111111-1111-1111-1111-111111111111', netns: 'net:[1]', directoryIdentity: '1:2',
      firewall: { ipv4: 'nf_tables', ipv6: 'nf_tables' },
      usb: client === 'radxa' ? { name: 'usb0', ifindex: 3, mac: '00:11:22:33:44:55', address: '192.168.7.1' } : null } };
  const backend = { config: async () => structuredClone(config), context: async () => structuredClone(state.context),
    inspect: async () => [...state.families], authorizeRelease: async () => state.authorized,
    commit: async (record, family) => { state.writes++; state.families[family === 4 ? 0 : 1] = record.stage === 'installing' ? 'present' : 'absent'; } };
  return { directory, state, config, backend, run: (operation, checkpoint) => dnsGuardTransaction({ directory, operation, backend, checkpoint }) };
}
const points = ['installing:dir-synced', 'installing:4:committed', 'installing:6:committed', 'active:file-synced', 'active:renamed', 'active',
  'releasing:file-synced', 'releasing:renamed', 'releasing:dir-synced', 'releasing:4:committed', 'releasing:6:committed', 'released:renamed'];
for (const client of ['vps2', 'radxa']) for (const point of points) test(`${client} guard durable recovery: ${point}`, async (t) => {
  const f = await fixture(t, client), releasing = /^(releasing|released)/.test(point);
  if (releasing) await f.run('enable');
  await assert.rejects(f.run(releasing ? 'disable' : 'enable', async (p) => { if (p === point) throw new Error('crash'); }), /crash/);
  const prior = await readDnsGuardJournal(f.directory);
  const result = await f.run('recover'); assert.equal(result.id, prior.input.id);
  const released = releasing && point !== 'releasing:file-synced';
  assert.equal(result.stage, released ? 'released' : 'active');
  assert.deepEqual(f.state.families, released ? ['absent', 'absent'] : ['present', 'present']);
});
test('first intent is required before firewall mutation; inspect is read-only', async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.run('start'), { code: 'ENOENT' }); assert.equal(f.state.writes, 0);
  await assert.rejects(f.run('enable', async (p) => { if (p === 'installing:file-synced') throw new Error('crash'); }));
  assert.equal(f.state.writes, 0); await assert.rejects(f.run('recover'), { code: 'ENOENT' });
  await f.run('enable'); const bytes = await readFile(join(f.directory, 'journal.json')), writes = f.state.writes;
  assert.equal((await f.run('inspect')).mode, 'read-only'); assert.equal(f.state.writes, writes);
  assert.deepEqual(await readFile(join(f.directory, 'journal.json')), bytes);
  await assert.rejects(f.run('enable'), /already exists/);
});
test('service start cannot reverse release intent, and recovery requires current proof', async (t) => {
  const f = await fixture(t); await f.run('enable');
  await assert.rejects(f.run('disable', async (p) => { if (p === 'releasing:4:committed') throw new Error('crash'); }));
  await assert.rejects(f.run('start'), /release intent/); assert.deepEqual(f.state.families, ['absent', 'present']);
  f.state.authorized = false; await assert.rejects(f.run('recover'), /proof/); assert.deepEqual(f.state.families, ['absent', 'present']);
  f.state.authorized = true; await f.run('recover'); await assert.rejects(f.run('start'), /release intent/);
  assert.equal((await f.run('recover')).stage, 'released');
});
test('missing family in active context is reasserted only after new durable install intent', async (t) => {
  const f = await fixture(t); await f.run('enable'); f.state.families[1] = 'absent';
  const writes = f.state.writes;
  await assert.rejects(f.run('start', async (p) => { if (p === 'installing:dir-synced') throw new Error('crash'); }));
  assert.equal(f.state.writes, writes); await f.run('recover'); assert.equal(f.state.writes, writes + 1);
});
test('completion after last removal still requires current restore proof', async (t) => {
  const f = await fixture(t); await f.run('enable');
  await assert.rejects(f.run('disable', async (p) => { if (p === 'releasing:6:committed') throw new Error('crash'); }));
  f.state.authorized = false; await assert.rejects(f.run('recover'), /release completion/);
  assert.equal((await readDnsGuardJournal(f.directory)).stage, 'releasing');
  assert.deepEqual(f.state.families, ['absent', 'absent']);
  f.state.authorized = true; assert.equal((await f.run('recover')).stage, 'released');
});
for (const key of ['bootId', 'netns', 'directoryIdentity', 'firewall', 'usb']) test(`stale ${key} is not adopted`, async (t) => {
  const f = await fixture(t, 'radxa'); await f.run('enable'); const bytes = await readFile(join(f.directory, 'journal.json'));
  f.state.context[key] = key === 'usb' ? { ...f.state.context.usb, ifindex: 4 } : key === 'firewall' ? { ipv4: 'legacy', ipv6: 'legacy' } : 'changed';
  const writes = f.state.writes;
  for (const op of ['start', 'recover', 'disable']) await assert.rejects(f.run(op));
  assert.equal(f.state.writes, writes); assert.deepEqual(await readFile(join(f.directory, 'journal.json')), bytes);
});
for (const unsafe of ['oversized', 'mode', 'symlink', 'hardlink', 'directory-mode', 'corrupt']) test(`unsafe journal ${unsafe} prevents setters`, async (t) => {
  const f = await fixture(t); await f.run('enable'); const path = join(f.directory, 'journal.json'), writes = f.state.writes;
  if (unsafe === 'oversized') await writeFile(path, ' '.repeat(8193));
  if (unsafe === 'mode') await chmod(path, 0o644);
  if (unsafe === 'directory-mode') await chmod(f.directory, 0o755);
  if (unsafe === 'corrupt') await writeFile(path, '{}');
  if (unsafe === 'hardlink') await link(path, join(f.directory, 'copy'));
  if (unsafe === 'symlink') { await rename(path, join(f.directory, 'copy')); await symlink('copy', path); }
  await assert.rejects(f.run('recover')); assert.equal(f.state.writes, writes);
});
test('schema binds USB identity and backend; policy drift and reappeared released rules fail', async (t) => {
  const f = await fixture(t, 'radxa'); await f.run('enable');
  const record = await readDnsGuardJournal(f.directory);
  assert.throws(() => validateDnsGuardJournal({ ...record, stage: 'unknown' }));
  assert.throws(() => validateDnsGuardJournal({ ...record, context: { ...record.context, usb: null } }));
  f.config.usbAddress = '192.168.7.2'; await assert.rejects(f.run('recover'), /policy changed/);
  f.config.usbAddress = '192.168.7.1'; await f.run('disable'); f.state.families[0] = 'present';
  await assert.rejects(f.run('recover'), /reappeared/);
});
test('real backend adapter revalidates context, policy and restore proof for each family', async (t) => {
  const f = await fixture(t); const config = f.config;
  const tables = new Map([[4, ''], [6, '']]); let writes = 0;
  const backend = createDnsGuardJournalBackend({ config, context: f.backend.context, read: async (family) => tables.get(family),
    authorizeRelease: async () => f.state.authorized,
    restore: async (family, batch) => {
      writes++;
      tables.set(family, batch.includes('\n-N ') ? batch.split('\n').filter((l) => /^-[NAI] /.test(l)).map((l) => l.replace(/^-I (\w+) 1 /, '-A $1 ')).join('\n') : '');
    } });
  const run = (operation) => dnsGuardTransaction({ directory: f.directory, operation, backend });
  await run('enable'); assert.equal(writes, 2);
  f.state.authorized = false; await assert.rejects(run('disable')); assert.equal(writes, 2);
  f.state.authorized = true; await run('disable'); assert.equal(writes, 4);
  const record = await readDnsGuardJournal(f.directory);
  await assert.rejects(backend.commit(record, 4), /intent/);
  assert.ok(compileDnsClientGuard(record.input));
});
