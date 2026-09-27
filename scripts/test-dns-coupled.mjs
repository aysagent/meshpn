import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { coupledDnsTransaction, readCoupledJournal, writeCoupledJournal, COUPLED_STEPS, validateCoupledJournal } from './lib/dns-coupled-journal.mjs';
import { createCoupledBackend } from './lib/dns-coupled-backend.mjs';
import { assertCoupledEvidence, COUPLED_CRASH_POINTS } from './lib/dns-coupled-crash-lab.mjs';
import { verifyCoupledGuardRestore } from './lib/dns-boot-guard-lifecycle.mjs';
import { readOwnedLinkJournal, writeOwnedLinkJournal } from './lib/dns-owned-link-journal.mjs';
import { createDnsClientController } from './lib/dns-client-controller.mjs';

const scope = { net: 'net:[1]', mnt: 'mnt:[2]', pid: 'pid:[3]' };
async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-coupled-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const s = { current: null, guard: false, port: 1053, ready: true, setters: [],
    context: { scope, bootId: '12345678-1234-1234-1234-123456789abc', busId: 'a'.repeat(32), owner: ':1.2' } };
  const b = {
    context: async () => structuredClone(s.context), ensureGuard: async () => { s.guard = true; },
    view: async () => structuredClone(s.current),
    linkView: async () => { if (!s.current) return null; const { addrgen, ...v } = s.current; return structuredClone(v); },
    adapterPort: async () => s.port, probe: async () => assert.equal(s.ready, true),
    async create(ctx, spec) { assert.equal(s.guard, true); assert.equal(s.current, null);
      s.current = { ...structuredClone(spec), ifindex: 10, addrgen: 'eui64', dns: { DNSEx: [], Domains: [], DefaultRoute: false } }; },
    async stamp(ctx, before, alias) { assert.deepEqual(await b.linkView(), before); s.current.alias = alias; },
    async remove(ctx, before) { assert.equal(s.guard, true); assert.deepEqual(await b.linkView(), before);
      assert.equal(s.current.up, false); assert.deepEqual(s.current.addresses, []); assert.deepEqual(s.current.dns.DNSEx, []); s.current = null; },
    async releaseGuard() { assert.equal(s.current, null); s.guard = false; },
    async set(ctx, before, step, after) { assert.equal(s.guard, true); assert.deepEqual(s.current, before); s.setters.push(step); s.current = structuredClone(after); },
  };
  const run = (operation, checkpoint) => coupledDnsTransaction({ directory, operation, scope, backend: b, checkpoint });
  return { directory, s, run, backend: b };
}
test('shared VPS2 controller preserves start identity, requires explicit disable, and proves release', async (t) => {
  const f = await fixture(t); let proof, releases = 0;
  const controller = (command, checkpoint) => createDnsClientController({ client: 'vps2', command, directory: f.directory, checkpoint,
    createGuard: async ({ client, restoring, authorizeRelease, dnsStateExists }) => {
      assert.equal(client, 'vps2'); assert.equal(restoring, command === 'disable'); proof = authorizeRelease;
      assert.equal(await dnsStateExists(), releases > 0 || f.s.current !== null);
      return { prepare: f.backend.ensureGuard, release: async () => { assert.equal(await authorizeRelease(), true); releases++; f.s.guard = false; } };
    },
    createContext: async ({ ensureGuard, releaseGuard }) => ({ scope, backend: { ...f.backend, ensureGuard, releaseGuard } }),
  });
  const first = await controller('start'), active = await first.run(); await assert.rejects(first.run(), /one command/);
  assert.equal(active.client, 'vps2'); assert.equal(active.protectionRetained, true); await assert.rejects(proof());
  assert.equal((await (await controller('start')).run()).id, active.id);
  await assert.rejects((await controller('disable', async (p) => { if (p === 'restore-intent') throw new Error('cut'); })).run(), /cut/);
  const before = await readFile(join(f.directory, 'journal.json'));
  await assert.rejects((await controller('start')).run(), /explicit disable/);
  assert.deepEqual(await readFile(join(f.directory, 'journal.json')), before); assert.equal(releases, 0);
  f.s.ready = false;
  const restored = await (await controller('disable')).run(); assert.equal(restored.id, active.id);
  assert.equal(restored.protectionRetained, false); assert.equal(f.s.guard, false); assert.equal(releases, 1);
  await assert.rejects((await controller('start')).run(), /explicit disable/);
});
test('guard proof requires both durable releases and absence of the owned name, without uplink restore', async (t) => {
  const f = await fixture(t), proof = () => verifyCoupledGuardRestore({ directory: f.directory, backend: f.backend });
  f.backend.releaseGuard = async () => { assert.equal(await proof(), true); f.s.guard = false; };
  await f.run('enable'); await assert.rejects(proof());
  await assert.rejects(f.run('disable', async (p) => { if (p === 'link-released') throw new Error('cut'); }), /cut/);
  assert.equal(f.s.current, null); assert.equal(f.s.guard, true); await assert.rejects(proof());
  await f.run('disable'); assert.equal(await proof(), true);
  f.s.current = { name: (await readCoupledJournal(f.directory)).name }; await assert.rejects(proof(), /name reused/); f.s.current = null;
  f.s.context.owner = ':1.9'; await assert.rejects(proof(), /context changed/);
});
test('guard proof refuses replaced child, unfinished child and journals changing during observation', async (t) => {
  const f = await fixture(t); await f.run('enable'); await f.run('disable');
  const proof = () => verifyCoupledGuardRestore({ directory: f.directory, backend: f.backend });
  const childPath = join(f.directory, 'link'), child = await readOwnedLinkJournal(childPath), root = await readCoupledJournal(f.directory);
  await writeOwnedLinkJournal(childPath, { ...child, ifindex: child.ifindex + 1 }); await assert.rejects(proof());
  await writeOwnedLinkJournal(childPath, { ...child, stage: 'delete-intent' }); await assert.rejects(proof());
  await writeOwnedLinkJournal(childPath, child);
  f.backend.view = async () => { await writeCoupledJournal(f.directory, { ...root, phase: 'unlink' }); return null; };
  await assert.rejects(proof(), /journal changed during proof/);
});
test('guard proof permits explicit rollback before link creation without inventing an uplink snapshot', async (t) => {
  const f = await fixture(t);
  f.backend.releaseGuard = async () => {
    assert.equal(await verifyCoupledGuardRestore({ directory: f.directory, backend: f.backend }), true);
    f.s.guard = false;
  };
  await assert.rejects(f.run('enable', async (point) => { if (point === 'prepared') throw new Error('cut'); }), /cut/);
  await f.run('disable'); assert.equal((await readCoupledJournal(f.directory)).original, null);
  assert.deepEqual(f.s.setters, []); assert.equal(f.s.current, null); assert.equal(f.s.guard, false);
});
const apply = ['prepared', 'link:link-created', 'link:link-stamped', 'link-ready', 'settings-prepared',
  ...COUPLED_STEPS.flatMap((s) => ['intent', 'set', 'ack'].map((p) => `apply:${s}:${p}`)), 'active'];
const restore = ['restore-intent', ...[...COUPLED_STEPS].reverse().flatMap((s) => ['intent', 'set', 'ack'].map((p) => `restore:${s}:${p}`)),
  'unlink-intent', 'link:delete-intent', 'link:link-deleted', 'link-released', 'release-intent', 'guard-removed'];
for (const [operation, points] of [['enable', apply], ['disable', restore]]) for (const point of points)
  test(`coupled ${operation} resumes after ${point}`, async (t) => {
    const f = await fixture(t); if (operation === 'disable') await f.run('enable');
    await assert.rejects(f.run(operation, async (p) => { if (p === point) throw new Error('crash'); }), /crash/);
    const r = await f.run('recover'); assert.equal(r.status, operation === 'enable' ? 'active' : 'released');
    if (operation === 'enable') { assert.equal(f.s.guard, true); await f.run('disable'); }
    assert.equal(f.s.current, null); assert.equal(f.s.guard, false);
    assert.equal((await f.run('recover')).status, 'released');
  });
for (const point of ['prepared', 'link:link-created', 'link-ready', 'apply:address:set', 'apply:DNSEx:set', 'active'])
  test(`coupled explicit disable unwinds partial apply at ${point} without upstream`, async (t) => {
    const f = await fixture(t);
    await assert.rejects(f.run('enable', async (p) => { if (p === point) throw new Error('crash'); }));
    f.s.ready = false; assert.equal((await f.run('disable')).status, 'released'); assert.equal(f.s.current, null); assert.equal(f.s.guard, false);
  });
for (const [name, mutate] of [
  ['DNS', (s) => { s.current.dns.Domains = [['foreign.test', true]]; }],
  ['address', (s) => { s.current.addresses.push('inet:192.0.2.2/32'); }],
  ['ifindex', (s) => { s.current.ifindex++; }],
  ['alias', (s) => { s.current.alias = 'foreign'; }],
  ['addrgen', (s) => { s.current.addrgen = 'eui64'; }],
  ['boot', (s) => { s.context = { ...s.context, bootId: '00000000-0000-0000-0000-000000000000' }; }],
]) test(`coupled recovery refuses ${name} drift without setters or journal overwrite`, async (t) => {
  const f = await fixture(t); await f.run('enable'); mutate(f.s);
  const before = structuredClone(f.s.current), setters = f.s.setters.length, record = await readCoupledJournal(f.directory);
  for (const op of ['recover', 'disable']) {
    await assert.rejects(f.run(op)); assert.equal(f.s.guard, true); assert.equal(f.s.setters.length, setters);
    assert.deepEqual(f.s.current, before); assert.deepEqual(await readCoupledJournal(f.directory), record);
  }
});
test('coupled adapter outage/endpoint change blocks recovery but permits explicit disable', async (t) => {
  const f = await fixture(t); await f.run('enable'); const before = f.s.setters.length;
  f.s.ready = false; await assert.rejects(f.run('recover')); assert.equal(f.s.guard, true);
  f.s.ready = true; f.s.port++; await assert.rejects(f.run('recover')); assert.equal(f.s.setters.length, before);
  await f.run('disable'); assert.equal(f.s.guard, false);
});
test('coupled child-journal loss is not treated as permission to create another link', async (t) => {
  const f = await fixture(t); await f.run('enable'); const before = structuredClone(f.s.current);
  await rm(join(f.directory, 'link', 'journal.json'));
  await assert.rejects(f.run('recover')); assert.deepEqual(f.s.current, before); assert.equal(f.s.guard, true);
  assert.ok(await readFile(join(f.directory, 'journal.json')));
});
test('coupled backend refuses host before mutation', async () => {
  await assert.rejects(createCoupledBackend({}), /namespace|launcher|provenance/);
});
for (const point of ['apply:DNSEx:intent:file-synced', 'apply:DNSEx:ack:renamed', 'restore-intent:file-synced',
  'restore:DNSEx:intent:file-synced', 'restore:DNSEx:ack:renamed', 'release-intent:renamed'])
  test(`coupled storage boundary ${point} resumes durable direction`, async (t) => {
    const f = await fixture(t), restoring = !point.startsWith('apply:'); if (restoring) await f.run('enable');
    await assert.rejects(f.run(restoring ? 'disable' : 'enable', async (p) => { if (p === point) throw new Error('crash'); }), /crash/);
    const result = await f.run('recover');
    const applied = !restoring || point === 'restore-intent:file-synced'; assert.equal(result.status, applied ? 'active' : 'released');
    if (applied) await f.run('disable'); assert.equal(f.s.current, null); assert.equal(f.s.guard, false);
  });
test('coupled journal/evidence validation rejects missing gates and unreachable states', async (t) => {
  const f = await fixture(t); await f.run('enable'); const r = await readCoupledJournal(f.directory);
  for (const patch of [{ level: 8 }, { level: -1 }, { pending: true }, { phase: 'released' }, { original: null },
    { extra: true }, { schema: 2 }, { name: 'eth0' }, { port: 53 }]) assert.throws(() => validateCoupledJournal({ ...r, ...patch }));
  const evidence = { status: 'passed', points: [...COUPLED_CRASH_POINTS], controllerSigkills: COUPLED_CRASH_POINTS.length + 1,
    lockConflicts: 1, refused: ['missing-journal', 'corrupt-journal', 'foreign-domains', 'foreign-address', 'exit-down', 'stale-boot'],
    remainingOwnedLinks: 0, dnsSettingsCoupled: true, rebootTested: false, baselineQueriesDuringProtection: 0 };
  assertCoupledEvidence(evidence);
  for (const key of Object.keys(evidence)) assert.throws(() => assertCoupledEvidence({ ...evidence, [key]: null }));
});
