import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ownedLinkTransaction, readOwnedLinkJournal, writeOwnedLinkJournal, validateOwnedLinkJournal } from './lib/dns-owned-link-journal.mjs';
import { createOwnedLinkBackend } from './lib/dns-owned-link-backend.mjs';
import { assertOwnedLinkEvidence, OWNED_LINK_CRASH_POINTS } from './lib/dns-owned-link-crash-lab.mjs';

const scope = { net: 'net:[1]', mnt: 'mnt:[2]', pid: 'pid:[3]' };
const context = () => ({ scope: structuredClone(scope), bootId: '12345678-1234-1234-1234-123456789abc', busId: 'a'.repeat(32), owner: ':1.2' });
async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-owned-link-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const state = { current: null, guard: false, created: 0, deleted: 0, context: context() };
  const backend = {
    context: async () => structuredClone(state.context),
    ensureGuard: async () => { state.guard = true; },
    view: async () => structuredClone(state.current),
    async create(expected, spec) {
      assert.equal(state.guard, true); assert.equal(state.current, null); assert.deepEqual(expected, state.context);
      state.current = { ...structuredClone(spec), ifindex: 10 + state.created++, dns: { DNSEx: [], Domains: [], DefaultRoute: true } };
    },
    async remove(expected, current) {
      assert.equal(state.guard, true); assert.deepEqual(expected, state.context); assert.deepEqual(state.current, current);
      state.current = null; state.deleted++;
    },
    async stamp(expected, current, alias) {
      assert.deepEqual(expected, state.context); assert.deepEqual(state.current, current); assert.equal(current.alias, '');
      state.current.alias = alias;
    },
    async releaseGuard(expected) { assert.deepEqual(expected, state.context); assert.equal(state.current, null); state.guard = false; },
  };
  const run = (operation, checkpoint) => ownedLinkTransaction({ directory, operation, scope, backend, checkpoint });
  return { directory, state, run, backend };
}
const points = ['prepared', 'create-intent', 'link-created', 'unstamped', 'stamp-intent', 'link-stamped', 'created', 'active',
  'create-intent:file-synced', 'created:renamed', 'delete-intent', 'link-deleted', 'deleted', 'guard-removed', 'released',
  'delete-intent:file-synced', 'deleted:renamed'];
for (const point of points) test(`owned link write-ahead recovery at ${point}`, async (t) => {
  const f = await fixture(t), deleting = /^(delete|link-deleted|guard-removed|released)/.test(point);
  if (deleting) await f.run('enable');
  await assert.rejects(f.run(deleting ? 'disable' : 'enable', async (p) => { if (p === point) throw new Error('simulated crash'); }), /simulated crash/);
  const record = await readOwnedLinkJournal(f.directory);
  const result = await f.run('recover'); assert.equal(result.id, record.id);
  // A crash before rename of the delete intent leaves a durable created state.
  const committedDelete = deleting && point !== 'delete-intent:file-synced';
  assert.equal(result.status, committedDelete ? 'released' : 'created');
  if (!committedDelete) { assert.equal(f.state.guard, true); await f.run('disable'); }
  assert.equal(f.state.current, null); assert.equal(f.state.guard, false);
  assert.equal(f.state.created, 1); assert.equal(f.state.deleted, 1);
  assert.equal((await f.run('recover')).status, 'released'); assert.equal(f.state.deleted, 1);
});
for (const point of ['prepared', 'create-intent']) test(`disable at ${point} durably cancels creation and cannot resurrect on recovery`, async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.run('enable', async (p) => { if (p === point) throw new Error('crash'); }));
  await assert.rejects(f.run('disable', async (p) => { if (p === 'deleted') throw new Error('crash'); }));
  assert.equal((await f.run('recover')).status, 'released');
  assert.equal(f.state.created, 0); assert.equal(f.state.deleted, 0);
});
for (const [name, mutate] of [
  ['alias', (s) => { s.current.alias = 'foreign'; }],
  ['MAC', (s) => { s.current.mac = '02:00:00:00:00:00'; }],
  ['ifindex reuse', (s) => { s.current.ifindex++; }],
  ['up', (s) => { s.current.up = true; }],
  ['address', (s) => { s.current.addresses = ['inet:192.0.2.1/32']; }],
  ['DNS', (s) => { s.current.dns.DNSEx = [[2, [127, 0, 0, 1], 1053, '']]; }],
  ['Domains', (s) => { s.current.dns.Domains = [['.', true]]; }],
  ['missing', (s) => { s.current = null; }],
  ['boot', (s) => { s.context.bootId = '00000000-0000-0000-0000-000000000000'; }],
  ['bus', (s) => { s.context.busId = 'b'.repeat(32); }],
  ['owner', (s) => { s.context.owner = ':1.3'; }],
  ['namespace', (s) => { s.context.scope.net = 'net:[99]'; }],
]) test(`owned link refuses ${name} conflict without mutation, keeping guard`, async (t) => {
  const f = await fixture(t); await f.run('enable'); mutate(f.state);
  const before = structuredClone(f.state.current), record = await readOwnedLinkJournal(f.directory);
  for (const op of ['recover', 'disable']) {
    await assert.rejects(f.run(op)); assert.deepEqual(f.state.current, before);
    assert.deepEqual(await readOwnedLinkJournal(f.directory), record); assert.equal(f.state.guard, true);
    assert.equal(f.state.deleted, 0);
  }
});
test('no create intent means no adoption, and deleted name reuse prevents release', async (t) => {
  const f = await fixture(t); await f.run('enable'); const record = await readOwnedLinkJournal(f.directory);
  for (const stage of ['prepared', 'deleted']) {
    await writeOwnedLinkJournal(f.directory, { ...record, stage, ifindex: stage === 'prepared' ? null : record.ifindex });
    await assert.rejects(f.run('recover')); assert.equal(f.state.guard, true); assert.equal(f.state.deleted, 0);
  }
});
test('missing/corrupt journal and repeated enable are fail-closed', async (t) => {
  const f = await fixture(t); await assert.rejects(f.run('recover')); assert.equal(f.state.guard, true);
  await f.run('enable'); await assert.rejects(f.run('enable')); assert.equal(f.state.created, 1);
  await writeFile(join(f.directory, 'journal.json'), '{broken');
  await assert.rejects(f.run('disable')); assert.equal(f.state.deleted, 0); assert.equal(f.state.guard, true);
});
test('strict link journal rejects extra fields, unreachable stages and unsafe names', async (t) => {
  const f = await fixture(t); await f.run('enable'); const record = await readOwnedLinkJournal(f.directory);
  for (const patch of [{ extra: true }, { stage: 'unknown' }, { name: 'eth0' }, { ifindex: 1 }, { ifindex: null }, { id: '' }, { schema: 2 }])
    assert.throws(() => validateOwnedLinkJournal({ ...record, ...patch }));
});
test('owned link backend refuses host before accessing bus or mutating network', async () => {
  await assert.rejects(createOwnedLinkBackend({}), /namespace|launcher|provenance/);
});
test('owned link real evidence requires all crash points, refusals and explicit coverage limits', () => {
  const evidence = { status: 'passed', realRtnetlink: true, controllerSigkills: OWNED_LINK_CRASH_POINTS.length + 1,
    lockConflicts: 1, points: [...OWNED_LINK_CRASH_POINTS],
    refused: ['missing-journal', 'corrupt-journal', 'foreign-alias', 'configured-dns', 'recreated-ifindex', 'stale-boot'],
    remainingOwnedLinks: 0, dnsSettingsCoupled: false, rebootTested: false };
  assertOwnedLinkEvidence(evidence);
  for (const key of Object.keys(evidence)) assert.throws(() => assertOwnedLinkEvidence({ ...evidence, [key]: null }), key);
  for (const key of ['points', 'refused']) assert.throws(() => assertOwnedLinkEvidence({ ...evidence, [key]: evidence[key].slice(1) }));
});
