/** Coupled DNS + link crash matrix. Parent namespace supervisor survives child SIGKILL. */
import assert from 'node:assert/strict';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { controller } from './dns-lifecycle-crash-lab.mjs';
import { createCoupledBackend } from './dns-coupled-backend.mjs';
import { readCoupledJournal, writeCoupledJournal } from './dns-coupled-journal.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { exec } from './browser-lab-driver.mjs';
import { resolvedMethod } from './dns-resolved-backend.mjs';

export const COUPLED_CRASH_POINTS = Object.freeze([
  'link:link-created', 'link-ready', 'settings-prepared', 'apply:address:set', 'apply:up:set',
  'apply:DNSEx:set', 'apply:Domains:set', 'active', 'restore:Domains:set', 'restore:DNSEx:set',
  'restore:up:set', 'restore:address:set', 'unlink-intent', 'link:link-deleted', 'release-intent', 'guard-removed',
]);
const REFUSALS = ['missing-journal', 'corrupt-journal', 'foreign-domains', 'foreign-address', 'exit-down', 'stale-boot'];
export function assertCoupledEvidence(r) {
  assert.equal(r.status, 'passed'); assert.deepEqual(r.points, COUPLED_CRASH_POINTS);
  assert.equal(r.controllerSigkills, COUPLED_CRASH_POINTS.length + 1); assert.equal(r.lockConflicts, 1);
  assert.deepEqual(r.refused, REFUSALS); assert.equal(r.remainingOwnedLinks, 0);
  assert.equal(r.dnsSettingsCoupled, true); assert.equal(r.rebootTested, false); assert.equal(r.baselineQueriesDuringProtection, 0);
}
export async function runCoupledCrashLab({ directory, bus, setGuard, lookup, hits, lab, probe, cloudSettings }) {
  await assertDnsMountNamespace();
  const raw = await createCoupledBackend({ bus, ensureGuard: () => setGuard(true), releaseGuard: () => setGuard(false), port: lab.adapter.port, probe });
  let errorText = '', serial = 0, sigkills = 0, lockConflicts = 0;
  const backend = Object.fromEntries(Object.entries(raw).map(([k, fn]) => [k, async (...args) => {
    try { return await fn(...args); } catch (e) { errorText = `${k}: ${e.message}`.slice(0, 2048); throw e; }
  }]));
  const points = [], refused = [], names = new Set();
  const fresh = async () => { const path = join(directory, `coupled-${serial++}`); await mkdir(path, { mode: 0o700 });
    await writeFile(join(path, 'lock'), '', { flag: 'wx', mode: 0o600 }); return path; };
  const run = async (path, op) => {
    errorText = ''; const result = await controller(path, op, backend, undefined, 'coupled').done;
    if (result.code !== 0) {
      const record = await readCoupledJournal(path).catch(() => null);
      const current = record ? await backend.view(record.name).catch(() => null) : null;
      assert.fail(`${op}: ${result.stderr} ${errorText} ${JSON.stringify({ record, current })}`);
    }
    assert.equal(result.signal, null); return result.result;
  };
  const guarded = async () => {
    for (const tool of ['iptables', 'ip6tables']) for (const proto of ['udp', 'tcp'])
      await exec(tool, ['-w', '2', '-C', 'OUTPUT', '-p', proto, '--dport', '53', '-j', 'REJECT']);
  };
  const killAt = async (path, op, point) => {
    const c = controller(path, op, backend, point, 'coupled');
    try {
      await c.reached;
      if (point === 'active') {
        const rival = await controller(path, 'recover', backend, undefined, 'coupled').done;
        assert.equal(rival.code, 75); lockConflicts++;
      }
    } finally { c.kill(); }
    const death = await c.done; assert.equal(death.signal, 'SIGKILL'); sigkills++;
  };
  for (const point of COUPLED_CRASH_POINTS) {
    const path = await fresh(), restore = /^(restore:|unlink|link:link-deleted|release|guard-removed)/.test(point);
    if (restore) await run(path, 'enable');
    const before = await hits(); await killAt(path, restore ? 'disable' : 'enable', point);
    const record = await readCoupledJournal(path); names.add(record.name);
    if (point !== 'guard-removed') await guarded();
    if (['apply:address:set', 'restore:DNSEx:set'].includes(point)) await lookup('test', null);
    assert.deepEqual(await hits(), before);
    const r = await run(path, 'recover'); assert.equal(r.id, record.id); assert.equal(r.status, restore ? 'released' : 'active');
    if (!restore) {
      for (const tcp of [false, true]) await lookup('test', '192.0.2.123', tcp);
      const bodies = lab.stats().resolverBodies;
      await lookup('auto.internal', null); assert.equal(lab.stats().resolverBodies, bodies);
      assert.deepEqual(await hits(), before); await cloudSettings(3); await run(path, 'disable');
    }
    assert.equal(await backend.view(record.name), null); await cloudSettings(3);
    await lookup('test', '203.0.113.8'); points.push(point);
  }
  const refuse = async (name, path, linkName) => {
    const before = linkName ? await backend.view(linkName) : null, counts = await hits();
    const bytes = await readFile(join(path, 'journal.json')).catch(() => null);
    const r = await controller(path, 'recover', backend, undefined, 'coupled').done;
    assert.equal(r.code, 2); assert.equal(r.result, undefined); await guarded();
    if (linkName) assert.deepEqual(await backend.view(linkName), before);
    assert.deepEqual(await readFile(join(path, 'journal.json')).catch(() => null), bytes);
    assert.deepEqual(await hits(), counts); refused.push(name);
  };
  const missing = await fresh(); await killAt(missing, 'enable', 'guard-installed'); await refuse('missing-journal', missing);
  const bad = await fresh(), b = await run(bad, 'enable'); names.add(b.name);
  const good = await readCoupledJournal(bad); await writeFile(join(bad, 'journal.json'), '{broken');
  await refuse('corrupt-journal', bad, b.name); await writeCoupledJournal(bad, good); await run(bad, 'disable');
  const foreign = await fresh(), f = await run(foreign, 'enable'); names.add(f.name);
  const state = await backend.view(f.name), owner = await bus.owner();
  await bus.set(owner, resolvedMethod('Domains', [['foreign.test', true]], state.ifindex));
  await refuse('foreign-domains', foreign, f.name);
  await bus.set(owner, resolvedMethod('Domains', state.dns.Domains, state.ifindex)); await run(foreign, 'disable');
  const address = await fresh(), a = await run(address, 'enable'); names.add(a.name);
  await exec('ip', ['addr', 'add', '192.0.2.2/32', 'dev', a.name]); await refuse('foreign-address', address, a.name);
  await exec('ip', ['addr', 'del', '192.0.2.2/32', 'dev', a.name]); await run(address, 'disable');
  const outage = await fresh(), o = await run(outage, 'enable'); names.add(o.name);
  await lab.stopExit();
  try { await refuse('exit-down', outage, o.name); const before = await hits(); await lookup('test', null); assert.deepEqual(await hits(), before);
    await run(outage, 'disable'); // Explicit disable does not require a healthy resolver.
  } finally { await lab.restartExit(); }
  const stale = await fresh(), s = await run(stale, 'enable'); names.add(s.name);
  const valid = await readCoupledJournal(stale), old = structuredClone(valid); old.context.bootId = '00000000-0000-0000-0000-000000000000';
  await writeCoupledJournal(stale, old); await refuse('stale-boot', stale, s.name);
  await writeCoupledJournal(stale, valid); await run(stale, 'disable');
  for (const name of names) assert.equal(await backend.view(name), null);
  for (const tcp of [false, true]) await lookup('test', '203.0.113.8', tcp);
  const report = { status: 'passed', points, controllerSigkills: sigkills, lockConflicts, refused,
    remainingOwnedLinks: 0, dnsSettingsCoupled: true, rebootTested: false, baselineQueriesDuringProtection: 0 };
  assertCoupledEvidence(report); return report;
}
