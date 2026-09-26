/** Actual controller SIGKILL + rtnetlink, inside the existing private networkd lab. */
import assert from 'node:assert/strict';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { controller } from './dns-lifecycle-crash-lab.mjs';
import { createOwnedLinkBackend } from './dns-owned-link-backend.mjs';
import { readOwnedLinkJournal, writeOwnedLinkJournal } from './dns-owned-link-journal.mjs';
import { resolvedMethod } from './dns-resolved-backend.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { exec } from './browser-lab-driver.mjs';

export const OWNED_LINK_CRASH_POINTS = Object.freeze(['prepared', 'create-intent', 'link-created', 'unstamped', 'stamp-intent', 'link-stamped', 'created', 'active',
  'create-intent:file-synced', 'created:renamed', 'delete-intent', 'link-deleted', 'deleted', 'guard-removed', 'released',
  'delete-intent:file-synced', 'deleted:renamed']);
const refusals = ['missing-journal', 'corrupt-journal', 'foreign-alias', 'configured-dns', 'recreated-ifindex', 'stale-boot'];
export function assertOwnedLinkEvidence(report) {
  assert.equal(report.status, 'passed'); assert.equal(report.realRtnetlink, true);
  assert.equal(report.controllerSigkills, OWNED_LINK_CRASH_POINTS.length + 1); assert.equal(report.lockConflicts, 1);
  assert.deepEqual(report.points, OWNED_LINK_CRASH_POINTS); assert.deepEqual(report.refused, refusals);
  assert.equal(report.remainingOwnedLinks, 0); assert.equal(report.dnsSettingsCoupled, false); assert.equal(report.rebootTested, false);
}

export async function runOwnedLinkCrashLab({ directory, bus, setGuard, lookup, hits }) {
  await assertDnsMountNamespace();
  const rawBackend = await createOwnedLinkBackend({ bus, ensureGuard: () => setGuard(true), releaseGuard: () => setGuard(false) });
  let lastBackendError = '';
  const backend = Object.fromEntries(Object.entries(rawBackend).map(([method, fn]) => [method, async (...args) => {
    try { return await fn(...args); } catch (error) { lastBackendError = `${method}: ${error.message}`.slice(0, 2048); throw error; }
  }]));
  let serial = 0, sigkills = 0, lockConflicts = 0;
  const points = [], refused = [], names = new Set();
  const fresh = async () => {
    const path = join(directory, `owned-link-${serial++}`); await mkdir(path, { mode: 0o700 });
    await writeFile(join(path, 'lock'), '', { flag: 'wx', mode: 0o600 }); return path;
  };
  const run = async (path, operation) => {
    lastBackendError = '';
    const r = await controller(path, operation, backend, undefined, 'link').done;
    if (r.code !== 0) {
      const record = await readOwnedLinkJournal(path).catch(() => null);
      const current = record ? await backend.view(record.name).catch(() => null) : null;
      assert.fail(`${operation}: ${r.stderr}; ${lastBackendError}; fixture=${JSON.stringify({ record, current })}`);
    }
    assert.equal(r.signal, null); return r.result;
  };
  const guarded = async () => {
    for (const tool of ['iptables', 'ip6tables']) for (const proto of ['udp', 'tcp'])
      await exec(tool, ['-w', '2', '-C', 'OUTPUT', '-p', proto, '--dport', '53', '-j', 'REJECT']);
  };
  const killAt = async (path, op, point) => {
    const c = controller(path, op, backend, point, 'link');
    try {
      await c.reached;
      if (point === 'link-created') {
        const rival = await controller(path, 'recover', backend, undefined, 'link').done;
        assert.equal(rival.code, 75); assert.equal(rival.result, undefined); lockConflicts++;
      }
    } finally { c.kill(); }
    const r = await c.done; assert.equal(r.signal, 'SIGKILL'); assert.equal(r.result, undefined); sigkills++;
  };
  for (const point of OWNED_LINK_CRASH_POINTS) {
    const path = await fresh(), deleting = /^(delete|link-deleted|guard-removed|released)/.test(point);
    if (deleting) await run(path, 'enable');
    await killAt(path, deleting ? 'disable' : 'enable', point);
    const record = await readOwnedLinkJournal(path); names.add(record.name);
    if (!['guard-removed', 'released'].includes(point)) await guarded();
    if (point === 'link-created') {
      const before = await hits(); await lookup('test', null); assert.deepEqual(await hits(), before);
    }
    const r = await run(path, 'recover'); assert.equal(r.id, record.id);
    const committedDelete = deleting && point !== 'delete-intent:file-synced';
    assert.equal(r.status, committedDelete ? 'released' : 'created');
    if (!committedDelete) await run(path, 'disable');
    assert.equal(await backend.view(record.name), null); assert.equal((await run(path, 'recover')).status, 'released');
    points.push(point);
  }
  const refuse = async (name, path, linkName) => {
    const before = linkName ? await backend.view(linkName) : null;
    const content = await readFile(join(path, 'journal.json')).catch(() => null);
    const r = await controller(path, 'recover', backend, undefined, 'link').done;
    assert.equal(r.code, 2); assert.equal(r.result, undefined); await guarded();
    if (linkName) assert.deepEqual(await backend.view(linkName), before);
    assert.deepEqual(await readFile(join(path, 'journal.json')).catch(() => null), content); refused.push(name);
  };
  const missing = await fresh(); await killAt(missing, 'enable', 'guard-installed'); await refuse('missing-journal', missing);
  const corrupt = await fresh(); const made = await run(corrupt, 'enable'); names.add(made.name);
  const saved = await readOwnedLinkJournal(corrupt); await writeFile(join(corrupt, 'journal.json'), '{broken');
  await refuse('corrupt-journal', corrupt, made.name); await writeOwnedLinkJournal(corrupt, saved); await run(corrupt, 'disable');
  const foreign = await fresh(), f = await run(foreign, 'enable'); names.add(f.name);
  const original = await backend.view(f.name);
  await exec('ip', ['link', 'set', 'dev', f.name, 'alias', 'foreign-fixture']);
  await refuse('foreign-alias', foreign, f.name);
  await exec('ip', ['link', 'set', 'dev', f.name, 'alias', original.alias]); await run(foreign, 'disable');
  const configured = await fresh(), d = await run(configured, 'enable'); names.add(d.name);
  const ro = await bus.owner();
  await bus.set(ro, resolvedMethod('DNSEx', [[2, [127, 0, 0, 55], 0, '']], d.ifindex));
  await refuse('configured-dns', configured, d.name);
  await bus.set(ro, resolvedMethod('DNSEx', [], d.ifindex)); await run(configured, 'disable');
  const replaced = await fresh(), r = await run(replaced, 'enable'); names.add(r.name);
  const before = await backend.view(r.name), ctx = await backend.context();
  await backend.remove(ctx, before);
  const { ifindex, dns, ...spec } = before; await backend.create(ctx, { ...spec, alias: '' });
  await backend.stamp(ctx, await backend.view(r.name), spec.alias);
  const replacement = await backend.view(r.name); assert.notEqual(replacement.ifindex, ifindex);
  await refuse('recreated-ifindex', replaced, r.name);
  // Only the lab owner explicitly removes its replacement fixture. Recovery refused it.
  await backend.remove(ctx, replacement);
  const stale = await fresh(), s = await run(stale, 'enable'); names.add(s.name);
  const valid = await readOwnedLinkJournal(stale), bad = structuredClone(valid);
  bad.context.bootId = '00000000-0000-0000-0000-000000000000'; await writeOwnedLinkJournal(stale, bad);
  await refuse('stale-boot', stale, s.name); await writeOwnedLinkJournal(stale, valid); await run(stale, 'disable');
  await setGuard(false); for (const tcp of [false, true]) await lookup('test', '203.0.113.8', tcp);
  for (const name of names) assert.equal(await backend.view(name), null);
  const report = { status: 'passed', realRtnetlink: true, controllerSigkills: sigkills, lockConflicts, points, refused,
    remainingOwnedLinks: 0, dnsSettingsCoupled: false, rebootTested: false };
  assertOwnedLinkEvidence(report); return report;
}
