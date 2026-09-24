import assert from 'node:assert/strict';
import { mkdir, writeFile, readlink, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { controller } from './dns-lifecycle-crash-lab.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { createResolvedJournalBackend, resolvedMethod } from './dns-resolved-backend.mjs';
import { RESOLVED_PROPERTIES, readResolvedJournal, writeResolvedJournal } from './dns-resolved-journal.mjs';
import { exec } from './browser-lab-driver.mjs';

export async function runResolvedCrashLab({ directory, bus, ifindex, identity, setGuard, probe, port, lookup, hits, lab, restartDaemon }) {
  await assertDnsMountNamespace();
  const scope = {};
  for (const name of ['net', 'mnt', 'pid']) scope[name] = await readlink(`/proc/self/ns/${name}`);
  const backend = createResolvedJournalBackend({ bus, ifindex, identity, scope,
    ensureGuard: () => setGuard(true), removeGuard: () => setGuard(false), probe, port });
  // Baseline differs in all three properties, so each setter is exercised (including DefaultRoute).
  // resolved canonicalizes the default DNS port to 0 in DNSEx read-back.
  const baseline = { DNSEx: [[2, [127, 0, 0, 55], 0, '']], Domains: [['baseline.test', false]], DefaultRoute: false };
  const cases = [], refused = []; let serial = 0, sigkills = 0, lockConflicts = 0;
  const query = (label, expected, tcp = false) => lookup(label, expected, tcp, 4, 'baseline.test');
  const run = async (path, operation, custom = backend) => {
    const result = await controller(path, operation, custom, undefined, 'resolved').done;
    assert.equal(result.code, 0, result.stderr); assert.equal(result.signal, null); return result.result;
  };
  const reset = async () => {
    await setGuard(true); const owner = await bus.owner();
    for (const property of RESOLVED_PROPERTIES) await bus.set(owner, resolvedMethod(property, baseline[property], ifindex));
    await setGuard(false);
    const path = join(directory, `resolved-journal-${serial++}`); await mkdir(path, { mode: 0o700 });
    await writeFile(join(path, 'lock'), '', { flag: 'wx', mode: 0o600 }); return path;
  };
  const guardPresent = async () => {
    for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
      await exec(tool, ['-w', '2', '-C', 'OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT']);
    }
  };
  async function killAt(path, operation, point, lockTest = false) {
    const child = controller(path, operation, backend, point, 'resolved');
    try {
      await child.reached;
      if (lockTest) {
        const second = await controller(path, 'recover', backend, undefined, 'resolved').done;
        assert.equal(second.code, 75); assert.equal(second.result, undefined); lockConflicts++;
      }
    } finally { child.kill(); }
    const death = await child.done; assert.equal(death.signal, 'SIGKILL'); assert.equal(death.result, undefined); sigkills++;
  }
  const points = ['prepared'];
  for (const direction of ['apply', 'restore']) for (const property of RESOLVED_PROPERTIES) {
    for (const boundary of ['intent', 'set', 'ack']) points.push(`${direction}:${property}:${boundary}`);
  }
  points.push('apply:DNSEx:intent:file-synced', 'apply:DNSEx:ack:renamed',
    'restore:DNSEx:intent:file-synced', 'restore:DNSEx:ack:renamed', 'restore-start', 'restore-complete', 'guard-removed', 'released');
  for (const point of points) {
    const path = await reset(), restoring = point.startsWith('restore') || ['guard-removed', 'released'].includes(point);
    await query(`resolved-crash-${point}-baseline`, '203.0.113.8');
    if (restoring) await run(path, 'enable');
    await killAt(path, restoring ? 'disable' : 'enable', point, point === 'apply:DNSEx:set');
    const record = await readResolvedJournal(path), before = hits();
    const current = (await backend.view()).settings;
    const unguarded = ['guard-removed', 'released'].includes(point);
    if (!unguarded) await guardPresent();
    // baseline.test is routed by both the baseline domain and the managed root route.
    const managedRoute = current.DNSEx[0][2] === port;
    if (!unguarded) {
      await query(`resolved-crash-${point}-before`, managedRoute ? '192.0.2.123' : null);
      assert.equal(hits(), before);
    } else await query(`resolved-crash-${point}-before`, '203.0.113.8');
    const result = await run(path, 'recover'); assert.equal(result.id, record.id);
    assert.equal(result.status, restoring ? 'released' : 'active');
    if (!restoring) {
      await query(`resolved-crash-${point}-after`, '192.0.2.123', true); assert.equal(hits(), before);
      await run(path, 'disable');
    }
    assert.deepEqual((await backend.view()).settings, baseline);
    await query(`resolved-crash-${point}-restored`, '203.0.113.8', true);
    cases.push({ point, recovered: result.status });
  }
  async function refuse(name, path, custom = backend) {
    const current = await backend.view(), contents = await readFile(join(path, 'journal.json')).catch(() => null), before = hits();
    const result = await controller(path, 'recover', custom, undefined, 'resolved').done;
    assert.equal(result.code, 2); assert.equal(result.result, undefined); await guardPresent();
    assert.deepEqual(await backend.view(), current); assert.deepEqual(await readFile(join(path, 'journal.json')).catch(() => null), contents);
    const route = current.settings.DefaultRoute || current.settings.Domains.some(([domain]) => ['.', 'baseline.test'].includes(domain));
    const answer = name !== 'exit-down' && current.settings.DNSEx[0][2] === port && route ? '192.0.2.123' : null;
    await query(`resolved-refused-${name}`, answer);
    assert.equal(hits(), before); refused.push(name);
  }
  const missing = await reset(); await killAt(missing, 'enable', 'guard-installed'); await refuse('missing', missing);
  const corrupt = await reset(); await run(corrupt, 'enable'); await writeFile(join(corrupt, 'journal.json'), '{broken'); await refuse('corrupt', corrupt);
  const conflict = await reset(); await killAt(conflict, 'enable', 'apply:DNSEx:set');
  await bus.set(await bus.owner(), resolvedMethod('Domains', [['foreign.test', true]], ifindex)); await refuse('foreign-pending-state', conflict);
  const stale = await reset(); await run(stale, 'enable'); const staleRecord = await readResolvedJournal(stale);
  staleRecord.context.scope.mnt = 'mnt:[0]'; await writeResolvedJournal(stale, staleRecord); await refuse('stale-scope', stale);
  const newBus = await reset(); await run(newBus, 'enable'); const busRecord = await readResolvedJournal(newBus);
  busRecord.context.busId = '0'.repeat(32); await writeResolvedJournal(newBus, busRecord); await refuse('bus-id-mismatch', newBus);
  const outage = await reset(); await killAt(outage, 'enable', 'apply:DNSEx:set'); await lab.stopExit();
  try { await refuse('exit-down', outage); } finally { await lab.restartExit(); }
  await run(outage, 'recover'); await run(outage, 'disable');
  const changedOwner = await reset(); await run(changedOwner, 'enable'); await restartDaemon(); await refuse('daemon-owner-changed', changedOwner);
  const partialDisable = await reset(); await killAt(partialDisable, 'enable', 'apply:Domains:set');
  const originalId = (await readResolvedJournal(partialDisable)).id;
  const disabled = await run(partialDisable, 'disable'); assert.equal(disabled.id, originalId);
  assert.ok(isDeepStrictEqual((await backend.view()).settings, baseline));
  await setGuard(false);
  return { status: 'passed', controllerSigkills: sigkills, lockConflicts, cases, refused,
    partialApplyDisabled: true, journalRecoveryTested: true, rebootTested: false, adapterSigkillTested: false };
}
