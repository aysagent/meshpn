import assert from 'node:assert/strict';
import { usbSoakInitialChecks, usbTrafficChecks, usbReadyChecks } from './usb-e2e-evidence.mjs';

export const soakLabels = () => ['baseline', ...[1, 2, 3].flatMap(c => ['exit-blackhole', 'carrier-dhcp'].map(s => `${c}-${s}-recovered`))];
const receiver = label => ['http', 'raw', 'dns', 'long TCP'].map(k => `${label} ${k} receiver audit`);
const stable = label => [`${label} long TCP survives healthy minute`, `${label} process and protection identities unchanged`,
  `${label} SSH 22`, `${label} SSH 2222`, ...receiver(label), `${label} no rule or journal accumulation`, `${label} bounded process resources`];
export const usbSoakChecks = () => [...usbSoakInitialChecks(), ...stable('baseline'),
  ...[1, 2, 3].flatMap(c => ['exit-blackhole', 'carrier-dhcp'].flatMap(s => {
    const label = `${c}-${s}`;
    return [...(s === 'carrier-dhcp' ? [`${label} bypass withdrawn`] : []), ...usbTrafficChecks(false),
      `${label} SSH during outage`, `${label} monitor sees outage`, ...receiver(label),
      ...(s === 'carrier-dhcp' ? [`${label} new DHCP address`] : []), ...usbReadyChecks,
      `${label} exit bypass repaired`, ...stable(label + '-recovered')];
  })), ...usbTrafficChecks(true), ...receiver('final'), 'soak workers exit cleanly', 'soak final fresh traffic succeeds'];

export function assertUsbSoakEvidence(r) {
  assert.equal(r.scenario, 'usb-soak'); assert.equal(r.nic, 'none'); assert.equal(r.hostSharedFilesystem, false);
  for (const k of ['realTls', 'realTun', 'persistentInstalledFiles']) assert.equal(r[k], true);
  assert.equal(r.boots.length, 1); const b = r.boots[0];
  assert.equal(b.phase, 0); assert.equal(b.code, 0); assert.equal(b.synced, true); assert.equal(b.unmounted, true);
  assert.equal(b.powerDown, true); assert.equal(b.kernelRestart, false);
  assert.deepEqual(b.events[0], { event: 'prepared', phase: 0, restored: false, uplinkDown: true });
  const types = ['prepared', 'check', 'lifecycle-ready', 'soak-fault', 'stable', 'resources', 'dhcp', 'soak-completed', 'completed', 'quiescent-memory',
    ...(r.nativeDiagnostics ? ['socket-sample', 'allocator-trim'] : [])];
  assert.ok(b.events.every(e => e.phase === 0 && types.includes(e.event)));
  for (const type of ['prepared', 'lifecycle-ready', 'soak-completed', 'completed']) assert.equal(b.events.filter(e => e.event === type).length, 1);
  assert.deepEqual(b.events.filter(e => e.event === 'check').map(e => e.name), usbSoakChecks());
  const faults = b.events.filter(e => e.event === 'soak-fault');
  assert.deepEqual(faults.map(e => [e.cycle, e.scenario, e.action]), [1, 2, 3].flatMap(c => ['exit-blackhole', 'carrier-dhcp'].flatMap(s => ['begin', 'restore', 'recovered'].map(a => [c, s, a]))));
  for (const f of faults) {
    if (f.action === 'restore') assert.ok(Number.isFinite(f.elapsedMs) && f.elapsedMs >= 120000);
    if (f.action === 'recovered') assert.ok(Number.isFinite(f.recoveryMs) && f.recoveryMs >= 0 && f.recoveryMs <= 210000);
  }
  assert.deepEqual(b.events.filter(e => e.event === 'dhcp').map(e => [e.cycle, e.address]), [1, 2, 3].map(c => [c, `192.168.1.${10 + c}`]));
  const intervals = b.events.filter(e => e.event === 'stable'), resources = b.events.filter(e => e.event === 'resources');
  for (const rows of [intervals, resources]) assert.deepEqual(rows.map(e => e.label), soakLabels());
  for (const e of intervals) assert.ok(Number.isFinite(e.elapsedMs) && e.elapsedMs >= 60000 && Number.isInteger(e.samples) && e.samples >= 50);
  const base = resources[0]; assert.match(base.rulesHash, /^[0-9a-f]{64}$/);
  for (const e of resources) {
    for (const k of ['rssKiB', 'fds', 'threads', 'ruleLines', 'ownedRoutes', 'conntrackCount']) assert.ok(Number.isInteger(e[k]) && e[k] >= 0);
    assert.ok(e.rssKiB > 0 && e.fds > 0 && e.threads > 0);
    assert.deepEqual([e.rulesHash, e.ruleLines, e.ownedRoutes, e.journalStage], [base.rulesHash, base.ruleLines, base.ownedRoutes, 'active']);
    assert.ok(e.rssKiB <= base.rssKiB + 65536 && e.fds <= base.fds + 16 && e.threads <= base.threads + 2);
  }
  const done = b.events.find(e => e.event === 'soak-completed');
  assert.equal(done.cycles, 3); assert.ok(Number.isFinite(done.elapsedMs) && done.elapsedMs >= 1140000);
  assert.ok(Number.isInteger(done.monitorSamples) && done.monitorSamples > 100 && Number.isInteger(done.longSamples) && done.longSamples >= 350);
  const end = b.events.at(-1); assert.equal(end.event, 'completed'); assert.equal(end.soak, true); assert.equal(end.faultScenarios, true);
  if (r.memoryInstrumentation) {
    assert.equal(r.memoryInstrumentation.labOnly, true);
    assert.equal(r.memoryInstrumentation.forcedGcAfterWorkloadOnly, true);
    for (const k of ['originalSha256', 'instrumentedSha256']) assert.match(r.memoryInstrumentation[k], /^[0-9a-f]{64}$/);
    const quiet = b.events.filter(e => e.event === 'quiescent-memory');
    assert.deepEqual(quiet.map(e => e.quietSeconds), [0, 60, 120, 180]);
    const memories = [...resources, ...quiet].map(e => e.nodeMemory);
    for (const m of memories) {
      assert.equal(m.pid, memories[0].pid);
      for (const k of ['rss', 'heapTotal', 'heapUsed', 'external', 'arrayBuffers', 'monotonicMs']) assert.ok(Number.isFinite(m[k]) && m[k] >= 0);
      assert.ok(Array.isArray(m.handles));
    }
    assert.equal(quiet.at(-1).nodeMemory.forcedGc, true);
    for (let i = 1; i < quiet.length; i++) assert.ok(quiet[i].nodeMemory.monotonicMs - quiet[i - 1].nodeMemory.monotonicMs >= 59000);
  }
  if (r.nativeDiagnostics) {
    assert.equal(r.nativeDiagnostics.labOnly, true); assert.equal(r.nativeDiagnostics.trimAfterQuietOnly, true);
    for (const k of ['originalSha256', 'instrumentedSha256', 'addonSha256']) assert.match(r.nativeDiagnostics[k], /^[0-9a-f]{64}$/);
    const trim = b.events.filter(e => e.event === 'allocator-trim'); assert.equal(trim.length, 1);
    const quiet = b.events.filter(e => e.event === 'quiescent-memory'); assert.equal(quiet.length, 4);
    assert.ok(b.events.indexOf(quiet[0]) > b.events.indexOf(resources.at(-1)));
    assert.ok(b.events.indexOf(trim[0]) > b.events.indexOf(quiet.at(-1)));
    assert.ok(b.events.indexOf(trim[0]) < b.events.indexOf(done));
    assert.ok(trim[0].nodeMemory.monotonicMs > quiet.at(-1).nodeMemory.monotonicMs);
    assert.equal(trim[0].nodeMemory.forcedGc, false);
    assert.ok(Number.isInteger(trim[0].fds) && trim[0].fds > 0);
    let previous;
    for (const e of [...resources, ...quiet, trim[0]]) {
      const n = e.nodeMemory.nativeMemory;
      for (const k of ['allocations', 'frees', 'inUse', 'peakInUse', 'pool', 'backingBytes', 'externalCreated', 'externalFinalized', 'arena', 'uordblks', 'fordblks', 'hblkhd', 'keepcost']) assert.ok(Number.isSafeInteger(n[k]) && n[k] >= 0);
      assert.equal(n.allocations - n.frees, n.inUse + n.pool);
      assert.equal(n.backingBytes, (n.inUse + n.pool) * 65535);
      assert.ok(n.pool <= 64 && n.inUse <= n.peakInUse && n.externalFinalized <= n.externalCreated);
      assert.equal(e.nodeMemory.pid, resources[0].nodeMemory.pid);
      assert.ok(e === trim[0] ? [0, 1].includes(n.trimmed) : n.trimmed === -1);
      if (previous) for (const k of ['allocations', 'frees', 'peakInUse', 'externalCreated', 'externalFinalized']) assert.ok(n[k] >= previous[k]);
      previous = n;
    }
    const sockets = b.events.filter(e => e.event === 'socket-sample'); assert.ok(sockets.length >= 100);
    for (let i = 0; i < sockets.length; i++) {
      assert.equal(sockets[i].sequence, i); assert.ok(Number.isFinite(sockets[i].observedMonotonicMs));
      assert.equal(typeof sockets[i].host, 'string'); assert.equal(typeof sockets[i].exit, 'string');
      if (i) assert.ok(sockets[i].observedMonotonicMs > sockets[i - 1].observedMonotonicMs);
    }
    assert.ok(sockets.some(e => e.host.includes('ESTAB') && e.exit.includes('ESTAB')));
    for (const f of faults) assert.ok(Number.isFinite(f.observedMonotonicMs));
    for (const f of faults.filter(f => f.action === 'restore')) {
      const recovered = faults.find(e => e.cycle === f.cycle && e.scenario === f.scenario && e.action === 'recovered');
      assert.ok(sockets.some(e => e.observedMonotonicMs >= f.observedMonotonicMs && e.observedMonotonicMs <= recovered.observedMonotonicMs));
    }
  }
  assert.equal(end.usbDnsPolicy, 'cvks4-usb-tunnel-only'); assert.equal(end.bootId, b.bootId);
  assert.match(b.bootId, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
}
