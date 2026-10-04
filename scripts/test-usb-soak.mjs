import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { assertUsbSoakEvidence, usbSoakChecks, soakLabels } from './lib/usb-soak-evidence.mjs';
import { runUsbSoak, runLongTcpPeer, startLongTcpOrigin } from './lib/usb-soak-vm.mjs';

const valid = () => {
  const bootId = '00000000-0000-0000-0000-000000000000', phase = 0;
  return { scenario: 'usb-soak', nic: 'none', hostSharedFilesystem: false, realTls: true, realTun: true, persistentInstalledFiles: true,
    boots: [{ phase, bootId, code: 0, synced: true, unmounted: true, powerDown: true, kernelRestart: false, events: [
      { event: 'prepared', phase, restored: false, uplinkDown: true }, { event: 'lifecycle-ready', phase },
      ...usbSoakChecks().map(name => ({ event: 'check', phase, name })),
      ...[1, 2, 3].flatMap(cycle => ['exit-blackhole', 'carrier-dhcp'].flatMap(scenario => ['begin', 'restore', 'recovered'].map(action => ({ event: 'soak-fault', phase, cycle, scenario, action, elapsedMs: 120001, recoveryMs: 1000 })))),
      ...[1, 2, 3].map(cycle => ({ event: 'dhcp', phase, cycle, address: `192.168.1.${10 + cycle}` })),
      ...soakLabels().flatMap(label => [{ event: 'stable', phase, label, samples: 65, elapsedMs: 65000 },
        { event: 'resources', phase, label, rssKiB: 50000, fds: 30, threads: 7, rulesHash: 'a'.repeat(64), ruleLines: 100, ownedRoutes: 6, journalStage: 'active', conntrackCount: 100 }]),
      { event: 'soak-completed', phase, cycles: 3, elapsedMs: 1200000, monitorSamples: 500, longSamples: 500 },
      { event: 'completed', phase, bootId, soak: true, faultScenarios: true, usbDnsPolicy: 'cvks4-usb-tunnel-only' },
    ] }] };
};
test('complete soak evidence accepted', () => assert.doesNotThrow(() => assertUsbSoakEvidence(valid())));
const withMemory = () => {
  const r = valid(); r.memoryInstrumentation = { labOnly: true, forcedGcAfterWorkloadOnly: true, originalSha256: 'a'.repeat(64), instrumentedSha256: 'b'.repeat(64) };
  const memory = (ms, forcedGc = false) => ({ pid: 42, rss: 60000000, heapTotal: 20000000, heapUsed: 12000000,
    external: 1000000, arrayBuffers: 100000, handles: ['Timeout'], monotonicMs: ms, forcedGc });
  for (const e of r.boots[0].events.filter(e => e.event === 'resources')) e.nodeMemory = memory(1000);
  r.boots[0].events.splice(-2, 0, ...[0, 1, 2, 3].map(i => ({ event: 'quiescent-memory', phase: 0, sample: i,
    quietSeconds: i * 60, nodeMemory: memory(2000 + i * 60000, i === 3), fds: 30 })));
  return r;
};
test('soak includes live V8 and post-workload collection evidence', () => assert.doesNotThrow(() => assertUsbSoakEvidence(withMemory())));
for (const [name, change] of Object.entries({
  missingQuiet: r => { r.boots[0].events = r.boots[0].events.filter(e => e.event !== 'quiescent-memory'); },
  noGc: r => { r.boots[0].events.filter(e => e.event === 'quiescent-memory').at(-1).nodeMemory.forcedGc = false; },
  differentPid: r => { r.boots[0].events.find(e => e.event === 'resources').nodeMemory.pid++; },
  invalidHeap: r => { r.boots[0].events.find(e => e.event === 'resources').nodeMemory.heapUsed = NaN; },
  noQuietDelay: r => { r.boots[0].events.filter(e => e.event === 'quiescent-memory')[1].nodeMemory.monotonicMs = 2001; },
})) test('memory evidence rejects ' + name, () => { const r = withMemory(); change(r); assert.throws(() => assertUsbSoakEvidence(r)); });
for (const [name, change] of Object.entries({
  missingCheck: r => r.boots[0].events.splice(2, 1),
  missingCycle: r => { r.boots[0].events = r.boots[0].events.filter(e => e.cycle !== 3); },
  shortOutage: r => { r.boots[0].events.find(e => e.action === 'restore').elapsedMs = 119999; },
  timeout: r => { r.boots[0].events.find(e => e.action === 'recovered').recoveryMs = 300000; },
  unchangedDHCP: r => { r.boots[0].events.find(e => e.event === 'dhcp').address = '192.168.1.10'; },
  noLongTCP: r => { r.boots[0].events.find(e => e.event === 'stable').samples = 1; },
  shortTCP: r => { r.boots[0].events.find(e => e.event === 'stable').elapsedMs = 20000; },
  fdGrowth: r => { r.boots[0].events.filter(e => e.event === 'resources').at(-1).fds += 17; },
  rssGrowth: r => { r.boots[0].events.filter(e => e.event === 'resources').at(-1).rssKiB += 65537; },
  changedRules: r => { r.boots[0].events.filter(e => e.event === 'resources').at(-1).rulesHash = 'b'.repeat(64); },
  fakeNumbers: r => { r.boots[0].events.find(e => e.event === 'resources').rssKiB = NaN; },
  missingShutdown: r => { r.boots[0].powerDown = false; },
  failure: r => { r.boots[0].events.push({ phase: 0, event: 'failed' }); },
  shortSoak: r => { r.boots[0].events.find(e => e.event === 'soak-completed').elapsedMs = 60000; },
})) test('reject incomplete soak: ' + name, () => { const r = valid(); change(r); assert.throws(() => assertUsbSoakEvidence(r)); });
for (const fn of [runUsbSoak, runLongTcpPeer, startLongTcpOrigin]) test(fn.name + ' refuses host before mutations', async () => {
  await assert.rejects(fn({}), /AssertionError/);
});
test('long TCP entry refuses host', () => {
  const r = spawnSync(process.execPath, ['scripts/lib/usb-e2e-vm.mjs', 'long-tcp'], { encoding: 'utf8', timeout: 10000 });
  assert.equal(r.status, 1); assert.match(r.stderr, /AssertionError/);
});
