import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runComboNetworkLoad, assertComboNetworkLoad } from './lib/native-combo-network-load.mjs';
import { comboNetworkChecks, assertComboNetworkEvidence } from './lib/native-combo-network-evidence.mjs';
function fixture(fault) {
  let time = 0, tun = 1, samples = 0, stopCalled = false; const jobs = [];
  const data = 'TCP 1048576 bytes roundtrip PASS\nDNS UDP PASS\nDNS TCP PASS\n' + [28, 1300, 2000, 8192, 60000].map(n => `UDP ${n} PASS`).join('\n');
  const start = output => { const job = { ended: false, code: 0, output, error: 'fixture_failed', end: time + 1000 }; jobs.push(job); return job; };
  const io = {
    snapshot() {
      ++samples; const x = { start: '12', ticks: Math.floor(time / 10), rss: 8000, fds: 8, threads: 3 };
      if (fault === 'pid' && samples > 1) x.start = '13';
      if (fault === 'memory' && samples > 1) x.rss = 131072;
      if (fault === 'fds' && samples > 1) x.fds = 100;
      if (fault === 'threads' && samples > 1) x.threads = 40;
      if (fault === 'idle' && samples > 1) x.fds++;
      return { client: { ...x }, exit: { ...x } };
    },
    tunPackets: () => tun++, startData: () => start(fault === 'payload' ? '' : data),
    startTls: () => { const j = start('native public policy TLS12/TLS13-HRR PASS'); if (fault === 'exit') j.code = 1; return j; },
    startHostDns: () => start('DNS UDP PASS\nDNS TCP PASS'),
    stopEngines: async () => {
      stopCalled = true; const x = { readyCount: fault === 'reconnect' ? 2 : 1, generation: 0, droppedPackets: fault === 'drop' ? 1 : 0, txPackets: 100, rxPackets: 100 };
      return { client: { ...x }, exit: { ...x } };
    },
  };
  const clock = { now: () => time, pause: async ms => { time += ms;
    for (const j of jobs) if (fault !== 'hang' && time >= j.end) j.ended = true;
  } };
  return { io, clock, stopped: () => stopCalled };
}
test('real-TUN load orchestrates concurrent C++ probes with resources, DNS and bounded graceful stop', async () => {
  const saved = JSON.parse(readFileSync(new URL('./fixtures/clean-vpn-native-combo-load-report.json', import.meta.url)));
  assertComboNetworkEvidence(saved.evidence, { load: true });
  assertComboNetworkEvidence(saved.priorRun.evidence, { load: true });
  const f = fixture(); const r = await runComboNetworkLoad(f.io, f.clock);
  assertComboNetworkLoad(r); assert.equal(r.rounds, 90); assert.equal(r.seconds, 180); assert.equal(f.stopped(), true);
  const checks = [...comboNetworkChecks]; checks.splice(7, 0, 'SUSTAINED_MIXED_LOAD', 'LOAD_CLEAN_RESTART');
  const e = { status: 'passed', checks, load: r, realTun: true, packetOwner: 'C++', roles: ['client', 'exit'], namespaces: 5,
    positiveCapturePackets: 20, directPacketsAfterGuard: 0, captureKernelDropped: 0,
    scope: 'runtime-static-routes-selected-IPv4-origin-not-installer-systemd-reboot-all-egress-or-benchmark' };
  assertComboNetworkEvidence(e, { load: true }); assert.throws(() => assertComboNetworkEvidence(e));
  const missing = { ...e }; delete missing.load; assert.throws(() => assertComboNetworkEvidence(missing, { load: true }));
  for (const mutate of [x => { x.seconds = 179; }, x => { x.rounds = 0; }, x => { x.payloadVerified = false; },
    x => { x.samples = 99; }, x => { x.tcpEchoBytes++; }, x => { x.tunPacketDelta = 0; },
    x => { x.roles.exit.cpuTicks = NaN; }, x => { x.roles.exit.generation = 1; },
    x => { x.roles.exit.rxPackets++; }, x => { x.roles.client.peakFds = 1; }]) {
    const bad = structuredClone(r); mutate(bad); assert.throws(() => assertComboNetworkLoad(bad));
  }
});
for (const fault of ['pid', 'memory', 'fds', 'threads', 'idle', 'payload', 'exit', 'hang', 'drop', 'reconnect'])
  test(`real-TUN load refuses ${fault} without a false pass`, async () => {
    const f = fixture(fault); await assert.rejects(runComboNetworkLoad(f.io, f.clock));
  });
