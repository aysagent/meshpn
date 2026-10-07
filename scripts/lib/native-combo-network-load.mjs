// Control/metadata only. Every byte of workload is generated/checked in C++.
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
export const comboLoadSeconds = 180;
export function assertComboNetworkLoad(r) {
  assert.equal(r.requestedSeconds, comboLoadSeconds);
  assert.ok(Number.isFinite(r.seconds) && r.seconds >= comboLoadSeconds && r.seconds < 300);
  assert.ok(Number.isInteger(r.rounds) && r.rounds >= 2);
  assert.equal(r.tcpEchoBytes, r.rounds * 1048576);
  assert.equal(r.tlsEchoBytes, r.rounds * 2 * 1048576);
  assert.equal(r.udpDatagrams, r.rounds * 5); assert.equal(r.dnsQueries, r.rounds * 4);
  assert.equal(r.payloadVerified, true);
  assert.ok(Number.isInteger(r.samples) && r.samples >= 100);
  assert.ok(Number.isInteger(r.tunPacketDelta) && r.tunPacketDelta > 0);
  assert.deepEqual(Object.keys(r.roles).sort(), ['client', 'exit']);
  assert.equal(r.roles.client.txPackets, r.roles.exit.rxPackets);
  assert.equal(r.roles.client.rxPackets, r.roles.exit.txPackets);
  for (const x of Object.values(r.roles)) {
    for (const k of ['baselineRssKiB', 'peakRssKiB', 'baselineFds', 'peakFds', 'idleFds', 'baselineThreads', 'peakThreads', 'idleThreads'])
      assert.ok(Number.isInteger(x[k]) && x[k] > 0, k);
    assert.ok(x.peakRssKiB >= x.baselineRssKiB && x.peakRssKiB < 128 * 1024);
    assert.ok(x.peakRssKiB - x.baselineRssKiB < 64 * 1024);
    assert.ok(x.peakFds >= x.baselineFds && x.peakFds <= x.baselineFds + 64 && x.idleFds <= x.baselineFds);
    assert.ok(x.peakThreads >= x.baselineThreads && x.peakThreads <= x.baselineThreads + 32 && x.idleThreads <= x.baselineThreads);
    assert.ok(Number.isInteger(x.cpuTicks) && x.cpuTicks >= 0);
    assert.equal(x.readyCount, 1); assert.equal(x.generation, 0); assert.equal(x.droppedPackets, 0);
    assert.ok(Number.isInteger(x.txPackets) && x.txPackets > 0);
    assert.ok(Number.isInteger(x.rxPackets) && x.rxPackets > 0);
  }
}
export async function runComboNetworkLoad({ snapshot, tunPackets, startData, startTls, startHostDns, stopEngines },
  { now = () => performance.now(), pause = delay } = {}) {
  const began = now(), beforeTun = tunPackets(), initial = snapshot(), roles = {};
  for (const [name, x] of Object.entries(initial)) roles[name] = {
    baselineRssKiB: x.rss, peakRssKiB: x.rss, baselineFds: x.fds, peakFds: x.fds,
    baselineThreads: x.threads, peakThreads: x.threads,
  };
  let samples = 0, rounds = 0, nextSample = 0;
  const sample = () => {
    const at = now(); assert.ok(at - began < 300000, 'combo_load_deadline');
    if (at < nextSample) return;
    for (const [name, x] of Object.entries(snapshot())) {
      const p = roles[name]; assert.equal(x.start, initial[name].start, 'engine_pid_reused');
      p.peakRssKiB = Math.max(p.peakRssKiB, x.rss); p.peakFds = Math.max(p.peakFds, x.fds);
      p.peakThreads = Math.max(p.peakThreads, x.threads);
      assert.ok(x.rss < 128 * 1024 && x.rss - p.baselineRssKiB < 64 * 1024, 'combo_load_memory');
      assert.ok(x.fds <= p.baselineFds + 64 && x.threads <= p.baselineThreads + 32, 'combo_load_handles');
    }
    samples++; nextSample = at + 500;
  };
  const finish = async jobs => {
    while (jobs.some(j => !j.ended)) { sample(); await pause(100); }
    for (const j of jobs) assert.equal(j.code, 0, j.error);
  };
  do {
    const data = startData(), tls = startTls(); await finish([data, tls]);
    assert.match(data.output, /TCP 1048576 bytes roundtrip PASS/);
    for (const size of [28, 1300, 2000, 8192, 60000]) assert.match(data.output, new RegExp(`UDP ${size} PASS`));
    assert.match(data.output, /DNS UDP PASS/); assert.match(data.output, /DNS TCP PASS/);
    assert.match(tls.output, /native public policy TLS12\/TLS13-HRR PASS/);
    const dns = startHostDns(); await finish([dns]);
    assert.match(dns.output, /DNS UDP PASS/); assert.match(dns.output, /DNS TCP PASS/);
    ++rounds;
  } while (now() - began < comboLoadSeconds * 1000);
  const settle = now() + 10000;
  let final;
  do {
    final = snapshot();
    if (Object.entries(final).every(([name, x]) => x.fds <= initial[name].fds && x.threads <= initial[name].threads)) break;
    assert.ok(now() < settle, 'combo_load_idle_handles'); sample(); await pause(100);
  } while (true);
  const tunPacketDelta = tunPackets() - beforeTun;
  const states = await stopEngines();
  for (const [name, x] of Object.entries(final)) {
    assert.equal(x.start, initial[name].start, 'engine_pid_reused');
    Object.assign(roles[name], { idleFds: x.fds, idleThreads: x.threads, cpuTicks: x.ticks - initial[name].ticks, ...states[name] });
  }
  const result = { requestedSeconds: comboLoadSeconds, seconds: (now() - began) / 1000,
    rounds, samples, tcpEchoBytes: rounds * 1048576, tlsEchoBytes: rounds * 2 * 1048576,
    udpDatagrams: rounds * 5, dnsQueries: rounds * 4, payloadVerified: true, tunPacketDelta, roles };
  assertComboNetworkLoad(result); return result;
}
