// Metadata/process control only. Workload and payload verification are C++.
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
export const benchmarkScope = 'native-combo-single-stream-local-origin-TCG-not-WAN-or-hardware-capacity';
const positive = x => Number.isFinite(x) && x > 0;
export function assertBenchmarkSample(x) {
  assert.equal(x.status, 'passed'); assert.ok(['boring', 'transparent'].includes(x.branch));
  assert.ok(['upload', 'download', 'latency'].includes(x.phase)); assert.equal(x.payloadVerified, true);
  assert.equal(x.streams, 1); assert.ok(positive(x.seconds));
  assert.ok(Number.isInteger(x.clockTicksPerSecond) && x.clockTicksPerSecond > 0);
  if (x.phase === 'latency') {
    assert.equal(x.payloadBytes, 0); assert.equal(x.goodputMbps, 0);
    assert.equal(x.rounds, 100); assert.equal(x.warmupRounds, 5);
    assert.ok(positive(x.latencyMedianMs) && positive(x.latencyP95Ms) && x.latencyP95Ms >= x.latencyMedianMs);
  } else {
    assert.equal(x.payloadBytes, 8 * 1048576); assert.equal(x.rounds, 0); assert.equal(x.warmupRounds, 0);
    assert.equal(x.latencyMedianMs, 0); assert.equal(x.latencyP95Ms, 0);
    assert.ok(positive(x.goodputMbps));
    assert.ok(Math.abs(x.goodputMbps - x.payloadBytes * 8 / x.seconds / 1e6) < 1e-9);
  }
}
export function assertComboBenchmark(r) {
  assert.equal(r.scope, benchmarkScope); assert.equal(r.status, 'passed');
  assert.equal(r.timing, 'application-after-connect-and-TLS-includes-start-and-completion-ack');
  assert.equal(r.cpuTiming, 'whole-fixture-process-window-including-connect-TLS-and-close');
  assert.equal(r.sampleIntervalMs, 100); assert.equal(r.repetitions, 3); assert.equal(r.samples.length, 18);
  let i = 0;
  for (let round=1;round<=3;round++) for (const branch of ['boring', 'transparent']) for (const phase of ['upload','download','latency']) {
    const x = r.samples[i++]; assertBenchmarkSample(x);
    assert.equal(x.repetition, round); assert.equal(x.branch, branch); assert.equal(x.phase, phase);
    assert.ok(positive(x.wallSeconds) && x.wallSeconds >= x.seconds);
    assert.ok(Number.isInteger(x.tunPacketDelta) && (branch === 'boring' ? x.tunPacketDelta > 0 : x.tunPacketDelta === 0));
    assert.deepEqual(Object.keys(x.roles).sort(), ['client','exit']);
    for (const role of Object.values(x.roles)) {
      assert.ok(Number.isInteger(role.cpuTicks) && role.cpuTicks >= 0);
      assert.equal(role.cpuSeconds, role.cpuTicks / x.clockTicksPerSecond);
      assert.ok(Math.abs(role.cpuPercentOneCore - role.cpuSeconds / x.wallSeconds * 100) < 1e-9);
      assert.ok(Number.isInteger(role.peakRssKiB) && role.peakRssKiB > 0 && role.peakRssKiB < 128 * 1024);
    }
  }
}
export async function runComboBenchmark({ snapshot, tunPackets, start, progress = () => {} },
  { now = () => performance.now(), pause = delay } = {}) {
  const samples = [];
  for (let repetition=1;repetition<=3;repetition++) for (const branch of ['boring','transparent']) for (const phase of ['upload','download','latency']) {
    progress({ repetition, branch, phase });
    const before = snapshot(), beforeTun = tunPackets(), began = now();
    const peak = Object.fromEntries(Object.entries(before).map(([name,x])=>[name,x.rss]));
    const job = start(branch, phase);
    let latest;
    do {
      assert.ok(now() - began < 120000, 'combo_benchmark_deadline');
      latest = snapshot();
      for (const [name,x] of Object.entries(latest)) {
        assert.equal(x.start,before[name].start,'benchmark_engine_replaced');
        assert.ok(x.rss > 0 && x.rss < 128*1024, 'benchmark_engine_rss');
        assert.ok(x.ticks >= before[name].ticks); peak[name]=Math.max(peak[name],x.rss);
      }
      if (job.ended) break;
      await pause(100);
    } while (true);
    const wallSeconds = (now()-began)/1000;
    assert.equal(job.code,0,job.error); assert.equal(job.signal ?? null,null);
    const result = JSON.parse(job.output); assertBenchmarkSample(result);
    assert.equal(result.branch,branch); assert.equal(result.phase,phase);
    const roles = Object.fromEntries(Object.entries(latest).map(([name,x]) => {
      const cpuTicks=x.ticks-before[name].ticks, cpuSeconds=cpuTicks/result.clockTicksPerSecond;
      return [name,{cpuTicks,cpuSeconds,cpuPercentOneCore:cpuSeconds/wallSeconds*100,peakRssKiB:peak[name]}];
    }));
    samples.push({...result,repetition,wallSeconds,tunPacketDelta:tunPackets()-beforeTun,roles});
  }
  const report = { status: 'passed', scope: benchmarkScope, repetitions: 3, sampleIntervalMs: 100,
    timing: 'application-after-connect-and-TLS-includes-start-and-completion-ack',
    cpuTiming: 'whole-fixture-process-window-including-connect-TLS-and-close', samples };
  assertComboBenchmark(report); return report;
}
