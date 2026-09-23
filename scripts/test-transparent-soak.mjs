import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { labSessionStats } from './lib/lab-session-stats.mjs';
import { soakOptions, assertIdle, assertResources, memoryTrend } from './lib/transparent-soak.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';
import { child } from './lib/browser-lab-driver.mjs';

test('soak has fixed finite duration and concurrency defaults', () => {
  assert.deepEqual(soakOptions([]), { seconds: 300, concurrency: 4 });
  assert.deepEqual(soakOptions(['--seconds=3600', '--concurrency=12']), { seconds: 3600, concurrency: 12 });
});
for (const option of ['--seconds=0', '--seconds=3601', '--seconds=Infinity', '--seconds=1.5', '--seconds=01',
  '--concurrency=1', '--concurrency=13', '--report=', '--target=example.com']) {
  test(`soak rejects ${option}`, () => assert.throws(() => soakOptions([option])));
}
test('duplicate soak options fail', () => assert.throws(() => soakOptions(['--seconds=1', '--seconds=2'])));

const labIdle = { sockets: 0, heldResponses: 0, h2Sessions: 0, pendingClients: 0, relaySessions: 0, relayTimers: 0, cleanupFailures: 0 };
const proxyIdle = { clients: 0, upstreams: 0, headerTimers: 0, relaySessions: 0, relayTimers: 0, cleanupFailures: 0 };
test('every owned resource counter must drain, including closed-session cleanup failures', () => {
  assertIdle(labIdle, proxyIdle);
  for (const key of Object.keys(labIdle)) assert.throws(() => assertIdle({ ...labIdle, [key]: 1 }, proxyIdle));
  for (const key of Object.keys(proxyIdle)) assert.throws(() => assertIdle(labIdle, { ...proxyIdle, [key]: 1 }));
});
test('FD and child-process growth fail; memory growth alone is not called a leak', () => {
  const base = { children: 0, fds: 24, memory: { rss: 100 * 1048576 } };
  assertResources({ ...base, memory: { rss: 200 * 1048576 } }, base);
  for (const current of [{ ...base, fds: 25 }, { ...base, children: 1 }, { ...base, memory: { rss: 513 * 1048576 } }]) {
    assert.throws(() => assertResources(current, base));
  }
});
for (const leak of [false, true]) test(`session tracker releases closed handles and detects residue=${leak}`, async () => {
  const tracker = labSessionStats(); let close;
  const session = { sockets: new Set([1]), timers: new Set([1]), closed: new Promise((resolve) => { close = resolve; }) };
  tracker.track(null); tracker.track(session);
  assert.deepEqual(tracker.stats(), { relaySessions: 1, relayTimers: 1, cleanupFailures: 0 });
  session.sockets.clear(); if (!leak) session.timers.clear(); close(); await session.closed;
  assert.deepEqual(tracker.stats(), { relaySessions: 0, relayTimers: 0, cleanupFailures: Number(leak) });
});
test('memory regression reports sampled slope and delta without forced GC', () => {
  const samples = [0, 60_000, 120_000].map((elapsedMs, i) => ({ elapsedMs,
    resources: { memory: Object.fromEntries(['rss', 'heapUsed', 'external', 'arrayBuffers'].map((key) => [key, 100 + i * 20])) } }));
  assert.deepEqual(memoryTrend(samples).rss, { first: 100, last: 140, peak: 140, delta: 40, bytesPerMinute: 20 });
  assert.equal(memoryTrend(samples.slice(0, 1)).rss.bytesPerMinute, 0);
  assert.throws(() => memoryTrend([]));
});

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-soak-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return join(directory, 'report.json');
}
test('short supervised soak really exercises all waves and exits with all resources closed', { timeout: 25_000 }, async (t) => {
  const path = await fixture(t);
  const command = await runCommand(process.execPath, ['scripts/transparent-soak.mjs', '--seconds=2', `--report=${path}`],
    { env: cleanEnvironment(process.env), timeoutMs: 20_000 });
  const report = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(command.code, 0, JSON.stringify(report)); assert.equal(report.status, 'passed');
  assert.equal(report.worker.closed, true); assert.equal(report.worker.signal, null); assert.equal(report.worker.reason, null);
  const result = report.result;
  assert.equal(result.warmupWaves, 3); assert.ok(result.waves > 0); assert.ok(result.measuredMs >= 2000);
  const waves = 3 + result.waves;
  assert.deepEqual(result.totals, { echoes: waves * 5, echoBytes: waves * 5 * 65536,
    helloAborts: waves * 4, uploadAborts: waves * 2, slowHellos: waves * 2, slowHeaders: waves * 2 });
  for (const point of result.samples) { assertIdle(point.lab, point.proxy); assert.equal(point.resources.fds, result.baseline.fds); }
  assertIdle(result.final.lab, result.final.proxy);
  assert.equal(result.final.resources.active.TCPServerWrap ?? 0, 0);
  assert.equal(result.final.resources.active.TCPSocketWrap ?? 0, 0);
  assert.equal(result.final.resources.active.Timeout ?? 0, 0);
  assert.equal(result.final.resources.children, 0);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
});
test('SIGTERM stops a running soak and saves aborted instead of success', { timeout: 20_000 }, async (t) => {
  const path = await fixture(t);
  const proc = child(process.execPath, ['scripts/transparent-soak.mjs', '--seconds=300', `--report=${path}`], { env: cleanEnvironment(process.env) });
  t.after(() => proc.stop());
  const closed = new Promise((resolve) => proc.proc.once('close', (code) => resolve(code)));
  await proc.waitFor(/idle FDs=/, 12_000);
  proc.proc.kill('SIGTERM');
  assert.notEqual(await closed, 0);
  const report = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(report.status, 'aborted'); assert.equal(report.worker.closed, true);
  assert.equal(report.worker.reason, 'aborted');
  assert.equal(report.result.status, 'aborted');
  assertIdle(report.result.final.lab, report.result.final.proxy);
  assert.equal(report.result.final.workloadSockets + report.result.final.workloadRequests + report.result.final.workloadTimers, 0);
});
test('soak refuses an existing report without overwriting it', { timeout: 5000 }, async (t) => {
  const path = await fixture(t); await writeFile(path, 'keep');
  const result = await runCommand(process.execPath, ['scripts/transparent-soak.mjs', '--seconds=1', `--report=${path}`]);
  assert.notEqual(result.code, 0); assert.equal(await readFile(path, 'utf8'), 'keep');
});
