import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { labSessionStats } from './lib/lab-session-stats.mjs';
import { slowStreamOrigin, STREAM_BYTES, drain } from './lib/lab-slow-streams.mjs';
import { startTransparentTlsLab, requestThroughLab } from './lib/transparent-tls-lab.mjs';
import { soakOptions, assertIdle } from './lib/transparent-soak.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';
import { child } from './lib/browser-lab-driver.mjs';

test('slow-reader is explicit; unknown profiles fail', () => {
  assert.equal(soakOptions(['--profile=slow-reader']).profile, 'slow-reader');
  assert.throws(() => soakOptions(['--profile=anything']));
});
for (const direction of ['forward', 'reverse']) test(`pressure census observes real pump predicates in ${direction} order`, () => {
  const tracker = labSessionStats();
  const a = { isPaused: () => true, readableLength: 65536, readableHighWaterMark: 65536,
    writableLength: 0, writableHighWaterMark: 65536, writableNeedDrain: false };
  const b = { ...a, isPaused: () => false, readableLength: 0, writableLength: 65536, writableNeedDrain: true };
  tracker.track({ state: 'streaming', sockets: new Set(direction === 'forward' ? [a, b] : [b, a]), timers: new Set(), closed: new Promise(() => {}) });
  assert.deepEqual(tracker.pressure(direction), { blocked: 1, readable: 65536, writable: 65536, overBudget: false });
  a.readableLength = 131073; assert.equal(tracker.pressure(direction).overBudget, true);
  assert.throws(() => tracker.pressure('invalid'));
});
for (const event of ['drain', 'error', 'close']) test(`stream drain waiter removes listeners on ${event}`, async () => {
  const stream = new EventEmitter();
  const waiting = drain(stream);
  const check = event === 'drain' ? waiting : assert.rejects(waiting);
  stream.emit(event, new Error('test')); await check;
  assert.equal(stream.listenerCount('drain') + stream.listenerCount('error') + stream.listenerCount('close'), 0);
});
test('stream fixture admits at most two fixed upload streams and clears timers on close', () => {
  const origin = slowStreamOrigin(), replies = [];
  const make = () => {
    const req = Object.assign(new EventEmitter(), { url: '/slow-upload', method: 'POST', httpVersion: '1.1',
      headers: { 'content-length': String(STREAM_BYTES) }, socket: { destroy() {} }, pause() {}, resume() {} });
    const res = Object.assign(new EventEmitter(), { writeHead(code) { replies.push(code); }, end() {} });
    return { req, res };
  };
  const pairs = [make(), make(), make()];
  try {
    for (const { req, res } of pairs) assert.equal(origin.handle(req, res), true);
    assert.deepEqual(replies, [400]); assert.deepEqual(origin.stats(), { slowStreams: 2, slowStreamTimers: 2 });
    origin.resumeUploads();
  } finally { for (const { res } of pairs) res.emit('close'); }
  assert.deepEqual(origin.stats(), { slowStreams: 0, slowStreamTimers: 0 });
});
test('stream endpoints are opt-in and cannot attach to an external origin', async (t) => {
  const lab = await startTransparentTlsLab(); t.after(() => lab.close());
  const response = await requestThroughLab(lab, { path: '/slow-download' });
  assert.equal(JSON.parse(response.body).ok, true);
  assert.equal(lab.stats().slowStreams, 0);
  await assert.rejects(startTransparentTlsLab({ slowStreams: 'yes' }), /slowStreams/);
  await assert.rejects(startTransparentTlsLab({ slowStreams: true, externalOriginPort: 12345 }), /internal lab origin/);
});
test('opt-in H1 fixture rejects H2 requests without illegal connection-specific headers', async (t) => {
  const lab = await startTransparentTlsLab({ slowStreams: true }); t.after(() => lab.close());
  await assert.rejects(requestThroughLab(lab, { httpVersion: '2', path: '/slow-download' }), { code: 'ERR_ASSERTION' });
  assert.equal(lab.stats().slowStreams, 0);
  assert.equal(lab.stats().slowStreamTimers, 0);
});
async function reportPath(t) {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-slow-reader-test-'));
  t.after(() => rm(directory, { recursive: true, force: true })); return join(directory, 'report.json');
}
test('real TLS slow-reader matrix delivers exact streams or runtime deadlines beside healthy traffic', { timeout: 70_000 }, async (t) => {
  const path = await reportPath(t);
  const command = await runCommand(process.execPath, ['scripts/transparent-soak.mjs', '--seconds=1', '--profile=slow-reader', `--report=${path}`],
    { env: cleanEnvironment(process.env), timeoutMs: 65_000 });
  const report = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(command.code, 0, JSON.stringify(report)); assert.equal(report.status, 'passed');
  const result = report.result, waves = result.warmupWaves + result.waves;
  assert.equal(result.profile, 'slow-reader'); assert.equal(result.totals.echoes, waves * 21);
  for (const direction of ['forward', 'reverse']) for (const outcome of ['resume', 'timeout']) {
    const item = result.slowReaders[`${direction}-${outcome}`];
    assert.equal(item.cases, waves); assert.ok(item.pressureSamples > 0);
    assert.ok(item.maxReadable <= 131072); assert.ok(item.maxWritable <= 131072);
    assert.equal(item.bytes, outcome === 'resume' ? waves * STREAM_BYTES : 0);
    assert.equal(item.timeout, outcome === 'timeout' ? 'TLS_RELAY_WRITE_TIMEOUT' : undefined);
  }
  assertIdle(result.final.lab, result.final.proxy);
  assert.equal(report.worker.closed, true); assert.equal(report.worker.code, 0);
});
test('SIGTERM during observed backpressure releases paused origin and worker', { timeout: 20_000 }, async (t) => {
  const path = await reportPath(t);
  const proc = child(process.execPath, ['scripts/transparent-soak.mjs', '--seconds=300', '--profile=slow-reader', `--report=${path}`], { env: cleanEnvironment(process.env) });
  t.after(() => proc.stop());
  const closed = new Promise((resolve) => proc.proc.once('close', resolve));
  await proc.waitFor(/forward-timeout blocked/, 12_000);
  proc.proc.kill('SIGTERM'); await closed;
  const report = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(report.status, 'aborted'); assert.equal(report.worker.reason, 'aborted');
  assert.equal(report.result.status, 'aborted'); assertIdle(report.result.final.lab, report.result.final.proxy);
  assert.equal(report.result.final.workloadSockets + report.result.final.workloadTimers + report.result.final.workloadRequests, 0);
});
