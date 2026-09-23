import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { h2FlowOrigin, H2_BYTES } from './lib/lab-h2-flow.mjs';
import { assertFlowBlocked, flowBlocked, waitFlowBlocked } from './lib/transparent-h2-flow.mjs';
import { startTransparentTlsLab, requestThroughLab } from './lib/transparent-tls-lab.mjs';
import { soakOptions, assertIdle } from './lib/transparent-soak.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';
import { child } from './lib/browser-lab-driver.mjs';

test('h2-flow is an explicit bounded soak profile', () => assert.equal(soakOptions(['--profile=h2-flow']).profile, 'h2-flow'));
test('flow evidence requires exhausted stream window but available connection window', () => {
  assertFlowBlocked({ localWindow: 0, needDrain: true, connectionWindow: 32768 });
});
test('flow readiness waits for connection credit as well as stream exhaustion', () => {
  const states = [
    { localWindow: 32768, needDrain: true, connectionWindow: 32768 },
    { localWindow: 0, needDrain: true, connectionWindow: 0 },
    { localWindow: 0, needDrain: true, connectionWindow: 32768 },
  ];
  assert.deepEqual(states.map(flowBlocked), [false, false, true]);
  assert.deepEqual(states.find(flowBlocked), states[2]);
  assertFlowBlocked(states.find(flowBlocked));
});
test('flow wait validates the satisfying snapshot without a racy second read', async () => {
  const ready = { localWindow: 0, needDrain: true, connectionWindow: 32768 };
  let reads = 0;
  const observed = await waitFlowBlocked(async (predicate) => assert.equal(predicate(), true), () => {
    reads++; return reads === 1 ? ready : { ...ready, connectionWindow: 0 };
  });
  assert.equal(observed, ready); assert.equal(reads, 1);
});
for (const point of [
  { localWindow: 1, needDrain: true, connectionWindow: 32768 },
  { localWindow: 0, needDrain: false, connectionWindow: 32768 },
  { localWindow: 0, needDrain: true, connectionWindow: 0 },
]) test(`rejects false flow-control evidence ${JSON.stringify(point)}`, () => assert.throws(() => assertFlowBlocked(point)));

test('H2 origin caps admitted slow streams and observes remote CANCEL without retaining handles', () => {
  const flow = h2FlowOrigin(), statuses = [], streams = [];
  for (let i = 0; i < 3; i++) {
    const stream = Object.assign(new EventEmitter(), { id: i * 2 + 1, rstCode: 0,
      state: { localWindowSize: 0 }, writableLength: 0, writableNeedDrain: false, session: { state: { remoteWindowSize: 65535 } } });
    streams.push(stream);
    const req = Object.assign(new EventEmitter(), { stream, httpVersionMajor: 2, method: 'POST', url: '/h2-flow-upload',
      headers: { 'content-length': String(H2_BYTES) }, readableLength: 65535, pause() {}, resume() {} });
    const res = { writeHead(code) { statuses.push(code); }, end() {} };
    flow.handle(req, res);
  }
  try {
    assert.deepEqual(statuses, [400]); assert.equal(flow.stats().h2FlowStreams, 2);
    assert.equal(flow.snapshots().length, 2); flow.resumeUploads();
  } finally {
    for (const stream of streams) { stream.rstCode = 8; stream.emit('close'); }
  }
  assert.deepEqual(flow.stats(), { h2FlowStreams: 0, h2FlowTimers: 0, h2FlowCancels: 2, h2FlowDeadlines: 0 });
  assert.deepEqual(flow.snapshots(), []);
});
test('H2 fixture is opt-in, typed, and incompatible with external origin', async (t) => {
  const lab = await startTransparentTlsLab(); t.after(() => lab.close());
  const response = await requestThroughLab(lab, { path: '/h2-flow-download' });
  assert.equal(JSON.parse(response.body).ok, true);
  assert.equal(lab.stats().h2FlowStreams, 0);
  await assert.rejects(startTransparentTlsLab({ h2Flow: 'yes' }), /h2Flow/);
  await assert.rejects(startTransparentTlsLab({ h2Flow: true, externalOriginPort: 12345 }), /internal lab origin/);
});
test('H2 fixture rejects HTTP/1 requests without starting a stream timer', async (t) => {
  const lab = await startTransparentTlsLab({ h2Flow: true }); t.after(() => lab.close());
  await assert.rejects(requestThroughLab(lab, { path: '/h2-flow-download' }), { code: 'ERR_ASSERTION' });
  assert.equal(lab.stats().h2FlowTimers, 0);
});
async function reportPath(t) {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-h2-flow-test-'));
  t.after(() => rm(directory, { recursive: true, force: true })); return join(directory, 'report.json');
}
test('real H2 flow matrix resumes or resets only stalled stream, preserving siblings and TLS connection', { timeout: 45_000 }, async (t) => {
  const path = await reportPath(t);
  const command = await runCommand(process.execPath, ['scripts/transparent-soak.mjs', '--seconds=1', '--profile=h2-flow', `--report=${path}`],
    { env: cleanEnvironment(process.env), timeoutMs: 40_000 });
  const report = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(command.code, 0, JSON.stringify(report)); assert.equal(report.status, 'passed');
  const result = report.result, waves = result.warmupWaves + result.waves;
  assert.equal(result.profile, 'h2-flow'); assert.equal(result.h2Flow.tlsConnections, waves);
  assert.equal(result.h2Flow.healthyEchoes, waves * 33);
  for (const direction of ['forward', 'reverse']) for (const outcome of ['resume', 'cancel']) {
    const item = result.h2Flow.cases[`${direction}-${outcome}`];
    assert.equal(item.cases, waves); assert.ok(item.zeroWindowSamples > 0);
    assert.equal(item.healthyWhileBlocked, waves * 4); assert.equal(item.healthyAfter, waves * 4);
    assert.ok(item.maxReadable <= 262144 && item.maxWritable <= 262144);
    assert.equal(item.bytes, outcome === 'resume' ? waves * H2_BYTES : 0);
    assert.equal(item.heldSurvived, outcome === 'cancel' ? waves * 4 : 0);
    assert.equal(item.rstCode, outcome === 'cancel' ? 8 : undefined);
  }
  assertIdle(result.final.lab, result.final.proxy);
  assert.equal(result.final.lab.h2FlowCancels, waves * 2); assert.equal(result.final.lab.h2FlowDeadlines, 0);
  assert.equal(report.worker.closed, true); assert.equal(report.worker.code, 0);
});
test('SIGTERM while H2 stream window is exhausted releases streams, timers and TLS worker', { timeout: 20_000 }, async (t) => {
  const path = await reportPath(t);
  const proc = child(process.execPath, ['scripts/transparent-soak.mjs', '--seconds=300', '--profile=h2-flow', `--report=${path}`], { env: cleanEnvironment(process.env) });
  t.after(() => proc.stop());
  const closed = new Promise((resolve) => proc.proc.once('close', resolve));
  await proc.waitFor(/h2-flow-forward-cancel blocked/, 12_000);
  proc.proc.kill('SIGTERM'); await closed;
  const report = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(report.status, 'aborted'); assert.equal(report.worker.reason, 'aborted');
  assert.equal(report.result.status, 'aborted'); assertIdle(report.result.final.lab, report.result.final.proxy);
  assert.equal(report.result.final.workloadSockets + report.result.final.workloadTimers + report.result.final.workloadRequests, 0);
});
