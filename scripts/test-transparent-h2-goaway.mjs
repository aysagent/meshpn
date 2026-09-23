import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertGoaways } from './lib/transparent-h2-goaway.mjs';
import { H2_BYTES } from './lib/lab-h2-flow.mjs';
import { startTransparentTlsLab } from './lib/transparent-tls-lab.mjs';
import { soakOptions, assertIdle } from './lib/transparent-soak.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';
import { child } from './lib/browser-lab-driver.mjs';

test('GOAWAY is an explicit bounded soak profile', () => assert.equal(soakOptions(['--profile=h2-goaway']).profile, 'h2-goaway'));
test('GOAWAY permits non-increasing boundaries ending at last accepted stream', () => {
  assertGoaways([{ code: 0, lastStreamID: 0x7fffffff }, { code: 0, lastStreamID: 9 }, { code: 0, lastStreamID: 9 }], 9);
});
for (const [name, events] of [
  ['absent', []],
  ['error code', [{ code: 2, lastStreamID: 9 }]],
  ['lost accepted stream', [{ code: 0, lastStreamID: 7 }]],
  ['increasing boundary', [{ code: 0, lastStreamID: 9 }, { code: 0, lastStreamID: 11 }, { code: 0, lastStreamID: 9 }]],
  ['missing final boundary', [{ code: 0, lastStreamID: 0x7fffffff }]],
  ['unbounded events', Array.from({ length: 9 }, () => ({ code: 0, lastStreamID: 9 }))],
]) test(`rejects incorrect GOAWAY evidence: ${name}`, () => assert.throws(() => assertGoaways(events, 9)));

test('drain without H2 sessions creates no deadline and rejects external origin', async (t) => {
  const lab = await startTransparentTlsLab(); t.after(() => lab.close());
  await lab.drainOriginHttp2(); assert.equal(lab.stats().h2DrainTimers, 0);
  const external = await startTransparentTlsLab({ externalOriginPort: 12345 }); t.after(() => external.close());
  await assert.rejects(external.drainOriginHttp2(), /external origin/);
});
async function reportPath(t) {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-h2-goaway-test-'));
  t.after(() => rm(directory, { recursive: true, force: true })); return join(directory, 'report.json');
}
test('real GOAWAY drains blocked streams and admitted POSTs, refuses new request, closes naturally without replay', { timeout: 45_000 }, async (t) => {
  const path = await reportPath(t);
  const command = await runCommand(process.execPath, ['scripts/transparent-soak.mjs', '--seconds=1', '--profile=h2-goaway', `--report=${path}`],
    { env: cleanEnvironment(process.env), timeoutMs: 40_000 });
  const report = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(command.code, 0, JSON.stringify(report)); assert.equal(report.status, 'passed');
  const result = report.result, waves = result.warmupWaves + result.waves;
  assert.equal(result.profile, 'h2-goaway');
  for (const direction of ['forward', 'reverse']) {
    const item = result.h2Goaway[direction];
    for (const key of ['cases', 'refused', 'tlsConnections', 'naturalCloses']) assert.equal(item[key], waves);
    assert.equal(item.bytes, waves * H2_BYTES); assert.equal(item.heldSurvived, waves * 4);
    assert.ok(item.goaways >= waves && item.goaways <= 8 * waves);
  }
  for (const point of result.samples) assertIdle(point.lab, point.proxy);
  assertIdle(result.final.lab, result.final.proxy);
  assert.equal(result.final.lab.h2FlowCancels + result.final.lab.h2FlowDeadlines, 0);
  assert.equal(report.worker.closed, true); assert.equal(report.worker.code, 0);
  assert.equal(report.worker.signal, null); assert.equal(report.worker.reason, null);
});
for (const direction of ['forward', 'reverse']) {
  test(`SIGTERM during ${direction} GOAWAY drain releases pending streams and deadline`, { timeout: 20_000 }, async (t) => {
    const path = await reportPath(t);
    const proc = child(process.execPath, ['scripts/transparent-soak.mjs', '--seconds=300', '--profile=h2-goaway', `--report=${path}`],
      { env: cleanEnvironment(process.env) });
    t.after(() => proc.stop());
    const closed = new Promise((resolve) => proc.proc.once('close', resolve));
    await proc.waitFor(new RegExp(`h2-goaway-${direction} draining`), 12_000);
    proc.proc.kill('SIGTERM'); await closed;
    const report = JSON.parse(await readFile(path, 'utf8'));
    assert.equal(report.lastDrain.direction, direction); assert.equal(report.lastDrain.phase, 'draining');
    assert.equal(report.status, 'aborted'); assert.equal(report.worker.reason, 'aborted');
    assert.equal(report.result.status, 'aborted'); assert.equal(report.result.failure.h2Goaway.step, 'new-request-refused');
    assertIdle(report.result.final.lab, report.result.final.proxy);
    assert.equal(report.result.final.workloadSockets + report.result.final.workloadTimers + report.result.final.workloadRequests, 0);
    for (const key of ['TCPSocketWrap', 'TCPServerWrap', 'Timeout', 'ProcessWrap']) assert.equal(report.result.final.resources.active[key] ?? 0, 0);
  });
}
