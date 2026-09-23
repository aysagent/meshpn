/** Opt-in real-browser regressions, deliberately separate from browser-independent Node acceptance. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { child } from './lib/browser-lab-driver.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';
import { assertIdle } from './lib/transparent-soak.mjs';
import { assertBrowserResult } from './lib/browser-soak.mjs';

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-browser-soak-real-'));
  t.after(() => rm(directory, { recursive: true, force: true })); return join(directory, 'report.json');
}
for (const kind of ['chrome', 'firefox']) {
  test(`${kind}: persistent-profile soak at maximum concurrency exits cleanly`, { timeout: 45_000 }, async (t) => {
    const path = await fixture(t);
    const command = await runCommand(process.execPath, ['scripts/transparent-browser-soak.mjs', `--browser=${kind}`,
      '--seconds=1', '--concurrency=12', `--report=${path}`], { env: cleanEnvironment(process.env), timeoutMs: 40_000 });
    const report = JSON.parse(await readFile(path, 'utf8'));
    assert.equal(command.code, 0, JSON.stringify(report)); assert.equal(report.status, 'passed');
    assert.equal(report.privateFilesRemoved, true);
    assertBrowserResult(report.results[0].result, { seconds: 1, concurrency: 12 }, kind);
    assert.deepEqual(report.results[0].worker, { code: 0, signal: null, closed: true, reason: null });
  });
  test(`${kind}: SIGTERM with admitted held requests reports aborted and removes private state`, { timeout: 25_000 }, async (t) => {
    const path = await fixture(t);
    const proc = child(process.execPath, ['scripts/transparent-browser-soak.mjs', `--browser=${kind}`, '--seconds=300', `--report=${path}`],
      { env: cleanEnvironment(process.env) });
    t.after(() => proc.stop());
    const closed = new Promise((resolve) => proc.proc.once('close', resolve));
    await proc.waitFor(new RegExp(`${kind} held requests reached origin`), 15_000);
    proc.proc.kill('SIGTERM'); assert.notEqual(await closed, 0);
    const report = JSON.parse(await readFile(path, 'utf8')), record = report.results[0], result = record.result;
    assert.equal(report.status, 'aborted'); assert.equal(record.status, 'aborted'); assert.equal(result.status, 'aborted');
    assert.equal(result.failure.phase, 'held'); assert.equal(result.launches, 1);
    assert.equal(record.worker.closed, true); assert.equal(record.worker.reason, 'aborted');
    assert.equal(report.privateFilesRemoved, true); assert.equal(result.cleanupFailed ?? false, false);
    assert.equal(result.final.resources.tree.live, 1); assertIdle(result.final.lab, result.final.proxy);
    for (const key of ['TCPSocketWrap', 'TCPServerWrap', 'Timeout', 'ProcessWrap']) assert.equal(result.final.resources.worker.active[key] ?? 0, 0);
  });
}
