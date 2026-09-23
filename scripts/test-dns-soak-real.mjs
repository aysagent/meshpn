/** Opt-in actual namespace/pcap regressions. Missing tools fail, never skip. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { child } from './lib/browser-lab-driver.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';
import { assertDnsSoakResult, assertDnsResources } from './lib/dns-soak.mjs';

async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-dns-soak-real-'));
  t.after(() => rm(dir, { recursive: true, force: true })); return join(dir, 'report.json');
}
const cli = 'scripts/transparent-dns-soak.mjs';
for (const concurrency of [1, 8]) test(`independent pcap and soak concurrency=${concurrency}`, { timeout: 30000 }, async (t) => {
  const path = await fixture(t);
  const result = await runCommand(process.execPath, [cli, '--seconds=1', `--concurrency=${concurrency}`, `--report=${path}`],
    { env: cleanEnvironment(process.env), timeoutMs: 25000 });
  const raw = await readFile(path, 'utf8'), report = JSON.parse(raw);
  assert.equal(result.code, 0, raw); assert.equal(report.status, 'passed'); assert.equal(report.privateFilesRemoved, true);
  assert.equal((await stat(path)).mode & 0o777, 0o600); assert.ok(!raw.includes('secret-'));
  assertDnsSoakResult(report.result, { seconds: 1, concurrency });
});
test('SIGTERM during measured work cleans namespace resources and reports aborted', { timeout: 25000 }, async (t) => {
  const path = await fixture(t), proc = child(process.execPath, [cli, '--seconds=60', `--report=${path}`], { env: cleanEnvironment(process.env) });
  t.after(() => proc.stop()); const closed = new Promise((resolve) => proc.proc.once('close', resolve));
  await proc.waitFor(/measured workload ready/, 15000); proc.proc.kill('SIGTERM');
  assert.notEqual(await closed, 0);
  const report = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(report.status, 'aborted'); assert.equal(report.result.status, 'aborted');
  assert.equal(report.privateFilesRemoved, true); assert.equal(report.result.cleanupFailed ?? false, false);
  assertDnsResources(report.result.final.resources, report.result.baseline, true);
});
for (const variable of ['MESHPN_TCPDUMP', 'MESHPN_TSHARK']) test(`missing ${variable} fails closed`, { timeout: 20000 }, async (t) => {
  const path = await fixture(t);
  const result = await runCommand(process.execPath, [cli, '--seconds=1', `--report=${path}`],
    { env: { ...cleanEnvironment(process.env), [variable]: '/nonexistent/dns-lab-tool' }, timeoutMs: 15000 });
  assert.notEqual(result.code, 0); const report = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(report.status, 'failed'); assert.equal(report.privateFilesRemoved, true);
});
test('existing report is never overwritten; direct isolated worker fails outside namespace', async (t) => {
  const path = await fixture(t); await writeFile(path, 'preserve');
  assert.notEqual((await runCommand(process.execPath, [cli, `--report=${path}`])).code, 0);
  assert.equal(await readFile(path, 'utf8'), 'preserve');
  assert.notEqual((await runCommand(process.execPath, [cli, '--isolated', '--seconds=1'])).code, 0);
});
