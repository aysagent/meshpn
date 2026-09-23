/** No skips: actual tcpdump/tshark, public-contract adapter, isolated namespaces. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { child } from './lib/browser-lab-driver.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';
import { assertAdapterSoakResult } from './lib/dns-adapter-soak.mjs';
import { assertDnsResources } from './lib/dns-soak.mjs';

const cli = 'scripts/dns-adapter-soak.mjs';
async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-adapter-soak-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  return join(dir, 'report.json');
}
for (const family of [4, 6]) for (const modeTag of ['transparent-tls', 'combo-tls']) {
  const concurrency = modeTag === 'transparent-tls' ? 1 : 8;
  test(`pcap/soak IPv${family} ${modeTag} concurrency=${concurrency}`, { timeout: 60000 }, async (t) => {
    const path = await fixture(t);
    const p = await runCommand(process.execPath, [cli, '--seconds=1', `--family=${family}`, `--mode=${modeTag}`,
      `--concurrency=${concurrency}`, `--report=${path}`], { env: cleanEnvironment(process.env), timeoutMs: 55000 });
    const raw = await readFile(path, 'utf8'), r = JSON.parse(raw);
    assert.equal(p.reason, null); assert.equal(p.code, 0, raw); assert.equal(r.status, 'passed');
    assert.equal(r.kind, 'dns-exit-adapter'); assert.equal(r.privateFilesRemoved, true);
    assert.equal((await stat(path)).mode & 0o777, 0o600); assert.ok(!raw.includes('secret-'));
    assertAdapterSoakResult(r.result, { seconds: 1, concurrency, family, modeTag });
  });
}
for (const signal of ['SIGTERM', 'SIGINT']) test(`${signal} during measured work reports aborted with cleanup`, { timeout: 45000 }, async (t) => {
  const path = await fixture(t), proc = child(process.execPath, [cli, '--seconds=60', `--report=${path}`], { env: cleanEnvironment(process.env) });
  t.after(() => proc.stop()); const closed = new Promise((resolve) => proc.proc.once('close', resolve));
  await proc.waitFor(/measured workload ready/, 35000); proc.proc.kill(signal); assert.notEqual(await closed, 0);
  const r = JSON.parse(await readFile(path, 'utf8')); assert.equal(r.status, 'aborted'); assert.equal(r.result.status, 'aborted');
  assert.equal(r.privateFilesRemoved, true); assert.equal(r.result.cleanupFailed ?? false, false);
  assertDnsResources(r.result.final.resources, r.result.baseline, true);
});
for (const variable of ['MESHPN_TCPDUMP', 'MESHPN_TSHARK']) test(`missing ${variable} cannot pass`, { timeout: 20000 }, async (t) => {
  const path = await fixture(t);
  const p = await runCommand(process.execPath, [cli, '--seconds=1', `--report=${path}`],
    { env: { ...cleanEnvironment(process.env), [variable]: '/nonexistent/adapter-tool' }, timeoutMs: 15000 });
  assert.notEqual(p.code, 0); const r = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(r.status, 'failed'); assert.equal(r.privateFilesRemoved, true);
});
test('exclusive report and namespace guard', async (t) => {
  const path = await fixture(t); await writeFile(path, 'preserve');
  assert.notEqual((await runCommand(process.execPath, [cli, `--report=${path}`])).code, 0);
  assert.equal(await readFile(path, 'utf8'), 'preserve');
  assert.notEqual((await runCommand(process.execPath, [cli, '--isolated', '--seconds=1'])).code, 0);
});
