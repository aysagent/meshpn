/** Browser-independent contract and ownership regressions; real browsers run via the soak CLI. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { child } from './lib/browser-lab-driver.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';
import { browserSoakOptions, assertBrowserResources, assertBrowserResult, namespaceArgs, waitBrowserCleanup } from './lib/browser-soak.mjs';

test('browser soak defaults are finite and per browser', () => {
  assert.deepEqual(browserSoakOptions([]), { browser: 'all', seconds: 300, concurrency: 4 });
  assert.equal(browserSoakOptions(['--browser=firefox', '--seconds=3600', '--concurrency=12']).seconds, 3600);
});
for (const arg of ['--browser=curl', '--seconds=0', '--seconds=3601', '--seconds=1.5', '--seconds=01',
  '--seconds=Infinity', '--concurrency=1', '--concurrency=13', '--report=', '--target=example.com', '--no-sandbox']) {
  test(`browser soak rejects ${arg}`, () => assert.throws(() => browserSoakOptions([arg])));
}
test('browser soak rejects duplicate options', () => assert.throws(() => browserSoakOptions(['--seconds=1', '--seconds=2'])));

const base = { tree: { live: 12, zombies: 0, fds: 500, rss: 1800 * 1048576 },
  worker: { fds: 27, memory: { rss: 90 * 1048576 }, active: {} } };
test('summed RSS is not unique RAM; a bounded cold Chrome-sized tree is admitted', () => assertBrowserResources(base, base));
for (const [name, change] of [
  ['missing browser', (r) => { r.tree.live = 1; }],
  ['absolute processes', (r) => { r.tree.live = 65; }],
  ['growing processes', (r) => { r.tree.live = 21; }],
  ['absolute FDs', (r) => { r.tree.fds = 4097; }],
  ['growing FDs', (r) => { r.tree.fds = 629; }],
  ['zombies', (r) => { r.tree.zombies = 9; }],
  ['tree RSS', (r) => { r.tree.rss = 3073 * 1048576; }],
  ['worker RSS', (r) => { r.worker.memory.rss = 513 * 1048576; }],
  ['worker FDs', (r) => { r.worker.fds = 28; }],
]) test(`resource checks reject ${name}`, () => {
  const current = structuredClone(base); change(current); assert.throws(() => assertBrowserResources(current, base));
});

const labIdle = Object.fromEntries(['sockets', 'heldResponses', 'h2Sessions', 'h2DrainTimers', 'pendingClients',
  'relaySessions', 'relayTimers', 'cleanupFailures', 'slowStreams', 'slowStreamTimers', 'h2FlowStreams', 'h2FlowTimers'].map((k) => [k, 0]));
const proxyIdle = Object.fromEntries(['clients', 'upstreams', 'headerTimers', 'relaySessions', 'relayTimers', 'cleanupFailures'].map((k) => [k, 0]));
const options = { seconds: 1, concurrency: 4 };
const valid = { schema: 1, status: 'passed', browser: 'chrome', version: 'test-browser', seconds: 1, concurrency: 4,
  launches: 1, warmupWaves: 3, waves: 1, measuredMs: 1000, baseline: base,
  samples: [{ resources: base }, { resources: base }],
  totals: { echoes: 16, echoBytes: 16 * 65536, aborted: 8, heldCompleted: 8, drains: 5, connections: 5, clientHellos: 15 },
  final: { resources: { tree: { live: 1 }, worker: { active: {} } }, lab: labIdle, proxy: proxyIdle } };
test('complete browser soak evidence is accepted', () => assertBrowserResult(valid, options, 'chrome'));
test('cleanup waits for a fully readable snapshot after dying processes deny FD access', async () => {
  let reads = 0;
  const snapshot = { tree: { live: 1 } };
  const result = await waitBrowserCleanup(() => {
    reads++; if (reads <= 2) throw Object.assign(new Error(), { code: 'EACCES' });
    return reads === 3 ? { tree: { live: 2 } } : snapshot;
  });
  assert.equal(result.resources, snapshot); assert.equal(result.transientReadErrors, 2);
});
test('cleanup cannot pass permanently denied resource observations', async () => {
  await assert.rejects(waitBrowserCleanup(() => { throw Object.assign(new Error(), { code: 'EPERM' }); }, 20), { code: 'BROWSER_CLEANUP_TIMEOUT' });
});
test('cleanup cannot pass surviving browser processes', async () => {
  await assert.rejects(waitBrowserCleanup(() => ({ tree: { live: 2 } }), 20), { code: 'BROWSER_CLEANUP_TIMEOUT' });
});
test('cleanup does not swallow unexpected resource errors', async () => {
  await assert.rejects(waitBrowserCleanup(() => { throw Object.assign(new Error(), { code: 'EIO' }); }), { code: 'EIO' });
});
for (const [name, change] of [
  ['failed workload', (r) => { r.status = 'failed'; }],
  ['wrong browser', (r) => { r.browser = 'firefox'; }],
  ['browser restart', (r) => { r.launches = 2; }],
  ['no measured waves', (r) => { r.waves = 0; }],
  ['too short', (r) => { r.measuredMs = 999; }],
  ['missing aborts', (r) => { r.totals.aborted--; }],
  ['hidden reconnect', (r) => { r.totals.connections++; }],
  ['missing trace', (r) => { r.totals.clientHellos--; }],
  ['surviving browser', (r) => { r.final.resources.tree.live = 2; }],
  ['leaked timer', (r) => { r.final.resources.worker.active.Timeout = 1; }],
  ['leaked relay', (r) => { r.final.lab.relaySessions = 1; }],
  ['cleanup failure', (r) => { r.cleanupFailed = true; }],
]) test(`incomplete browser soak report is rejected: ${name}`, () => {
  const result = structuredClone(valid); change(result); assert.throws(() => assertBrowserResult(result, options, 'chrome'));
});

async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-browser-soak-test-'));
  t.after(() => rm(dir, { recursive: true, force: true })); return join(dir, 'report.json');
}
test('internal worker refuses the host namespace before launching tools', async () => {
  const env = cleanEnvironment(process.env); delete env.MESHPN_PARENT_NETNS; delete env.MESHPN_PARENT_PIDNS;
  const command = await runCommand(process.execPath, ['scripts/transparent-browser-soak.mjs', '--isolated', '--browser=chrome', '--seconds=1'], { env });
  assert.notEqual(command.code, 0); assert.match(command.stderr, /public browser soak launcher/);
});
test('browser soak never overwrites an existing report', async (t) => {
  const path = await fixture(t); await writeFile(path, 'keep');
  const command = await runCommand(process.execPath, ['scripts/transparent-browser-soak.mjs', '--seconds=1', `--report=${path}`]);
  assert.notEqual(command.code, 0); assert.equal(await readFile(path, 'utf8'), 'keep');
});
test('missing browser fails without skips and still closes lab and removes private profiles', { timeout: 20_000 }, async (t) => {
  const path = await fixture(t), env = cleanEnvironment(process.env);
  delete env.MESHPN_BROWSER_CHROME;
  const command = await runCommand(process.execPath, ['scripts/transparent-browser-soak.mjs', '--browser=chrome', '--seconds=1', `--report=${path}`], { env });
  const report = JSON.parse(await readFile(path, 'utf8'));
  assert.notEqual(command.code, 0); assert.equal(report.status, 'failed'); assert.equal(report.privateFilesRemoved, true);
  assert.equal(report.results[0].result.launches, 0); assert.equal(report.results[0].result.final.resources.tree.live, 1);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
});
for (const signal of ['SIGTERM', 'SIGKILL']) test(`PID namespace contains a detached TERM-resistant descendant on ${signal}`, { timeout: 10_000 }, async (t) => {
  const source = `const {spawn}=require('node:child_process');
    process.on('SIGTERM',()=>process.exit(0));
    const p=spawn(process.execPath,['-e','process.on("SIGTERM",()=>{});setInterval(()=>{},1000);console.log("READY")'],{detached:true,stdio:['ignore','inherit','inherit']});
    setInterval(()=>{},1000);`;
  const proc = child('unshare', [...namespaceArgs, process.execPath, '-e', source]);
  t.after(() => proc.stop()); await proc.waitFor(/READY/, 5000);
  const init = (await readFile(`/proc/${proc.proc.pid}/task/${proc.proc.pid}/children`, 'utf8')).trim();
  assert.match(init, /^\d+$/);
  const descendant = (await readFile(`/proc/${init}/task/${init}/children`, 'utf8')).trim();
  assert.match(descendant, /^\d+$/);
  await proc.stop(signal);
  async function running() {
    try { const data = await readFile(`/proc/${descendant}/stat`, 'utf8'); return data.slice(data.lastIndexOf(')') + 2).split(' ')[0] !== 'Z'; }
    catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  }
  for (let i = 0; i < 100 && await running(); i++) await delay(10);
  assert.equal(await running(), false, 'descendant escaped namespace owner cleanup');
});
