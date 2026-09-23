import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import reporter from './lib/acceptance-reporter.mjs';
import { BROWSER_SCENARIOS } from './lib/browser-lab-driver.mjs';
import { parseOptions, cleanEnvironment, runCommand, nodeSummary, browserSummary, repeatMatrix } from './lib/transparent-acceptance.mjs';

test('acceptance defaults to full matrix and bounded repeats', () => {
  assert.deepEqual(parseOptions([]), { suite: 'full', repeat: 1 });
  assert.deepEqual(parseOptions(['--suite=node', '--repeat=3']), { suite: 'node', repeat: 3 });
});
for (const arg of ['--repeat=0', '--repeat=4', '--repeat=Infinity', '--repeat=01', '--suite=chrome', '--unknown', '--report=']) {
  test(`invalid acceptance option ${arg} fails closed`, () => assert.throws(() => parseOptions([arg])));
}
test('duplicate flags are not silently overridden', () => assert.throws(() => parseOptions(['--repeat=1', '--repeat=2'])));
test('child environment cannot inherit key logging or Node test filters', () => {
  const input = { SSLKEYLOGFILE: '/secret', NODE_OPTIONS: '--test-only', NODE_TEST_CONTEXT: 'child-v8', HOME: '/unchanged', GOTOOLCHAIN: 'auto' };
  const result = cleanEnvironment(input);
  assert.equal(result.HOME, input.HOME); assert.equal(result.GOTOOLCHAIN, 'local');
  for (const key of ['SSLKEYLOGFILE', 'NODE_OPTIONS', 'NODE_TEST_CONTEXT']) assert.equal(key in result, false);
  assert.equal(input.GOTOOLCHAIN, 'auto');
});

async function report(events) { let out = ''; for await (const chunk of reporter(events)) out += chunk; return out; }
const pass = { type: 'test:pass', data: { file: '/test/case.mjs', name: 'case', details: {} } };
test('reporter consumes test events and excludes raw logs/stacks', async () => {
  const out = await report([{ type: 'test:stdout', data: { message: 'SECRET' } }, pass]);
  assert.equal(nodeSummary(out, ['case.mjs']).counts.tests, 1);
  assert.ok(!out.includes('SECRET'));
});
for (const flag of ['skip', 'todo']) test(`zero exit with ${flag} is not acceptance`, async () => {
  const out = await report([{ ...pass, data: { ...pass.data, [flag]: true } }]);
  assert.throws(() => nodeSummary(out, ['case.mjs']));
});
test('failed test names retained without exception payloads', async () => {
  const out = await report([{ type: 'test:fail', data: { ...pass.data, details: { error: new Error('SECRET') } } }]);
  assert.ok(out.includes('case.mjs')); assert.ok(!out.includes('SECRET'));
  assert.throws(() => nodeSummary(out, ['case.mjs']));
});
test('missing, empty, duplicated or partial Node summaries fail', async () => {
  const valid = await report([pass]);
  for (const output of ['', await report([]), valid + valid]) assert.throws(() => nodeSummary(output, ['case.mjs']));
  assert.throws(() => nodeSummary(valid, ['case.mjs', 'missing.mjs']));
});

function browserRows() {
  return ['chrome', 'firefox'].flatMap((kind) => BROWSER_SCENARIOS.map((scenario) => {
    const repeat = ['resumption', 'resumption-hrr', 'ticket-rejection'].includes(scenario);
    return { schema: 1, kind, scenario, version: `${kind === 'chrome' ? 'Chrome' : 'Firefox'}/151.0`,
      connections: repeat ? 2 : 1, clientHellos: scenario === 'resumption-hrr' ? 9 : scenario === 'hrr' || repeat ? 6 : 3 };
  }));
}
const browserOutput = (rows) => rows.map((row) => `BROWSER_RESULT ${JSON.stringify(row)}\n`).join('');
test('complete structured browser matrix passes', () => assert.equal(browserSummary(browserOutput(browserRows())).length, 14));
for (const [name, change] of [
  ['missing', (rows) => rows.pop()], ['duplicate', (rows) => { rows[1] = rows[0]; }],
  ['wrong flight count', (rows) => { rows[2].clientHellos = 3; }],
  ['version drift', (rows) => { rows[1].version = 'Chrome/999.0'; }],
]) test(`browser matrix rejects ${name}`, () => {
  const rows = browserRows(); change(rows); assert.throws(() => browserSummary(browserOutput(rows)));
});

test('repeat means full repetitions, not retry until green', async () => {
  let calls = 0;
  const result = await repeatMatrix({ suite: 'full', repeat: 3 }, async () => ({ status: ++calls === 2 ? 'failed' : 'passed' }));
  assert.equal(calls, 2); assert.equal(result.status, 'failed');
});
test('node-only matrix is never expanded implicitly', async () => {
  const calls = [];
  const result = await repeatMatrix({ suite: 'node', repeat: 2 }, async (stage) => { calls.push(stage); return { status: 'passed' }; });
  assert.deepEqual(calls, ['node', 'node']); assert.equal(result.results.length, 2);
});
test('unexpected stage exception preserves completed results and stops repeats', async () => {
  let calls = 0;
  const result = await repeatMatrix({ suite: 'full', repeat: 3 }, async () => {
    if (++calls === 2) throw new Error('SECRET');
    return { status: 'passed' };
  });
  assert.equal(calls, 2); assert.equal(result.status, 'failed');
  assert.equal(result.results.length, 2); assert.equal(result.results[0].status, 'passed');
  assert.equal(result.results[1].reason, 'stage-exception');
  assert.ok(!JSON.stringify(result).includes('SECRET'));
});
test('aborted matrix starts no further stages', async () => {
  const controller = new AbortController(); controller.abort();
  const result = await repeatMatrix({ suite: 'full', repeat: 3 }, () => assert.fail('must not run'), controller.signal);
  assert.equal(result.status, 'aborted'); assert.equal(result.results.length, 0);
});

test('bounded command distinguishes success, nonzero exit and missing executable', async () => {
  const good = await runCommand(process.execPath, ['-e', 'console.log("ok")']);
  assert.equal(good.code, 0); assert.equal(good.reason, null);
  const bad = await runCommand(process.execPath, ['-e', 'process.exit(7)']);
  assert.equal(bad.code, 7);
  const missing = await runCommand('/meshpn-missing-test-executable', []);
  assert.equal(missing.reason, 'spawn-error');
});
test('command timeout, cancellation and output overflow cannot become success', { timeout: 10_000 }, async () => {
  const timed = await runCommand(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { timeoutMs: 100 });
  assert.equal(timed.reason, 'timeout');
  const verbose = await runCommand(process.execPath, ['-e', 'console.log("x".repeat(10000))'], { maxBytes: 100 });
  assert.equal(verbose.reason, 'output-limit'); assert.ok(verbose.stdout.length <= 100);
  const controller = new AbortController();
  const pending = runCommand(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { signal: controller.signal });
  controller.abort(); assert.equal((await pending).reason, 'aborted');
});

test('CLI refuses existing reports and persists explicit preflight failure privately', { timeout: 15_000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-acceptance-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'report.json'); await writeFile(path, 'keep');
  const args = ['scripts/transparent-acceptance.mjs', '--suite=node', `--report=${path}`];
  const env = cleanEnvironment({ ...process.env, MESHPN_ECH_GO: '/meshpn-missing-go' });
  assert.notEqual((await runCommand(process.execPath, args, { env })).code, 0);
  assert.equal(await readFile(path, 'utf8'), 'keep');
  const failedPath = join(directory, 'failed.json');
  const result = await runCommand(process.execPath, ['scripts/transparent-acceptance.mjs', '--suite=node', `--report=${failedPath}`], { env });
  assert.notEqual(result.code, 0);
  const failure = JSON.parse(await readFile(failedPath, 'utf8'));
  assert.equal(failure.status, 'failed'); assert.equal(failure.fullAcceptance, false);
  assert.equal(failure.results.length, 0); assert.equal(failure.tools.go.status, 'failed');
  assert.equal((await stat(failedPath)).mode & 0o777, 0o600);
});
