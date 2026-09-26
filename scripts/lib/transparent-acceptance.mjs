/** Fixed-scope acceptance manifest, validators and bounded subprocess execution. */
import assert from 'node:assert/strict';
import { child, BROWSER_SCENARIOS } from './browser-lab-driver.mjs';

export const TEST_FILES = Object.freeze([
  'test-tls-clienthello-ja4.mjs', 'test-transparent-tls-enc-sni.mjs', 'test-transparent-tls-integration.mjs',
  'test-transparent-tls-runtime.mjs', 'test-transparent-tls-retry.mjs', 'test-transparent-tls-resumption.mjs',
  'test-transparent-tls-early-data.mjs', 'test-transparent-tls-ech.mjs', 'test-transparent-connect-lab.mjs',
  'test-browser-lab-pcap.mjs', 'test-browser-lab-process.mjs', 'test-transparent-tls-load.mjs',
  'test-transparent-acceptance.mjs',
  'test-transparent-soak.mjs',
  'test-transparent-slow-reader.mjs',
  'test-transparent-h2-flow.mjs',
  'test-transparent-h2-goaway.mjs',
  'test-browser-soak.mjs',
  'test-transparent-tls-replay.mjs',
  'test-transparent-tls-destination.mjs',
  'test-transparent-dns-lab.mjs',
  'test-dns-wire.mjs',
  'test-dns-soak.mjs',
  'test-dns-upstream-config.mjs',
  'test-dns-upstream-route.mjs',
  'test-dns-exit-adapter.mjs',
  'test-dns-adapter-soak.mjs',
  'test-dns-lifecycle.mjs',
  'test-dns-lifecycle-journal.mjs',
  'test-dns-inspect.mjs',
  'test-dns-diagnostic.mjs',
  'test-dnsmasq-config.mjs',
  'test-dnsmasq-journal.mjs',
  'test-dns-networkd.mjs',
  'test-dhcp-lab-wire.mjs',
  'test-dns-resolved.mjs',
  'test-dns-resolved-journal.mjs',
  'test-dns-adapter-process.mjs',
  'test-dns-boot.mjs',
  'test-dns-vm.mjs',
  'test-ingress-routing.mjs',
  'test-ingress-journal.mjs',
  'test-tun-bridge-startup.mjs',
]);

export function parseOptions(args) {
  const options = { suite: 'full', repeat: 1 };
  const seen = new Set();
  for (const arg of args) {
    if (arg === '--help') { options.help = true; continue; }
    const match = /^--(suite|repeat|report)=(.+)$/.exec(arg);
    if (!match || seen.has(match[1])) throw new Error(`invalid or duplicate argument: ${arg}`);
    seen.add(match[1]); options[match[1]] = match[2];
  }
  if (!['full', 'node'].includes(options.suite)) throw new Error('suite must be full or node');
  if (!/^[1-3]$/.test(String(options.repeat))) throw new Error('repeat must be 1..3');
  options.repeat = Number(options.repeat);
  return options;
}

export function cleanEnvironment(env) {
  const result = { ...env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off', GOENV: 'off', GOWORK: 'off', GOFLAGS: '' };
  for (const key of ['SSLKEYLOGFILE', 'NODE_OPTIONS', 'NODE_TEST_CONTEXT']) delete result[key];
  return result;
}

export async function runCommand(file, args, { cwd, env, signal, timeoutMs = 15_000, maxBytes = 1024 * 1024 } = {}) {
  if (signal?.aborted) return { code: null, signal: null, reason: 'aborted', stdout: '', stderr: '', durationMs: 0 };
  const started = performance.now(), proc = child(file, args, { cwd, env });
  let stdout = '', stderr = '', bytes = 0, reason = null, stopping;
  const stop = (why) => { reason ??= why; stopping ??= proc.stop().catch(() => { reason = 'cleanup-failed'; }); };
  const abort = () => stop('aborted');
  signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(() => stop('timeout'), timeoutMs);
  proc.proc.once('error', () => { reason ??= 'spawn-error'; });
  for (const [stream, append] of [[proc.proc.stdout, (text) => { stdout += text; }], [proc.proc.stderr, (text) => { stderr += text; }]]) {
    stream.setEncoding('utf8');
    stream.on('data', (text) => {
      bytes += Buffer.byteLength(text);
      if (bytes > maxBytes) stop('output-limit');
      else append(text);
    });
  }
  if (signal?.aborted) abort();
  const result = await new Promise((resolve) => proc.proc.once('close', (code, sig) => resolve({ code, signal: sig })));
  clearTimeout(timer); signal?.removeEventListener('abort', abort);
  await stopping;
  return { ...result, reason, stdout, stderr, durationMs: Math.round(performance.now() - started) };
}

export function resultLines(output, prefix) {
  return output.split('\n').filter((line) => line.startsWith(`${prefix} `)).map((line) => JSON.parse(line.slice(prefix.length + 1)));
}
export function nodeSummary(output, expectedFiles = TEST_FILES) {
  const results = resultLines(output, 'NODE_RESULT');
  assert.equal(results.length, 1, 'exactly one completed Node report required');
  const result = results[0]; assert.equal(result.schema, 1);
  for (const field of ['tests', 'passed', 'failed', 'skipped', 'todo']) assert.ok(Number.isSafeInteger(result.counts[field]) && result.counts[field] >= 0);
  assert.ok(result.counts.tests > 0, 'empty suite is not a pass');
  assert.equal(result.counts.tests, result.counts.passed, 'not all tests passed');
  for (const field of ['failed', 'skipped', 'todo']) assert.equal(result.counts[field], 0, `${field} tests are not accepted`);
  assert.deepEqual([...result.files].sort(), [...expectedFiles].sort(), 'test file manifest incomplete');
  return result;
}
export function browserSummary(output) {
  const rows = resultLines(output, 'BROWSER_RESULT'), seen = new Set(), versions = new Map();
  assert.equal(rows.length, 2 * BROWSER_SCENARIOS.length, 'browser matrix incomplete');
  for (const row of rows) {
    assert.equal(row.schema, 1);
    assert.ok(['chrome', 'firefox'].includes(row.kind) && BROWSER_SCENARIOS.includes(row.scenario));
    const key = `${row.kind}/${row.scenario}`; assert.ok(!seen.has(key), 'duplicate browser scenario'); seen.add(key);
    assert.match(row.version, row.kind === 'chrome' ? /^Chrome\/[\d.]+$/ : /^Firefox\/[\d.]+$/);
    if (versions.has(row.kind)) assert.equal(row.version, versions.get(row.kind), 'browser version changed within matrix');
    versions.set(row.kind, row.version);
    const repeated = ['resumption', 'resumption-hrr', 'ticket-rejection'].includes(row.scenario);
    assert.equal(row.connections, repeated ? 2 : 1);
    assert.equal(row.clientHellos, row.scenario === 'resumption-hrr' ? 9 : row.scenario === 'hrr' || repeated ? 6 : 3);
  }
  return rows;
}

export async function repeatMatrix({ suite, repeat }, run, signal, onResult = () => {}) {
  const results = [];
  for (let iteration = 1; iteration <= repeat; iteration++) {
    for (const stage of suite === 'full' ? ['node', 'browser'] : ['node']) {
      if (signal?.aborted) return { status: 'aborted', results };
      let outcome;
      try { outcome = await run(stage); }
      catch { outcome = { status: signal?.aborted ? 'aborted' : 'failed', reason: 'stage-exception' }; }
      const result = { ...outcome, iteration, stage };
      results.push(result); onResult(result);
      if (result.status !== 'passed') return { status: result.status, results };
    }
  }
  return { status: signal?.aborted ? 'aborted' : 'passed', results };
}
