import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { fileURLToPath } from 'node:url';
import { collectClientCheck, parseClientCheckArgs, parseClientCurl, clientCurlArgs } from './lib/client-check.mjs';
import { DIAGNOSTIC_ENV } from './lib/dns-diagnostic.mjs';
import { runCommand } from './lib/transparent-acceptance.mjs';

const exit = '8.8.4.4', metric = '\nCLEAN_VPN_CURL_STATS\t';
const ok = stdout => ({ code: 0, signal: null, reason: null, stdout, stderr: '', durationMs: 1 });
const trace = (ip = exit) => `private=never-include-body\nip=${ip}\n${metric}200\t1.1.1.1\t10.99.0.2\t128\t0.2\t0\t2\n`;
function fixture({ active = true, route = 'tun0', v6 = 'eth0', egress = exit, drift = false, dnsFailure = false, noCurl = false } = {}) {
  const calls = []; let traceRoutes = 0;
  return { calls, run: async (file, args, options) => {
    calls.push({ file, args, options });
    if (options.signal.aborted) return { ...ok(''), code: null, reason: 'aborted' };
    if (file === 'git') return ok('d72e11b\n');
    if (file === 'ip') {
      if (args.includes('addr')) return ok(JSON.stringify(active ? [{ ifname: 'tun0', flags: ['UP'], addr_info: [{ family: 'inet', local: '10.99.0.2' }] }] : []));
      if (args.includes('get')) {
        if (args.at(-1) === '1.1.1.1') traceRoutes++;
        return ok(JSON.stringify([{ dev: args.includes('-6') ? v6 : drift && traceRoutes >= 3 ? 'eth0' : route, type: 'unicast' }]));
      }
      return ok('[]');
    }
    if (file === 'getent') return ok('1.0.0.1 STREAM endpoint\n');
    if (file === 'dig') return ok(dnsFailure ? ';; status: SERVFAIL,\n' : `;; status: NOERROR,\nexample.com. 30 IN ${args[1]} ${args[1] === 'A' ? '1.0.0.1' : '::1'}\n`);
    assert.equal(file, 'curl');
    if (noCurl) return { ...ok(''), code: null, reason: 'spawn-error' };
    if (args.includes('--version')) return ok('curl fixture\n');
    return ok(args.at(-1).includes('__down') ? `${metric}200\t1.0.0.1\t10.99.0.2\t1048576\t1.0\t0\t2\n` : trace(egress));
  } };
}
const options = { probe: true, tun: 'tun0', expectedExitIp: exit };

test('strict CLI refuses ambiguous/unsafe interface, exit IP and mutation options', () => {
  assert.deepEqual(parseClientCheckArgs([]), { probe: false, tun: 'tun0', expectedExitIp: null });
  assert.deepEqual(parseClientCheckArgs(['--probe', '--expect-exit-ip=8.8.4.4']), options);
  for (const args of [['--probe', '--probe'], ['--run'], ['--apply'], ['--tun=lo'], ['--tun=-bad'], ['--tun=../../etc'],
    ['--expect-exit-ip=127.0.0.1'], ['--expect-exit-ip=10.1.1.1'], ['--expect-exit-ip=hostname'], ['--url=https://other']]) assert.throws(() => parseClientCheckArgs(args));
});

test('inspection sends no probes or setters; ignores user proxy, curl config, credentials and response bodies', async () => {
  const f = fixture(), r = await collectClientCheck({}, f);
  assert.equal(r.status, 'inspection-only'); assert.equal(r.systemSettingsChanged, false);
  assert.equal(r.probes.status, 'not-requested');
  for (const c of f.calls) {
    assert.deepEqual(c.options.env, DIAGNOSTIC_ENV);
    assert.ok(c.options.timeoutMs <= 23000); assert.ok(c.options.maxBytes <= 32768);
    assert.ok(['git', 'ip', 'curl'].includes(c.file));
    assert.ok(!c.args.some(a => ['add', 'del', 'replace', 'flush', '--apply', '--insecure'].includes(a)));
    if (c.file === 'curl') assert.deepEqual(c.args, ['-q', '--version']);
  }
});

for (const scenario of [{ active: false }, { route: 'eth0' }]) test(`no host tunnel route never becomes success ${JSON.stringify(scenario)}`, async () => {
  const f = fixture(scenario), r = await collectClientCheck(options, f);
  assert.equal(r.status, 'incomplete-or-failed'); assert.equal(r.probes.status, 'skipped-no-confirmed-host-tunnel-route');
  assert.ok(!f.calls.some(c => c.file === 'dig' || c.file === 'getent' || c.args.some(a => a.startsWith('https:'))));
});

test('host smoke matches expected exit, checks repeat HTTPS and exact download size without claiming leak freedom', async () => {
  const f = fixture(), r = await collectClientCheck(options, f);
  assert.equal(r.status, 'ipv4-smoke-passed'); assert.equal(r.checks.ipv6, 'direct-route-present-review-required');
  assert.equal(r.probes.dns.length, 4); assert.equal(r.probes.nss.status, 'passed');
  assert.equal(r.probes.repeatHttps.status, 'passed');
  assert.ok(r.limitations.includes('not-a-packet-capture-or-leak-test'));
  assert.doesNotMatch(JSON.stringify(r), /never-include-body/);
  const curls = f.calls.filter(c => c.file === 'curl' && !c.args.includes('--version'));
  assert.equal(curls.length, 3);
  for (const { args, options: opts } of curls) {
    assert.equal(args[0], '-q'); assert.equal(args[args.indexOf('--interface') + 1], 'if!tun0');
    assert.equal(args[args.indexOf('--noproxy') + 1], '*'); assert.equal(args[args.indexOf('--proxy') + 1], '');
    assert.equal(args[args.indexOf('--proto') + 1], '=https'); assert.equal(args[args.indexOf('--max-time') + 1], '20');
    assert.ok(!args.includes('--location')); assert.ok(!args.includes('--insecure'));
    assert.equal(opts.timeoutMs, 23000);
  }
  assert.ok(curls.at(-1).args.includes('speed.cloudflare.com:443:1.0.0.1'));
});

for (const scenario of [{ egress: '8.8.8.8' }, { drift: true }, { dnsFailure: true }, { noCurl: true }]) {
  test(`failure cannot pass: ${JSON.stringify(scenario)}`, async () => {
    const r = await collectClientCheck(options, fixture(scenario)); assert.equal(r.status, 'incomplete-or-failed');
  });
}
test('missing expected IP leaves smoke unconfirmed', async () => {
  const r = await collectClientCheck({ probe: true }, fixture());
  assert.equal(r.checks.egress, 'expected-IP-not-specified'); assert.equal(r.status, 'incomplete-or-failed');
});

test('aborted collection returns report and does not start external probes', async () => {
  const f = fixture(), controller = new AbortController(); controller.abort();
  const r = await collectClientCheck(options, { ...f, signal: controller.signal });
  assert.equal(r.status, 'aborted'); assert.equal(f.calls.length, 0);
});

test('curl success requires verified TLS, expected remote, usable metrics and complete content', () => {
  assert.equal(parseClientCurl(ok(trace()), { trace: true, remoteIp: '1.1.1.1' }).status, 'passed');
  for (const r of [ok(''), { ...ok(trace()), code: 60 }, { ...ok(trace()), reason: 'timeout' },
    ok(trace().replace('\t0\t2', '\t20\t2')), ok(trace().replace('200\t', '302\t')), ok(trace('invalid'))])
    assert.equal(parseClientCurl(r, { trace: true, remoteIp: '1.1.1.1' }).status, 'failed');
  assert.equal(parseClientCurl(ok(trace()), { size: 1048576, remoteIp: '1.1.1.1' }).status, 'failed');
  assert.equal(parseClientCurl(ok(trace()), { trace: true, remoteIp: '1.0.0.1' }).status, 'failed');
});

test('CLI help and invalid arguments are network-free', () => {
  const r = spawnSync(process.execPath, ['scripts/clean-vpn-client-check.mjs', '--help'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(r.status, 0); assert.match(r.stdout, /ALREADY RUNNING/);
  const bad = spawnSync(process.execPath, ['scripts/clean-vpn-client-check.mjs', '--run'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(bad.status, 1); assert.doesNotMatch(bad.stdout, /BEGIN/);
});

test('real curl contract: trusted TLS, untrusted TLS rejection and complete 1 MiB body on loopback', { timeout: 30000 }, async t => {
  if (process.platform !== 'linux' || spawnSync('curl', ['-q', '--version']).status !== 0) return t.skip('Linux/curl required');
  const certPath = fileURLToPath(new URL('./fixtures/boring-tls-local.cert.pem', import.meta.url));
  const server = createServer({ cert: await readFile(certPath),
    key: await readFile(new URL('./fixtures/boring-tls-local.key.pem', import.meta.url)) }, (req, res) => {
    if (req.url === '/download') { res.writeHead(200, { 'Content-Length': 1048576 }); res.end(Buffer.alloc(1048576)); }
    else { res.writeHead(200); res.end(`ip=${exit}\nprivate=not-in-report\n`); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  const base = `https://127.0.0.1:${server.address().port}`;
  const request = async (path, trusted, trace) => {
    const args = clientCurlArgs({ tun: 'lo', url: `${base}${path}`, trace });
    if (trusted) args.splice(1, 0, '--cacert', certPath); // Fixture trust is test-only, never a CLI option.
    return runCommand('curl', args, { env: DIAGNOSTIC_ENV, timeoutMs: 23000, maxBytes: 24576 });
  };
  const rejected = await request('/', false, true);
  assert.equal(rejected.code, 60);
  assert.equal(parseClientCurl(rejected, { remoteIp: '127.0.0.1', trace: true }).status, 'failed');
  const trusted = parseClientCurl(await request('/', true, true), { remoteIp: '127.0.0.1', trace: true });
  assert.equal(trusted.status, 'passed'); assert.equal(trusted.localIp, '127.0.0.1');
  assert.doesNotMatch(JSON.stringify(trusted), /not-in-report/);
  const downloaded = parseClientCurl(await request('/download', true, false), { remoteIp: '127.0.0.1', size: 1048576 });
  assert.equal(downloaded.status, 'passed'); assert.equal(downloaded.downloadedBytes, 1048576);
});
