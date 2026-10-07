import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import { once } from 'node:events';
import { execFileSync } from 'node:child_process';
import { benchmarkMetrics, probeBenchmark, summarizeBenchmarks, execute, trialUnitFinished } from './clean-vpn-native-usb-check.mjs';
import { benchmarkPhases, validateBenchmarkResult, readProcess, sampleTrialCpu } from './lib/native-trial-benchmark.mjs';
import { createPeerChannel, peerStatus, submitPeerResult } from './lib/native-usb-trial-peer.mjs';

const serverIp = '162.159.140.220', exit = '154.62.226.216';
const request = { phase: 'bench-native', token: '12345678-1234-1234-1234-123456789abc' };
const goodStream = upload => ({ code: 0, reason: null, httpStatus: 200, tlsVerify: 0,
  bytes: upload ? 1048576 : 8388608, seconds: 5, remoteIp: serverIp });
const good = p => ({ ...p, serverIp, exitBefore: exit, exitAfter: exit, warmup: true,
  download: { seconds: 5.1, streams: Array.from({ length: 4 }, () => goodStream(false)) },
  upload: { seconds: 5.1, streams: Array.from({ length: 4 }, () => goodStream(true)) }, elapsedMs: 12000 });
test('next cycle waits for completed or collected unit, never treats SSH failure as completion', () => {
  for (const code of [0, 1, 4]) assert.equal(trialUnitFinished({ code, reason: null,
    out: 'LoadState=not-found\nActiveState=inactive\n' }), true);
  assert.equal(trialUnitFinished({ code: 0, reason: null, out: 'ActiveState=inactive\nLoadState=loaded\n' }), true);
  for (const patch of [{ code: 255 }, { reason: 'timeout' }, { out: '' },
    { out: 'LoadState=loaded\nActiveState=deactivating\n' },
    { out: 'LoadState=loaded\nActiveState=active\n' },
    { out: 'LoadState=not-found\n' }, { out: 'LoadState=not-found\nLoadState=not-found\n' }])
    assert.equal(trialUnitFinished({ code: 0, reason: null, out: 'LoadState=not-found\nActiveState=inactive\n', ...patch }), false);
});
test('benchmark contract computes group goodput; rejects arbitrary fields, endpoints and counters', () => {
  const r = validateBenchmarkResult(good(request), request);
  assert.equal(r.status, 'passed'); assert.equal(r.download.mbps, 4 * 8388608 * 8 / 1e6 / 5.1);
  for (const patch of [{ token: 'stale' }, { phase: 'native' }, { exitAfter: '1.2.3.4' },
    { serverIp: 'payload' }, { secret: 'PRIVATE' }, { elapsedMs: 120001 }])
    assert.throws(() => validateBenchmarkResult({ ...good(request), ...patch }, request));
  for (const patch of [{ bytes: 8388609 }, { seconds: -1 }, { reason: 'PRIVATE' }, { httpStatus: 200.5 }, { payload: 'PRIVATE' }]) {
    const v = good(request); Object.assign(v.download.streams[0], patch);
    assert.throws(() => validateBenchmarkResult(v, request));
  }
});
test('only a verified bounded-time download may use partial bytes; upload timeout is failure', () => {
  const v = good(request); v.download.seconds = 20.1;
  Object.assign(v.download.streams[0], { code: 28, seconds: 20, bytes: 1000000 });
  assert.equal(validateBenchmarkResult(v, request).status, 'passed');
  for (const patch of [{ code: 7 }, { seconds: 3 }, { bytes: 0 }, { httpStatus: 0 },
    { tlsVerify: 60 }, { remoteIp: '1.2.3.4' }, { reason: 'timeout' }]) {
    const bad = structuredClone(v); Object.assign(bad.download.streams[0], patch);
    assert.equal(validateBenchmarkResult(bad, request).status, 'failed');
  }
  Object.assign(v.upload.streams[0], { code: 28, seconds: 30 }); v.upload.seconds = 30.1;
  assert.equal(validateBenchmarkResult(v, request).status, 'failed');
});
test('curl metrics are bounded and never include stderr/body', () => {
  assert.deepEqual(benchmarkMetrics({ code: 0, reason: null, out: `200 0 100 1048576 2.5 ${serverIp}` }, true),
    { code: 0, reason: null, httpStatus: 200, tlsVerify: 0, bytes: 1048576, seconds: 2.5, remoteIp: serverIp });
  for (const out of ['PRIVATE body', `200 0 9999999999 0 1 ${serverIp}`, `200 0 100 0 NaN ${serverIp}`]) {
    const r = benchmarkMetrics({ code: 0, reason: null, out }, false);
    assert.equal(r.reason, 'invalid_metrics'); assert.doesNotMatch(JSON.stringify(r), /PRIVATE|body|NaN/);
  }
});
test('Mac measures four concurrent pinned streams with bounded synthetic upload and verified exit', async () => {
  let clock = 0, concurrent = 0, peak = 0;
  const calls = [], options = { iface: 'en9', address: '192.168.7.19', now: () => clock, run: async (file, args, opts) => {
    calls.push({ file, args, inputBytes: opts?.input?.length });
    if (file === 'dig') return { code: 0, reason: null, out: `;; status: NOERROR,\nspeed.cloudflare.com. 60 IN A ${serverIp}` };
    assert.equal(args[0], '-q'); assert.ok(args.includes('en9') && args.includes('--noproxy') && args.includes('--http1.1'));
    assert.ok(!args.includes('-k') && !args.includes('--location'));
    if (args.at(-1).includes('cdn-cgi/trace')) return { code: 0, reason: null, out: `ip=${exit}\n` };
    assert.ok(args.includes(`speed.cloudflare.com:443:${serverIp}`));
    const upload = args.includes('--data-binary'), warm = args.at(-1).includes('262144');
    if (upload) { assert.ok(Buffer.isBuffer(opts.input)); assert.equal(opts.input.length, 1048576); assert.ok(args.includes('@-')); }
    if (!warm) { concurrent++; peak = Math.max(peak, concurrent); await new Promise(r => setImmediate(r)); concurrent--; }
    clock += 5000;
    return { code: 0, reason: null, out: `200 0 ${upload ? 0 : warm ? 262144 : 8388608} ${upload ? 1048576 : 0} 5 ${serverIp}` };
  } };
  const r = await probeBenchmark(request, options);
  assert.equal(validateBenchmarkResult(r, request).status, 'passed'); assert.equal(peak, 4);
  assert.equal(calls.filter(c => c.inputBytes === 1048576).length, 4);
  assert.equal(calls.filter(c => c.file === 'dig').length, 1); assert.equal(options.serverIp, serverIp);
  clock = 0; await probeBenchmark(request, options);
  assert.equal(calls.filter(c => c.file === 'dig').length, 1, 'same IP across phases/cycles');
  assert.ok(JSON.stringify(r).length < 4096);
});
test('failed pre-exit or warmup cannot upload or report usable measurements', async () => {
  for (const fail of ['exit', 'warmup']) {
    let uploads = 0;
    const r = await probeBenchmark(request, { iface: 'en9', address: '192.168.7.19', serverIp,
      run: async (f, args) => {
        if (args.includes('--data-binary')) uploads++;
        return { code: fail === 'warmup' && args.at(-1).includes('trace') ? 0 : 28, reason: null, out: `ip=${exit}\n` };
      } });
    assert.equal(uploads, 0); assert.equal(validateBenchmarkResult(r, request).status, 'failed');
  }
});
test('real curl HTTPS download/upload uses exact bounded bytes (local TLS fixture, no internet)', { timeout: 20000 }, async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-bench-https-'));
  t.after(() => fs.rmSync(dir, { recursive: true }));
  const key = path.join(dir, 'key.pem'), cert = path.join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
    '-days', '1', '-subj', '/CN=speed.cloudflare.com', '-addext', 'subjectAltName=DNS:speed.cloudflare.com'], { stdio: 'pipe' });
  let uploadBytes = 0, uploadRequests = 0, downloadBytes = 0;
  const server = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (req, res) => {
    const url = new URL(req.url, 'https://speed.cloudflare.com');
    if (url.pathname === '/__down') {
      const bytes = Number(url.searchParams.get('bytes')); downloadBytes += bytes;
      res.writeHead(200, { 'Content-Length': bytes }); res.end(Buffer.alloc(bytes));
    } else {
      assert.equal(url.pathname, '/__up'); assert.equal(req.method, 'POST');
      assert.equal(Number(req.headers['content-length']), 1048576); uploadRequests++;
      req.on('data', b => { uploadBytes += b.length; }); req.on('end', () => { res.writeHead(200); res.end('OK'); });
    }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); server.close(); });
  const r = await probeBenchmark(request, { iface: '127.0.0.1', address: '127.0.0.1', serverIp: '127.0.0.1',
    run: async (f, a, o) => {
      if (a.at(-1).includes('cdn-cgi/trace')) return { code: 0, reason: null, out: `ip=${exit}\n` };
      return execute(f, [...a, '--cacert', cert, '--connect-to', `speed.cloudflare.com:443:127.0.0.1:${server.address().port}`], o);
    } });
  const measured = validateBenchmarkResult(r, request);
  assert.equal(measured.status, 'passed', JSON.stringify(measured));
  assert.equal(uploadRequests, 4); assert.equal(uploadBytes, 4194304); assert.equal(downloadBytes, 33816576);
});
test('benchmark channel keeps nonce/deadline checks and accepts bounded samples', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-bench-peer-'));
  t.after(() => fs.rmSync(dir, { recursive: true }));
  const ip = '192.168.7.19'; let now = 0;
  const peer = createPeerChannel(dir, ip, { now: () => now, sleep: async () => {
    const p = peerStatus(dir, ip, () => now);
    const v = good({ token: p.token, phase: p.phase });
    assert.throws(() => submitPeerResult(dir, ip, { ...v, token: request.token }, () => now));
    submitPeerResult(dir, ip, v, () => now); now += 100;
  } });
  const phases = {}; await peer.phase('bench-native', phases);
  assert.equal(phases['bench-native'].status, 'passed');
});
test('proc stat parser handles spaces/parentheses; refuses unsafe PID', () => {
  const fields = Array(30).fill('0'); fields[0] = 'S'; fields[11] = '100'; fields[12] = '20'; fields[19] = '999';
  const read = file => file.endsWith('/stat') ? `123 (name ) with spaces) ${fields.join(' ')}`
    : file.endsWith('/status') ? 'VmRSS:\t1024 kB\n' : '124 125';
  assert.deepEqual(readProcess(123, read), { ticks: 120, start: 999, rssKiB: 1024, children: [124, 125] });
  assert.throws(() => readProcess('../secret', read));
});
test('CPU sums root plus children, keys by process start, rejects root reuse and keeps clear units', () => {
  let tick = 0, clock = 0, callback, cancelled = false;
  const stop = sampleTrialCpu(100, 100, { now: () => clock,
    every: (fn, ms) => { assert.equal(ms, 250); callback = fn; return 1; }, cancel: () => { cancelled = true; },
    read: pid => ({ start: pid, ticks: tick * (pid === 100 ? 1 : 2), rssKiB: 1024, children: pid === 100 ? [101] : [] }) });
  tick = 50; clock = 1000; callback(); tick = 100; clock = 2000;
  const r = stop(); assert.equal(cancelled, true); assert.equal(r.cpuSeconds, 3); assert.equal(r.meanOneCorePercent, 150);
  assert.equal(r.peakRssKiB, 2048); assert.equal(r.processPeak, 2);
  let start = 100;
  const bad = sampleTrialCpu(100, 100, { now: () => clock, every: () => 1, cancel: () => {},
    read: () => ({ start, ticks: 1, rssKiB: 1, children: [] }) });
  clock++; start++; assert.equal(bad().status, 'incomplete');
});
function reports() {
  return Array.from({ length: 3 }, () => ({ status: 'passed', rollback: 'verified', guard: 'verified',
    usb: { status: 'passed', phases: Object.fromEntries(benchmarkPhases.map(phase => [phase,
      { ...validateBenchmarkResult(good({ ...request, phase }), { ...request, phase }),
        cpu: { status: 'sampled', meanOneCorePercent: 50, peakRssKiB: 1000 } }])) } }));
}
test('comparison retains all baselines and paired ratios, never declares a winner', () => {
  const r = summarizeBenchmarks(reports()); assert.equal(r.status, 'completed'); assert.equal(r.rows.length, 9);
  assert.equal(r.statistics.legacy.downloadMbps.count, 6); assert.equal(r.statistics.native.downloadMbps.count, 3);
  assert.equal(r.paired[0].download.nativeToLegacyRatio, 1);
  assert.equal(summarizeBenchmarks(reports().slice(0, 2)).status, 'incomplete');
  const a = reports(); a[1].rollback = 'manual-review-required';
  assert.equal(summarizeBenchmarks(a).paired.length, 0);
  const b = reports(); b[1].usb.phases['bench-native'].serverIp = '1.1.1.1';
  assert.equal(summarizeBenchmarks(b).status, 'incomplete');
  for (const corrupt of [r => { r.usb.status = 'failed'; },
    r => { r.usb.phases['bench-native'].cpu.status = 'incomplete'; }]) {
    const invalid = reports(); corrupt(invalid[0]);
    assert.equal(summarizeBenchmarks(invalid).status, 'incomplete');
    assert.equal(summarizeBenchmarks(invalid).paired.length, 0);
  }
  const c = reports(); c[0].usb.phases['bench-restored'].download.mbps *= 2;
  assert.ok(summarizeBenchmarks(c).warnings.includes('legacy-baseline-varies-over-25-percent'));
});
test('CPU parser reads the actual Linux process without changing it', t => {
  if (process.platform !== 'linux') return t.skip('Linux /proc required');
  const p = readProcess(process.pid);
  assert.ok(p.start > 0 && p.ticks >= 0 && p.rssKiB > 0);
  assert.ok(Array.isArray(p.children));
});
