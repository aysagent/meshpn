#!/usr/bin/env node
// Standalone Mac coordinator: copy THIS file only. No packet IPC or Mac setup.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { isIPv4, isIPv6 } from 'node:net';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { randomBytes } from 'node:crypto';

const EXIT = '154.62.226.216', GATEWAY = '192.168.7.1';
const SCRIPT = '/root/dev/meshpn/scripts/clean-vpn-native-trial.mjs';
const check = (ok, code) => { if (!ok) throw Error(code); };
export const quote = s => "'" + s.replaceAll("'", "'\\''") + "'";
export function execute(file, args, { timeout = 15000, input, onOutput = () => {} } = {}) {
  return new Promise(resolve => {
    const child = spawn(file, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', reason = null, bytes = 0;
    const timer = setTimeout(() => { reason = 'timeout'; child.kill('SIGKILL'); }, timeout);
    for (const [stream, retain] of [[child.stdout, true], [child.stderr, false]]) stream.on('data', b => {
      bytes += b.length;
      if (bytes > 1024 * 1024) { reason = 'output_limit'; child.kill('SIGKILL'); }
      else if (retain) { out += b; onOutput(out); }
    });
    child.on('error', () => { reason = 'spawn_failed'; });
    child.stdin.on('error', () => {});
    child.stdin.end(input);
    child.on('close', code => { clearTimeout(timer); resolve({ code, out, reason }); });
  });
}
const ok = r => r.code === 0 && !r.reason;
export function trialUnitFinished(r) {
  if (r.reason || ![0, 1, 4].includes(r.code)) return false;
  const lines = r.out.trim().split(/\r?\n/);
  if (lines.length !== 2 || new Set(lines.map(l => l.split('=')[0])).size !== 2) return false;
  const props = Object.fromEntries(lines.map(l => l.split('=')));
  // --collect may unload the unit before the next poll. A missing unit is
  // acceptable only with explicit systemd properties, never an SSH failure.
  return (props.LoadState === 'not-found' && props.ActiveState === 'inactive')
    || (r.code === 0 && props.LoadState === 'loaded' && ['inactive', 'failed'].includes(props.ActiveState));
}
export function dnsAddresses(r, type) {
  if (!ok(r) || !/status: NOERROR,/.test(r.out)) return [];
  return r.out.split('\n').flatMap(line => {
    const f = line.trim().split(/\s+/);
    return f[3] === type && (type === 'A' ? isIPv4(f[4]) : isIPv6(f[4])) ? [f[4]] : [];
  });
}
export async function probePeer(request, { iface, address, run = execute, now = () => performance.now(), sleep = delay }) {
  const began = now();
  const result = { token: request.token, phase: request.phase, dnsPassed: 0, httpsPassed: 0,
    downloadBytes: 0, exitIp: null, blockedAttempts: 0, recoveryMs: 0, elapsedMs: 0 };
  const curl = ['-q', '-4', '-sS', '--noproxy', '*', '--interface', iface,
    '--connect-timeout', '3', '--max-time', '5'];
  const trace = () => run('curl', [...curl, '--fail', 'https://1.1.1.1/cdn-cgi/trace'], { timeout: 6500 });
  const traceOk = r => ok(r) && r.out.split(/\r?\n/).includes(`ip=${EXIT}`);
  const dns = (name, type, tcp) => run('dig', ['-4', '-b', address, `@${GATEWAY}`, name, type,
    '+time=2', '+tries=1', '+noall', '+comments', '+answer', ...(tcp ? ['+tcp'] : [])], { timeout: 4000 });
  if (request.phase === 'blocked') {
    for (let i = 0; i < 2; i++) {
      const r = await trace();
      // A missing command, wrong interface or TLS error is NOT evidence of blocking.
      if ([7, 28].includes(r.code) && !r.reason) result.blockedAttempts++;
    }
  } else {
    let recovered = request.phase !== 'recovered';
    if (!recovered) {
      while (now() - began < 55000) {
        if (traceOk(await trace())) { recovered = true; break; }
        await sleep(1000);
      }
      result.recoveryMs = Math.min(60000, Math.round(now() - began));
    }
    if (recovered) {
      for (const type of ['A', 'AAAA']) for (const tcp of [false, true])
        if (dnsAddresses(await dns('example.com', type, tcp), type).length) result.dnsPassed++;
      for (let i = 0; i < 3; i++) if (traceOk(await trace())) { result.httpsPassed++; result.exitIp = EXIT; }
      const ips = dnsAddresses(await dns('speed.cloudflare.com', 'A', false), 'A');
      if (ips.length) {
        const r = await run('curl', [...curl, '--max-time', '20', '--fail', '--output', '/dev/null',
          '--resolve', `speed.cloudflare.com:443:${ips[0]}`, '--max-filesize', '1048576',
          '--write-out', '%{http_code} %{size_download} %{ssl_verify_result}',
          'https://speed.cloudflare.com/__down?bytes=1048576'], { timeout: 22000 });
        if (ok(r) && /^200 1048576 0\s*$/.test(r.out)) result.downloadBytes = 1048576;
      }
    }
  }
  result.elapsedMs = Math.min(120000, Math.round(now() - began));
  return result;
}

export function benchmarkMetrics(result, upload) {
  const fields = result.out.trim().split(/\s+/), numbers = fields.slice(0, 5).map(Number);
  const valid = fields.length === 6 && numbers.every(n => Number.isFinite(n) && n >= 0)
    && Number.isInteger(numbers[0]) && numbers[0] <= 599 && Number.isInteger(numbers[1]) && numbers[1] <= 1000
    && numbers[4] <= 32 && isIPv4(fields[5]);
  const bytes = numbers[upload ? 3 : 2];
  if (!valid || !Number.isSafeInteger(bytes) || bytes > (upload ? 1048576 : 8388608))
    return { code: result.code, reason: result.reason ?? 'invalid_metrics', httpStatus: 0,
      tlsVerify: 0, bytes: 0, seconds: 0, remoteIp: null };
  return { code: result.code, reason: result.reason, httpStatus: numbers[0], tlsVerify: numbers[1],
    bytes, seconds: numbers[4], remoteIp: fields[5] };
}

export async function probeBenchmark(request, options) {
  const { iface, address, run = execute, now = () => performance.now() } = options;
  const began = now(), result = { token: request.token, phase: request.phase, exitBefore: null, exitAfter: null,
    serverIp: options.serverIp ?? null, warmup: false, download: { seconds: 0, streams: [] },
    upload: { seconds: 0, streams: [] }, elapsedMs: 0 };
  const base = ['-q', '-4', '-sS', '--noproxy', '*', '--interface', iface, '--http1.1', '--connect-timeout', '5'];
  const trace = async () => {
    const r = await run('curl', [...base, '--max-time', '5', '--fail', 'https://1.1.1.1/cdn-cgi/trace'], { timeout: 6500 });
    return ok(r) && r.out.split(/\r?\n/).includes(`ip=${EXIT}`) ? EXIT : null;
  };
  result.exitBefore = await trace();
  if (result.exitBefore) {
    if (!result.serverIp) {
      const r = await run('dig', ['-4', '-b', address, `@${GATEWAY}`, 'speed.cloudflare.com', 'A',
        '+time=2', '+tries=1', '+noall', '+comments', '+answer'], { timeout: 4000 });
      result.serverIp = dnsAddresses(r, 'A')[0] ?? null;
      // One resolved IP for all nine phases. Anycast routing can still vary.
      options.serverIp = result.serverIp;
    }
    if (result.serverIp) {
      check(isIPv4(result.serverIp), 'invalid_benchmark_server');
      const args = [...base, '--resolve', `speed.cloudflare.com:443:${result.serverIp}`,
        '--fail', '--output', '/dev/null', '--header', 'Accept-Encoding: identity',
        '--header', 'Cache-Control: no-cache', '--write-out',
        '%{http_code} %{ssl_verify_result} %{size_download} %{size_upload} %{time_total} %{remote_ip}'];
      const warm = benchmarkMetrics(await run('curl', [...args, '--max-time', '8', '--max-filesize', '262144',
        'https://speed.cloudflare.com/__down?bytes=262144'], { timeout: 9500 }), false);
      result.warmup = warm.code === 0 && !warm.reason && warm.httpStatus === 200
        && warm.tlsVerify === 0 && warm.bytes === 262144 && warm.remoteIp === result.serverIp;
      if (result.warmup) {
        for (const upload of [false, true]) {
          const groupBegan = now(), input = upload ? randomBytes(1048576) : undefined;
          const streams = await Promise.all(Array.from({ length: 4 }, async () => benchmarkMetrics(await run('curl',
            [...args, '--max-time', upload ? '30' : '20', '--max-filesize', upload ? '65536' : '8388608',
              ...(upload ? ['--header', 'Expect:', '--header', 'Content-Type: application/octet-stream', '--data-binary', '@-',
                'https://speed.cloudflare.com/__up'] : ['https://speed.cloudflare.com/__down?bytes=8388608'])],
            { timeout: upload ? 32000 : 22000, input }), upload)));
          result[upload ? 'upload' : 'download'] = { seconds: (now() - groupBegan) / 1000, streams };
        }
      }
      result.exitAfter = await trace();
    }
  }
  result.elapsedMs = Math.min(120000, Math.round(now() - began));
  return result;
}

export function summarizeBenchmarks(reports) {
  const median = values => { const a = [...values].sort((x, y) => x - y), n = a.length;
    return n ? (a[Math.floor((n - 1) / 2)] + a[Math.floor(n / 2)]) / 2 : null; };
  const rows = reports.flatMap((r, i) => ['bench-old', 'bench-native', 'bench-restored'].flatMap(phase => {
    const p = r.usb?.phases?.[phase];
    return p ? [{ cycle: i + 1, phase, implementation: phase === 'bench-native' ? 'native' : 'legacy',
      status: p.status, serverIp: p.serverIp, downloadMbps: p.download?.mbps ?? null, uploadMbps: p.upload?.mbps ?? null,
      cpuStatus: p.cpu?.status ?? 'missing',
      cpuMeanOneCorePercent: p.cpu?.meanOneCorePercent ?? null, peakRssKiB: p.cpu?.peakRssKiB ?? null,
      shortSample: !!(p.download?.shortSample || p.upload?.shortSample) }] : [];
  }));
  const complete = reports.length === 3 && reports.every(r => r.status === 'passed' && r.usb?.status === 'passed'
    && r.rollback === 'verified' && r.guard === 'verified')
    && rows.length === 9 && rows.every(r => r.status === 'passed' && r.cpuStatus === 'sampled' && isIPv4(r.serverIp)
      && [r.downloadMbps, r.uploadMbps, r.cpuMeanOneCorePercent]
      .every(n => Number.isFinite(n) && n >= 0)) && new Set(rows.map(r => r.serverIp)).size === 1;
  const statistics = implementation => Object.fromEntries(['downloadMbps', 'uploadMbps', 'cpuMeanOneCorePercent', 'peakRssKiB'].map(key => {
    const values = rows.filter(r => r.implementation === implementation && r.status === 'passed').map(r => r[key]).filter(Number.isFinite);
    return [key, { count: values.length, median: median(values), min: values.length ? Math.min(...values) : null, max: values.length ? Math.max(...values) : null }];
  }));
  const paired = complete ? reports.map((r, i) => {
    const p = r.usb.phases;
    return { cycle: i + 1, ...Object.fromEntries(['download', 'upload'].map(key => {
      const a = p['bench-old'][key].mbps, b = p['bench-restored'][key].mbps;
      return [key, { nativeToLegacyRatio: a + b > 0 ? p['bench-native'][key].mbps / ((a + b) / 2) : null,
        legacyBeforeAfterRatio: Math.min(a, b) > 0 ? Math.max(a, b) / Math.min(a, b) : null }];
    })) };
  }) : [];
  return { schema: 1, kind: 'clean-vpn-internet-comparison', status: complete ? 'completed' : 'incomplete',
    endpoint: 'speed.cloudflare.com', parallelStreams: 4, requestedCycles: 3, completedReports: reports.length,
    rows, statistics: { legacy: statistics('legacy'), native: statistics('native') }, paired,
    warnings: [...(!complete ? ['incomplete-no-comparison-verdict'] : []),
      ...(rows.some(r => r.shortSample) ? ['some-transfers-under-3s-startup-overhead-significant'] : []),
      ...(paired.some(p => ['download', 'upload'].some(k => p[k].legacyBeforeAfterRatio > 1.25)) ? ['legacy-baseline-varies-over-25-percent'] : [])],
    limitations: ['not-ookla-or-line-rate', 'one-anycast-IP-not-guaranteed-same-POP', 'client-CPU-includes-warmup-and-RPC-not-kernel-or-exit',
      'network-variation-not-controlled', 'existing-legacy-exit-unchanged'], reports };
}

export async function main(args = process.argv.slice(2)) {
  if (args.length === 1 && args[0] === '--help') {
    console.log('--benchmark: three legacy/native/legacy cycles, four HTTPS streams, synthetic upload, <=340 MiB total application data. No uplink/crash fault. Not Ookla.');
    console.log('Usage on Mac: node clean-vpn-native-usb-check.mjs --interface=en9 [--crash | --benchmark] [--combo-profile=/absolute/path/on/radxa.json]\nDefault: real wlan0 down/up on Radxa. --crash: SIGKILL native engine, keep uplink up, capture selected IPv4 HTTPS egress; requires tcpdump on Radxa.\nCombo profile path is evaluated on Radxa and must be a root-owned private file.\nUSB rescue SSH :2222 remains available. Requires Node 18+, ssh, curl, dig and a current built Radxa checkout at /root/dev/meshpn.\nNo Mac settings change. Without --benchmark: up to seven 1 MiB downloads; functional checks, not a speed benchmark. No mode is comprehensive leak acceptance.'); return;
  }
  console.log('[usb-check] Проверяю окружение Mac и USB-интерфейс');
  check(process.platform === 'darwin', 'run_on_mac');
  const interfaceArgs = args.filter(value => /^--interface=[a-zA-Z0-9]{1,15}$/.test(value));
  const modeArgs = args.filter(value => ['--crash', '--benchmark'].includes(value));
  const comboArgs = args.filter(value => value.startsWith('--combo-profile='));
  check(interfaceArgs.length === 1 && modeArgs.length <= 1 && comboArgs.length <= 1
    && interfaceArgs.length + modeArgs.length + comboArgs.length === args.length, 'invalid_usb_check_options');
  const crash = modeArgs[0] === '--crash', benchmark = modeArgs[0] === '--benchmark';
  const comboProfile = comboArgs[0] ?? null, iface = interfaceArgs[0].split('=')[1];
  const addresses = (os.networkInterfaces()[iface] ?? []).filter(a => a.family === 'IPv4'
    && /^192\.168\.7\./.test(a.address) && !['0', '1', '255'].includes(a.address.split('.')[3]));
  check(addresses.length === 1, 'usb_ipv4_required');
  const address = addresses[0].address;
  const route = await execute('route', ['-n', 'get', GATEWAY]);
  check(ok(route) && new RegExp(`interface: ${iface}(?:\\s|$)`).test(route.out), 'usb_gateway_route_required');
  for (const [file, flag] of [['ssh', '-V'], ['curl', '--version'], ['dig', '-v']])
    check(ok(await execute(file, [flag])), `missing_${file}`);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-usb-'));
  fs.chmodSync(dir, 0o700);
  const socket = path.join(dir, 'ssh');
  const base = ['-4', '-p', '2222', '-b', address, '-S', socket,
    '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes', '-o', 'ConnectTimeout=5',
    '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none',
    '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=3'];
  const target = `root@${GATEWAY}`;
  let interrupted = false;
  const interrupt = () => { interrupted = true; };
  process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);
  try {
    console.log(benchmark
      ? 'USB benchmark: 3 цикла legacy/native/legacy, download/upload в 4 потока, CPU Radxa. До 340 MiB тестовых данных; обычно 5–10 минут. Не скачивай другое во время замера.'
      : crash
      ? 'USB crash trial: SIGKILL native-движка, wlan0 остаётся включён. Проверка блокировки IPv4 HTTPS и возврат старого VPN по журналам владения.'
      : 'USB trial: реальный обрыв wlan0; старый VPN будет восстановлен автоматически после проверок.');
    // Authenticate once; known-host checks remain enabled. Later RPCs use this socket.
    const auth = await new Promise(resolve => {
      const child = spawn('ssh', [...base, '-M', '-N', '-f', '-o', 'ControlPersist=60', target], { stdio: 'inherit' });
      child.on('error', () => resolve(1)); child.on('close', resolve);
    });
    check(auth === 0 && !interrupted, 'ssh_authentication_failed');
    const ssh = (cmd, options) => execute('ssh', [...base, '-o', 'BatchMode=yes', target, cmd], options);
    // Discover the running service's Node executable (works with root NVM).
    const nodeResult = await ssh('readlink /proc/"$(systemctl show clean-vpn.service -p MainPID --value)"/exe');
    const node = nodeResult.out.trim();
    check(ok(nodeResult) && /^\/[a-zA-Z0-9_./-]+\/node$/.test(node), 'running_legacy_node_required');
    const cmd = params => [node, SCRIPT, ...params].map(quote).join(' ');
    const reports = [], benchmarkOptions = { iface, address };
    for (let cycle = 0; cycle < (benchmark ? 3 : 1); cycle++) {
      check(!interrupted, 'observer_interrupted');
      if (cycle > 0) {
        let idle = false;
        for (let attempt = 0; attempt < 15 && !interrupted; attempt++) {
          const r = await ssh('systemctl show clean-vpn-native-trial.service -p ActiveState -p LoadState');
          if (trialUnitFinished(r)) { idle = true; break; }
          await delay(1000);
        }
        check(idle && !interrupted, 'previous_trial_not_finished');
      }
      if (benchmark) console.log(`[usb-check] цикл ${cycle + 1}/3`);
      let runId, finished;
      const job = ssh(cmd(['--apply', benchmark ? '--usb-benchmark' : crash ? '--usb-crash' : '--usb-peer',
        ...(comboProfile ? [comboProfile] : [])]), { timeout: 1600000, onOutput: out => {
        const match = /^USB_TRIAL_ID=(run-[a-zA-Z0-9]+)$/m.exec(out); if (match) runId = match[1];
      } }).then(r => { finished = r; return r; });
      const seen = new Set();
      try {
        while (!finished) {
          check(!interrupted, 'observer_interrupted');
          if (runId) {
            const r = await ssh(cmd(['--peer-status', runId]));
            check(ok(r), 'peer_status_failed');
            const p = JSON.parse(r.out);
            if (p.status === 'probe' && !seen.has(p.token)) {
              check((benchmark ? ['bench-old', 'bench-native', 'bench-restored'] : ['baseline', 'native', 'blocked', 'recovered', 'restored']).includes(p.phase)
                && /^[a-f0-9-]{36}$/.test(p.token), 'invalid_peer_request');
              seen.add(p.token); console.log(`[usb-check] ${p.phase}`);
              const result = benchmark ? await probeBenchmark(p, benchmarkOptions) : await probePeer(p, { iface, address });
              check(!interrupted, 'observer_interrupted');
              const sent = await ssh(cmd(['--peer-result', runId]), { input: JSON.stringify(result) });
              check(ok(sent), 'peer_result_not_accepted');
            }
          }
          await delay(500);
        }
        const r = await job;
        const m = /=== CLEAN-VPN NATIVE TRIAL BEGIN ===\s*([\s\S]+?)\s*=== CLEAN-VPN NATIVE TRIAL END ===/.exec(r.out);
        check(m, 'trial_report_missing');
        const report = JSON.parse(m[1]);
        reports.push(report);
        if (benchmark) {
          if (!ok(r) || report.status !== 'passed' || report.rollback !== 'verified' || report.guard !== 'verified') break;
        } else {
          console.log('=== CLEAN-VPN USB CHECK BEGIN ==='); console.log(JSON.stringify(report, null, 2));
          console.log('=== CLEAN-VPN USB CHECK END ===');
          process.exitCode = ok(r) && report.status === 'passed' && report.usb?.status === 'passed' ? 0 : 1;
        }
      } catch (e) {
        // Closing SSH below ends only the observer. The systemd worker continues
        // bounded waits and audited rollback; the uplink unit has its own deadline.
        console.error('Radxa продолжает восстановление. Через USB SSH: node scripts/clean-vpn-native-trial.mjs --report');
        throw e;
      }
    }
    if (benchmark) {
      const result = summarizeBenchmarks(reports);
      console.log('=== CLEAN-VPN BENCHMARK BEGIN ==='); console.log(JSON.stringify(result, null, 2));
      console.log('=== CLEAN-VPN BENCHMARK END ===');
      process.exitCode = result.status === 'completed' ? 0 : 1;
    }
  } finally {
    await execute('ssh', [...base, '-O', 'exit', target], { timeout: 5000 });
    process.off('SIGINT', interrupt); process.off('SIGTERM', interrupt);
    try { fs.unlinkSync(socket); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    fs.rmdirSync(dir);
  }
}
// A copied standalone file may be reached through a platform/container mount
// alias. The unique entry basename survives that remapping; imports from the
// test/application entry have a different basename and do not execute main.
const entryFile = import.meta.main === true
  || process.argv[1] && path.basename(process.argv[1]) === path.basename(fileURLToPath(import.meta.url));
if (entryFile)
  main().catch(e => { console.error(JSON.stringify({ status: 'failed', code: /^[a-z0-9_]+$/.test(e.message) ? e.message : 'usb_check_failed' })); process.exitCode = 1; });
