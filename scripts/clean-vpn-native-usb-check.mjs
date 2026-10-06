#!/usr/bin/env node
// Standalone Mac coordinator: copy THIS file only. No packet IPC or Mac setup.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { isIPv4, isIPv6 } from 'node:net';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

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

export async function main(args = process.argv.slice(2)) {
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage on Mac: node clean-vpn-native-usb-check.mjs --interface=en9 [--crash]\nDefault: real wlan0 down/up on Radxa. --crash: SIGKILL native engine, keep uplink up, capture selected IPv4 HTTPS egress; requires tcpdump on Radxa.\nUSB rescue SSH :2222 remains available. Requires Node 18+, ssh, curl, dig and a current built Radxa checkout at /root/dev/meshpn.\nNo Mac settings change. Up to seven 1 MiB downloads. Not comprehensive leak acceptance or a benchmark.'); return;
  }
  console.log('[usb-check] Проверяю окружение Mac и USB-интерфейс');
  check(process.platform === 'darwin', 'run_on_mac');
  const crash = args.length === 2 && args[1] === '--crash';
  check((args.length === 1 || crash) && /^--interface=[a-zA-Z0-9]{1,15}$/.test(args[0]), 'specify_usb_interface');
  const iface = args[0].split('=')[1];
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
    console.log(crash
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
    let runId, finished;
    const job = ssh(cmd(['--apply', crash ? '--usb-crash' : '--usb-peer']), { timeout: 1600000, onOutput: out => {
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
            check(['baseline', 'native', 'blocked', 'recovered', 'restored'].includes(p.phase)
              && /^[a-f0-9-]{36}$/.test(p.token), 'invalid_peer_request');
            seen.add(p.token); console.log(`[usb-check] ${p.phase}`);
            const result = await probePeer(p, { iface, address });
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
      console.log('=== CLEAN-VPN USB CHECK BEGIN ==='); console.log(JSON.stringify(report, null, 2));
      console.log('=== CLEAN-VPN USB CHECK END ===');
      process.exitCode = ok(r) && report.status === 'passed' && report.usb?.status === 'passed' ? 0 : 1;
    } catch (e) {
      // Closing SSH below ends only the observer. The systemd worker continues
      // bounded waits and audited rollback; the uplink unit has its own deadline.
      console.error('Radxa продолжает восстановление. Через USB SSH: node scripts/clean-vpn-native-trial.mjs --report');
      throw e;
    }
  } finally {
    await execute('ssh', [...base, '-O', 'exit', target], { timeout: 5000 });
    process.off('SIGINT', interrupt); process.off('SIGTERM', interrupt);
    try { fs.unlinkSync(socket); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    fs.rmdirSync(dir);
  }
}
// Node resolves the entry module's symlinks, but argv retains the supplied
// path. On macOS /tmp is a symlink to /private/tmp.
if (process.argv[1] && (import.meta.url === pathToFileURL(process.argv[1]).href
    || import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href))
  main().catch(e => { console.error(JSON.stringify({ status: 'failed', code: /^[a-z0-9_]+$/.test(e.message) ? e.message : 'usb_check_failed' })); process.exitCode = 1; });
