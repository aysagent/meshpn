#!/usr/bin/env node
/** One-shot Radxa trial, managed by a TRANSIENT systemd unit. No installation. */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { deriveTrialConfig, summarizeTrialProbe, hasUsbRescueConnection, requireTrial as check, runTrial } from './lib/native-radxa-trial.mjs';
import { inspectBlockedTrialIpv6, validateReleasedTrialIpv6 } from './lib/native-trial-ipv6.mjs';
import { trialServiceFingerprint } from './lib/native-trial-service.mjs';
import { trialDiagnostics } from './lib/native-trial-diagnostics.mjs';
import { waitLegacyReady } from './lib/native-trial-readiness.mjs';
import { probeNativeHold } from './lib/native-trial-hold.mjs';
import { createPeerChannel, exerciseNativePeer, peerStatus, submitPeerResult } from './lib/native-usb-trial-peer.mjs';
import { faultUnit, faultUnitArgs } from './clean-vpn-native-usb-uplink.mjs';
import { startCrashCapture, exerciseCrashPeer, recoverCrashNetwork } from './lib/native-trial-crash.mjs';
import { openHostRoutes } from './lib/vpn-host-routes.mjs';
import { openTunnelDnsJournal } from './lib/dns-tunnel-journal.mjs';
import { benchmarkPhases, sampleTrialCpu } from './lib/native-trial-benchmark.mjs';

const SELF = fileURLToPath(import.meta.url), ROOT = path.dirname(path.dirname(SELF));
const UNIT = 'clean-vpn-native-trial.service', OLD = 'clean-vpn.service';
const REPORTS = '/var/lib/clean-vpn-native-trial';
const ENV = { PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' };
const ENGINE = path.join(ROOT, 'native/clean_vpn/build/clean-vpn-engine');
const sleep = () => delay(250);
const safeCode = e => /^[a-z0-9_]{1,100}$/.test(e.message) ? e.message : 'operation_failed';

// Never print subprocess errors: they can contain configuration/credentials.
async function command(file, args, timeout = 10000, limit = 2 * 1024 * 1024) {
  return await new Promise(resolve => {
    const child = spawn(file, args, { cwd: ROOT, env: ENV, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', bytes = 0, reason = null;
    const timer = setTimeout(() => { reason = 'timeout'; child.kill('SIGKILL'); }, timeout);
    for (const [stream, retain] of [[child.stdout, true], [child.stderr, false]]) stream.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > limit) { reason = 'output_limit'; child.kill('SIGKILL'); }
      else if (retain) out += chunk.toString();
    });
    child.on('error', () => { reason = 'spawn_failed'; });
    child.on('close', code => { clearTimeout(timer); resolve({ code, out, reason }); });
  });
}
async function run(file, args, timeout) {
  const r = await command(file, args, timeout);
  check(r.code === 0 && !r.reason, `command_${path.basename(file).replace(/[^a-z0-9_]/g, '_')}_${r.reason ?? 'failed'}`);
  return r.out.trim();
}
const system = (...args) => run('systemctl', args);
const node = (script, args = [], timeout) => run(process.execPath, [path.join(ROOT, 'scripts', script), ...args], timeout);
const prop = (unit, property) => system('show', unit, `--property=${property}`, '--value');
async function links() { return JSON.parse(await run('ip', ['-j', 'address', 'show'])); }
async function requireNoTun() { check(!(await links()).some(l => l.ifname === 'tun0'), 'tun0_still_present'); }
function privateDirectory(dir) {
  try { fs.mkdirSync(dir, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  const s = fs.lstatSync(dir);
  check(s.isDirectory() && !s.isSymbolicLink() && s.uid === 0 && (s.mode & 0o777) === 0o700, 'unsafe_report_directory');
}
function writeJson(file, data) {
  const tmp = file + '.' + randomUUID() + '.new';
  try {
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    fs.renameSync(tmp, file);
  } finally {
    try { fs.unlinkSync(tmp); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
}
async function hostRequired() {
  check(process.platform === 'linux' && process.getuid?.() === 0, 'linux_root_required');
  check(fs.readFileSync('/proc/1/comm', 'utf8').trim() === 'systemd', 'systemd_required');
  check(fs.readlinkSync('/proc/self/ns/net') === fs.readlinkSync('/proc/1/ns/net'), 'host_namespace_required');
}
async function verifyGuard() {
  const output = await run('/usr/local/bin/clean-vpn-killswitch.sh', ['status']);
  for (const family of [4, 6]) check(output.includes(`IPv${family}: cvks4:both:block:tun0:154.62.226.216:22`), 'guard_profile_mismatch');
  for (const unit of ['clean-vpn-killswitch.service', 'clean-vpn-usb-rescue.socket', 'clean-vpn-usb-rescue-address.service'])
    check(await system('is-active', unit) === 'active', 'rescue_or_guard_inactive');
}
async function snatReady() {
  const report = JSON.parse(await run(process.execPath, ['/usr/local/bin/clean-vpn-usb-snat.mjs', '--status'], 90000));
  check(report.status === 'ready' && report.mss?.present === 2, 'snat_mss_not_ready');
}
async function auditReleased() {
  const h = JSON.parse(await node('clean-vpn-host-recover.mjs', [], 90000));
  check(h.stage === 'released' && h.routes === 0 && h.rpFilterPending === false, 'host_journal_not_released');
  const d = JSON.parse(await node('clean-vpn-dns-recover.mjs', [], 90000));
  check(d.stage === 'released' && d.operations === 0 && d.hold === 0, 'dns_journal_not_released');
}
async function probe() {
  const r = await command(process.execPath, [path.join(ROOT, 'scripts/clean-vpn-client-check.mjs'),
    '--probe', '--expect-exit-ip=154.62.226.216'], 100000);
  const match = /=== CLEAN-VPN CLIENT CHECK BEGIN ===\s*([\s\S]+?)\s*=== CLEAN-VPN CLIENT CHECK END ===/.exec(r.out);
  check(match && !r.reason, 'probe_report_missing');
  const data = JSON.parse(match[1]);
  // The client checker already strips response bodies and credentials. Omit
  // interface addresses, route dumps and arbitrary tool output from this report.
  return summarizeTrialProbe(data, r.code);
}

export function launchTrialNative(config, { spawnChild = spawn, readyMs = 45000, stopMs = 240000, trialCrash = false } = {}) {
  const child = spawnChild(process.execPath, [path.join(ROOT, 'scripts/clean-vpn-native.mjs'), '--config', config, '--usb-profile', ...(trialCrash ? ['--trial-crash'] : [])],
    { cwd: ROOT, env: ENV, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let ended = false, code, signal, statusReady = false, dnsReady = false, bytes = 0, stdout = '', stderr = '', broken = false;
  const diagnostics = trialDiagnostics();
  let crashRequested = false, killed = false;
  let stdoutBytes = 0, stderrBytes = 0;
  child.stdin.on('error', () => { broken = true; });
  child.on('error', () => { broken = true; });
  child.on('close', (c, s) => { ended = true; code = c; signal = s; });
  for (const [stream, kind] of [[child.stdout, 'out'], [child.stderr, 'err']]) {
    stream.setEncoding('utf8');
    stream.on('data', chunk => {
      bytes += Buffer.byteLength(chunk);
      if (kind === 'out') stdoutBytes += Buffer.byteLength(chunk); else stderrBytes += Buffer.byteLength(chunk);
      if (bytes > 256 * 1024) { broken = true; return; }
      if (kind === 'out') {
        stdout += chunk;
        let at;
        while ((at = stdout.indexOf('\n')) >= 0) {
          const line = stdout.slice(0, at); stdout = stdout.slice(at + 1);
          try { statusReady = diagnostics.state(JSON.parse(line)) === 'ready'; } catch { broken = true; }
        }
      } else {
        stderr += chunk;
        let at;
        while ((at = stderr.indexOf('\n')) >= 0) {
          const line = stderr.slice(0, at); stderr = stderr.slice(at + 1);
          if (line === 'native-control: engine exited code=null signal=SIGKILL') killed = true;
          if (diagnostics.stderrLine(line) === 'dns_active') dnsReady = true;
        }
        if (stderr.length > 4096) { stderr = ''; broken = true; }
      }
    });
  }
  return {
    diagnostics: () => ({ ...diagnostics.snapshot(), dnsReady, statusReady, ended, broken,
      exitCode: Number.isInteger(code) ? code : null, signal: signal ?? null, stdoutBytes, stderrBytes,
      ...(trialCrash ? { crashRequested, engineSigkillSeen: killed } : {}) }),
    healthy: () => !ended && !broken,
    metricsRootPid: () => child.pid,
    crashRequested: () => crashRequested,
    async crash() {
      check(trialCrash && !ended && !broken && !crashRequested, 'trial_crash_not_allowed');
      crashRequested = true;
      child.stdin.write('{"op":"trial_crash"}\n');
      const deadline = performance.now() + 15000;
      while (!ended && performance.now() < deadline) await sleep();
      check(ended && killed && code === 1 && !signal && !broken, 'native_crash_not_verified');
    },
    async ready(cancelled) {
      const deadline = performance.now() + readyMs;
      while (performance.now() < deadline) {
        check(!cancelled(), 'cancelled');
        check(!ended && !broken, 'native_start_failed');
        // ready -> END_STREAM -> idle_wait can arrive in one pipe read, or
        // during DNS activation. Lazy idle is ready for the active smoke probe
        // to wake it; waiting for another ready without traffic deadlocks.
        // Historical ready alone must not accept errors/waiting_uplink/stopped.
        const state = diagnostics.snapshot();
        if (dnsReady && (statusReady || (state.readySeen && state.lastState === 'idle_wait'))) return;
        await sleep();
      }
      throw Error('native_ready_timeout');
    },
    async stop() {
      if (!ended && !child.stdin.destroyed) child.stdin.write('{"op":"stop"}\n');
      const deadline = performance.now() + stopMs;
      while (!ended && performance.now() < deadline) await sleep();
      check(ended, 'native_stop_timeout');
      // A failed engine may still have cleaned up; ownership journals decide
      // whether a restart is safe. Never kill/delete its TUN to force success.
      return { code, signal };
    }
  };
}

async function adapter(trialCrash = false) {
  let initialPid, config, scratch, fingerprint, buildLock, ipv6Evidence;
  const legacyFingerprint = () => trialServiceFingerprint({ run, root: ROOT });
  const requireOldInactive = async () => {
    check(await prop(OLD, 'ActiveState') === 'inactive' && await prop(OLD, 'MainPID') === '0', 'old_service_not_inactive');
  };
  return {
    async preflight() {
      await hostRequired(); await verifyGuard(); await snatReady();
      if (trialCrash) await run('tcpdump', ['--version']);
      buildLock = fs.openSync(path.join(ROOT, 'native/clean_vpn/build/radxa-operation.lock'),
        fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW, 0o600);
      // flock operates on the inherited open-file description. Keeping this
      // descriptor open prevents replacing the engine throughout the trial.
      const locked = await new Promise(resolve => {
        const c = spawn('flock', ['--exclusive', '--nonblock', '3'], { env: ENV, stdio: ['ignore', 'ignore', 'ignore', buildLock] });
        c.on('error', () => resolve(false)); c.on('close', code => resolve(code === 0));
      });
      check(locked, 'native_build_or_trial_in_progress');
      check(await system('is-enabled', OLD) === 'enabled', 'old_autostart_required');
      check(await system('is-active', OLD) === 'active', 'old_service_not_active');
      // A same-checkout trial is allowed only while legacy runtime files are
      // unchanged from main. New native files do not alter the old entry point.
      const changed = await run('git', ['diff', '--name-only', '--diff-filter=DMRT', 'origin/main', '--',
        'scripts', 'native/boring_tls', 'native/tun_linux', 'package.json', 'package-lock.json']);
      check(changed.split('\n').filter(Boolean).every(f => f.endsWith('.md')), 'legacy_runtime_differs_from_main');
      const capabilities = JSON.parse(await run(ENGINE, ['--capabilities']));
      check(capabilities?.engine === 'clean-vpn-native-m1' && capabilities.packet_ipc === false
        && capabilities.dns === 'native-udp-tcp-fixed-upstreams', 'invalid_engine_capabilities');
      initialPid = await prop(OLD, 'MainPID');
      check(/^[1-9]\d*$/.test(initialPid), 'old_pid_missing');
      const argv = fs.readFileSync(`/proc/${initialPid}/cmdline`, 'utf8').split('\0').filter(Boolean);
      const cwd = fs.realpathSync(`/proc/${initialPid}/cwd`);
      check(cwd === fs.realpathSync(ROOT), 'run_trial_in_installed_checkout');
      if (argv.includes('--ipv6=auto')) ipv6Evidence = await inspectBlockedTrialIpv6({ run });
      config = deriveTrialConfig(argv, { cwd, root: ROOT, exists: fs.existsSync, ipv6Evidence });
      const key = fs.readFileSync(config.secret_path), ca = fs.readFileSync(config.ca);
      check(key.length === 32 && ca.length > 0 && ca.length <= 1024 * 1024, 'invalid_existing_credentials');
      scratch = fs.mkdtempSync('/run/clean-vpn-native-trial-');
      fs.chmodSync(scratch, 0o700);
      fs.writeFileSync(path.join(scratch, 'psk'), key, { mode: 0o600, flag: 'wx' }); key.fill(0);
      fs.writeFileSync(path.join(scratch, 'ca.pem'), ca, { mode: 0o600, flag: 'wx' });
      config = { ...config, secret_path: path.join(scratch, 'psk'), ca: path.join(scratch, 'ca.pem') };
      fs.writeFileSync(path.join(scratch, 'client.json'), JSON.stringify(config), { mode: 0o600, flag: 'wx' });
      fingerprint = await legacyFingerprint();
    },
    async beforeStop() {
      check(await prop(OLD, 'MainPID') === initialPid && await legacyFingerprint() === fingerprint, 'service_changed_during_trial');
      await verifyGuard();
      if (ipv6Evidence) {
        const current = await inspectBlockedTrialIpv6({ run });
        check(JSON.stringify(current.state) === JSON.stringify(ipv6Evidence.state), 'ipv6_changed_before_trial_stop');
      }
    },
    async stopOld() { await run('systemctl', ['stop', OLD], 480000); await requireOldInactive(); },
    auditReleased, requireNoTun, requireOldInactive, verifyGuard, probe,
    async auditIpv6Released() {
      // Only call after old is stopped and no TUN exists: released journals
      // retain the old interface identity. Never use recovery --apply here.
      await requireOldInactive(); await requireNoTun();
      const report = JSON.parse(await node('clean-vpn-ipv6-recover.mjs', [], 90000));
      validateReleasedTrialIpv6({ report, links: await links(),
        rules: JSON.parse(await run('ip', ['-j', '-6', 'rule', 'show'])),
        routes: JSON.parse(await run('ip', ['-j', '-6', 'route', 'show', 'table', 'all'])),
        filter: await run('ip6tables', ['-w', '5', '-t', 'filter', '-S']),
        nat: await run('ip6tables', ['-w', '5', '-t', 'nat', '-S']) }, !!ipv6Evidence);
    },
    async createTun() {
      await run('ip', ['tuntap', 'add', 'dev', 'tun0', 'mode', 'tun']);
      const tun = (await links()).find(l => l.ifname === 'tun0');
      check(Number.isSafeInteger(tun?.ifindex), 'test_tun_identity_missing');
      return tun.ifindex;
    },
    async configureTun() {
      await run('ip', ['addr', 'add', '10.99.0.2/30', 'dev', 'tun0']);
      await run('ip', ['link', 'set', 'dev', 'tun0', 'mtu', '1400', 'up']);
    },
    launch: () => launchTrialNative(path.join(scratch, 'client.json'), { trialCrash }),
    async recoverCrash(index) {
      await recoverCrashNetwork(index, { guard: verifyGuard, inactive: requireOldInactive,
        openHost: openHostRoutes, openDns: openTunnelDnsJournal, removeTun: this.removeTun });
    },
    async hold(seconds, cancelled, session, report) {
      await probeNativeHold({ seconds, cancelled, session, report, probe: async timeout => {
        const result = await command('curl', ['-q', '-4', '-f', '-sS', '--noproxy', '*', '--interface', 'tun0',
          '--connect-timeout', '3', '--max-time', '5', '--max-filesize', '4096',
          'https://1.1.1.1/cdn-cgi/trace'], timeout, 8192);
        return result.code === 0 && !result.reason
          && result.out.split(/\r?\n/).filter(l => l.startsWith('ip=')).join('') === 'ip=154.62.226.216';
      } });
    },
    async removeTun(index) {
      const tun = (await links()).find(l => l.ifname === 'tun0');
      check(tun?.ifindex === index, 'test_tun_identity_changed');
      await run('ip', ['tuntap', 'del', 'dev', 'tun0', 'mode', 'tun']);
    },
    async startOld() {
      check(await legacyFingerprint() === fingerprint, 'legacy_source_or_unit_changed');
      await verifyGuard(); await run('systemctl', ['start', OLD], 90000);
    },
    async waitOld() {
      return waitLegacyReady({ run, inspectIpv6: ipv6Evidence ? inspectBlockedTrialIpv6 : undefined });
    },
    cleanSecrets() {
      if (buildLock !== undefined) { fs.closeSync(buildLock); buildLock = undefined; }
      if (!scratch) return;
      // Exact files in our mkdtemp directory only; no recursive removal.
      for (const name of ['client.json', 'psk', 'ca.pem']) {
        try { fs.unlinkSync(path.join(scratch, name)); } catch (e) { if (e.code !== 'ENOENT') throw e; }
      }
      fs.rmdirSync(scratch);
    }
  };
}

async function authenticatedUsb() {
  const ssh = (process.env.SSH_CONNECTION || '').trim().split(/\s+/);
  check(ssh.length === 4 && /^192\.168\.7\.\d+$/.test(ssh[0]) && ssh[2] === '192.168.7.1' && ssh[3] === '2222', 'use_authenticated_usb_rescue_ssh_port_2222');
  const sockets = await run('ss', ['-4Htn', 'state', 'established', '( sport = :2222 )']);
  check(hasUsbRescueConnection(sockets, ssh), 'usb_rescue_connection_not_found');
  return ssh[0];
}

export function uplinkFault(directory, { exec = run, commandResult = command, getLinks = links,
  guard = verifyGuard, clock = () => performance.now(), wait = delay } = {}) {
  const unit = faultUnit(directory);
  const wlan = async () => (await getLinks()).find(l => l.ifname === 'wlan0');
  const defaults = async () => JSON.parse(await exec('ip', ['-j', '-4', 'route', 'show', 'default']));
  let attempted = false;
  const requireDown = async () => {
    check(await exec('systemctl', ['show', unit, '--property=ActiveState', '--value']) === 'active', 'uplink_fault_not_active');
    check(!(await wlan())?.flags?.includes('UP') && (await defaults()).length === 0, 'uplink_not_down');
  };
  return {
    requireDown,
    async start() {
      await guard();
      check(await exec('systemctl', ['is-active', 'systemd-networkd.service']) === 'active', 'networkd_required');
      const routes = await defaults();
      check((await wlan())?.flags?.includes('UP') && routes.length === 1 && routes[0].dev === 'wlan0', 'reviewed_wlan_uplink_required');
      attempted = true;
      await exec('systemd-run', faultUnitArgs(directory, process.execPath,
        path.join(ROOT, 'scripts/clean-vpn-native-usb-uplink.mjs')), 15000);
      const deadline = clock() + 10000;
      while (clock() < deadline) {
        try { await requireDown(); return; } catch { await wait(250); }
      }
      throw Error('uplink_down_timeout');
    },
    async restore() {
      if (!attempted) return;
      // Stop runs the helper's finally AND the independent ExecStopPost. No
      // relationship to the main trial cgroup: its death cannot cancel this.
      const result = await commandResult('systemctl', ['stop', unit], 25000);
      check(result.code === 0 && !result.reason, 'uplink_restore_unit_failed');
      check((await wlan())?.flags?.includes('UP'), 'uplink_restore_not_up');
    },
  };
}

async function worker(directory, holdSeconds, peerIp, trialCrash = false, benchmark = false) {
  await hostRequired();
  check(path.dirname(directory) === REPORTS && /^run-[a-zA-Z0-9]+$/.test(path.basename(directory)), 'invalid_worker_directory');
  privateDirectory(REPORTS); privateDirectory(directory);
  const owner = await prop(UNIT, 'MainPID');
  check(owner === String(process.pid), 'worker_requires_transient_unit');
  writeJson(path.join(REPORTS, 'current.json'), { directory });
  let cancelled = false;
  process.on('SIGTERM', () => { cancelled = true; });
  process.on('SIGINT', () => { cancelled = true; });
  const io = await adapter(trialCrash);
  if (peerIp) {
    const peer = createPeerChannel(directory, peerIp, { cancelled: () => cancelled });
    const benchmarkPhase = async (phase, target, session) => {
      const pid = session ? session.metricsRootPid() : Number(await prop(OLD, 'MainPID'));
      const stopCpu = sampleTrialCpu(pid, Number(await run('getconf', ['CLK_TCK'])));
      try { await peer.phase(phase, target, session?.healthy); }
      finally { (target[phase] ??= { status: 'failed' }).cpu = stopCpu(); }
      check(target[phase].cpu.status === 'sampled', 'benchmark_cpu_incomplete');
    };
    io.peer = benchmark ? { requiredPhases: benchmarkPhases,
      phase: (p, target) => benchmarkPhase(p === 'baseline' ? 'bench-old' : 'bench-restored', target),
      native: async (session, report) => {
        await benchmarkPhase('bench-native', report.phases, session);
        check(!(session.diagnostics().stateCounts?.peer_address > 0), 'native_peer_address_rejected');
      } } : trialCrash ? { phase: peer.phase, requiredPhases: ['baseline', 'native', 'blocked', 'restored'],
      native: (session, report, release) => exerciseCrashPeer(peer, session, report, {
        capture: startCrashCapture, release, requireUplink: async () => {
          await verifyGuard();
          const defaults = JSON.parse(await run('ip', ['-j', '-4', 'route', 'show', 'default']));
          const wlan = (await links()).find(l => l.ifname === 'wlan0');
          check(wlan?.flags?.includes('UP') && wlan.flags.includes('LOWER_UP')
            && defaults.length === 1 && defaults[0].dev === 'wlan0', 'crash_uplink_not_ready');
          if (session.crashRequested()) {
            await requireNoTun();
            const routes = JSON.parse(await run('ip', ['-j', '-4', 'route', 'get', '1.1.1.1', 'from', peerIp, 'iif', 'usb0']));
            check(routes.length === 1 && routes[0].dev === 'wlan0', 'crash_fallback_route_not_verified');
          }
        } }) } : { phase: peer.phase,
        native: (session, report) => exerciseNativePeer(peer, session, report, uplinkFault(directory)) };
  }
  const started = new Date().toISOString(), began = performance.now();
  const report = await runTrial(io, { holdSeconds, cancelled: () => cancelled, progress: stage => {
    try { writeJson(path.join(directory, 'progress.json'), { stage }); } catch { /* never interrupt rollback */ }
  } });
  if (trialCrash) report.limitations = report.limitations.filter(s => !['not-a-leak-or-crash-test', 'host-smoke-not-usb-peer-acceptance'].includes(s))
    .concat(['crash-scope-engine-only-not-worker-or-host', 'capture-only-selected-ipv4-https-not-ipv6-or-dns-or-all-egress']);
  if (trialCrash && report.usb) report.usb.scope = 'authenticated-Mac-USB-with-independent-selected-ipv4-uplink-capture';
  if (benchmark) {
    report.limitations = report.limitations.filter(s => !['not-speedtest-or-throughput-benchmark', 'host-smoke-not-usb-peer-acceptance'].includes(s))
      .concat(['bounded-cloudflare-4-stream-goodput-not-ookla-or-line-rate', 'cpu-sampled-client-tree-not-kernel-or-exit']);
    if (report.usb) report.usb.scope = 'Mac-USB-bounded-download-upload-and-Radxa-client-process-tree-CPU';
  }
  try { io.cleanSecrets(); } catch { report.secretCleanup = 'failed-private-run-directory-retained'; report.status = 'failed'; }
  Object.assign(report, { started, seconds: Math.round((performance.now() - began) / 1000),
    holdSeconds, reportFile: path.join(directory, 'report.json') });
  if (report.rollback === 'manual-review-required') report.next = 'Keep USB rescue. Do not flush rules or delete journals. Review report; reboot restores the enabled legacy service if ordinary recovery is unsafe.';
  writeJson(path.join(directory, 'report.json'), report); writeJson(path.join(REPORTS, 'last.json'), report);
  // In a failed stop, systemd owns any remaining processes and kills them when
  // the unit ends. No attempt to restart old on top of these processes is made.
  process.exit(report.status === 'passed' ? 0 : 1);
}

export async function main(args = process.argv.slice(2)) {
  if (args.length === 1 && args[0] === '--help') {
    console.log('Benchmark mode: --apply --usb-benchmark (Mac --benchmark coordinates three old/native/old cycles). Bounded synthetic upload/download, no fault injection.');
    console.log('Crash mode: --apply --usb-crash (coordinate from Mac with --crash). SIGKILL the owned native engine; keep wlan0 up; tcpdump selected IPv4 HTTPS; audited legacy rollback.');
    console.log('Usage: node scripts/clean-vpn-native-trial.mjs --apply [--hold-seconds=0..300 | --usb-peer | --usb-crash | --usb-benchmark] | --report\nRun from authenticated USB rescue SSH :2222 as root, after build-clean-vpn-native.sh.\nTemporarily stops ONLY clean-vpn.service, tests native, audits cleanup and restores legacy.\nUSB modes are coordinated by clean-vpn-native-usb-check.mjs on Mac. --usb-peer: REAL wlan0 down/up with independent systemd restoration.\nTransient systemd unit survives SSH loss. No install/enable/firewall flush/reboot.\nWithout --usb-benchmark: real DNS/HTTPS and bounded downloads, not a speed benchmark.'); return;
  }
  await hostRequired();
  if (args.length === 2 && ['--peer-status', '--peer-result'].includes(args[0])) {
    const peerIp = await authenticatedUsb();
    check(/^run-[a-zA-Z0-9]+$/.test(args[1]), 'invalid_peer_run');
    const directory = path.join(REPORTS, args[1]);
    check(fs.existsSync(directory), 'peer_run_missing');
    privateDirectory(REPORTS); privateDirectory(directory);
    if (args[0] === '--peer-status') {
      const finished = fs.existsSync(path.join(directory, 'report.json'));
      console.log(JSON.stringify(finished ? { status: 'finished' } : peerStatus(directory, peerIp)));
    } else {
      let input = '';
      const timer = setTimeout(() => process.exit(1), 5000);
      try {
        for await (const chunk of process.stdin) { input += chunk; check(input.length <= 4096, 'peer_result_too_large'); }
        submitPeerResult(directory, peerIp, JSON.parse(input));
        console.log('{"status":"accepted"}');
      } finally { clearTimeout(timer); }
    }
    return;
  }
  if (args.length === 1 && args[0] === '--report') {
    privateDirectory(REPORTS);
    const { directory } = JSON.parse(fs.readFileSync(path.join(REPORTS, 'current.json'), 'utf8'));
    check(path.dirname(directory) === REPORTS && /^run-[a-zA-Z0-9]+$/.test(path.basename(directory)), 'invalid_report_directory');
    privateDirectory(directory);
    const file = path.join(directory, 'report.json');
    if (fs.existsSync(file)) console.log(fs.readFileSync(file, 'utf8'));
    else {
      const state = await prop(UNIT, 'ActiveState');
      let progress = {};
      try { progress = JSON.parse(fs.readFileSync(path.join(directory, 'progress.json'), 'utf8')); } catch { /* startup */ }
      console.log(JSON.stringify({ status: ['active', 'activating', 'deactivating'].includes(state) ? 'running' : 'incomplete-keep-usb-rescue',
        unitState: state, stage: progress.stage ?? 'starting', reportDirectory: directory }, null, 2));
    }
    return;
  }
  if (args[0] === '--worker' && [3, 4, 5].includes(args.length) && /^\d{1,3}$/.test(args[2]) && Number(args[2]) <= 300) {
    check(!args[3] || /^192\.168\.7\.(?:[2-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])$/.test(args[3]), 'invalid_usb_peer');
    check(args.length !== 5 || (args[3] && ['--crash', '--benchmark'].includes(args[4])), 'invalid_trial_mode');
    return worker(args[1], Number(args[2]), args[3], args[4] === '--crash', args[4] === '--benchmark');
  }
  check(args[0] === '--apply' && args.length <= 2, 'use_apply_or_report_or_help');
  const crash = args[1] === '--usb-crash';
  const benchmark = args[1] === '--usb-benchmark';
  const usb = args[1] === '--usb-peer' || crash || benchmark;
  const match = args.length === 2 && !usb ? /^--hold-seconds=(\d{1,3})$/.exec(args[1]) : ['', '0'];
  check(match && Number(match[1]) <= 300, 'hold_seconds_must_be_0_to_300');
  const peerIp = await authenticatedUsb();
  const state = await prop(UNIT, 'ActiveState');
  check(!['active', 'activating', 'deactivating', 'reloading'].includes(state), 'trial_already_running');
  privateDirectory(REPORTS);
  const dir = fs.mkdtempSync(path.join(REPORTS, 'run-')); fs.chmodSync(dir, 0o700);
  await run('systemd-run', ['--quiet', '--collect', '--unit=clean-vpn-native-trial', '--service-type=exec',
    '--property=KillMode=mixed', '--property=TimeoutStopSec=600', '--property=RuntimeMaxSec=1500',
    '--property=StandardOutput=null', '--property=StandardError=null',
    `--working-directory=${ROOT}`, process.execPath, SELF, '--worker', dir, match[1], ...(usb ? [peerIp] : []),
    ...(crash ? ['--crash'] : benchmark ? ['--benchmark'] : [])], 15000);
  if (usb) console.log(`USB_TRIAL_ID=${path.basename(dir)}`);
  console.error('Trial started; survives SSH disconnect. Do not checkout/build/restart services during the trial.');
  console.error('After reconnect: node scripts/clean-vpn-native-trial.mjs --report');
  let previous = '', inactiveCount = 0;
  while (true) {
    const reportFile = path.join(dir, 'report.json');
    if (fs.existsSync(reportFile)) {
      const r = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
      console.log('=== CLEAN-VPN NATIVE TRIAL BEGIN ==='); console.log(JSON.stringify(r, null, 2));
      console.log('=== CLEAN-VPN NATIVE TRIAL END ==='); process.exitCode = r.status === 'passed' ? 0 : 1; return;
    }
    try {
      const { stage } = JSON.parse(fs.readFileSync(path.join(dir, 'progress.json'), 'utf8'));
      if (stage !== previous) { console.error(`[native-trial] ${stage}`); previous = stage; }
    } catch { /* worker may not have published progress yet */ }
    const active = await prop(UNIT, 'ActiveState');
    inactiveCount = ['inactive', 'failed'].includes(active) ? inactiveCount + 1 : 0;
    check(inactiveCount < 3, 'worker_ended_without_report_keep_usb_rescue');
    await delay(1000);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(e => { console.error(JSON.stringify({ status: 'refused-or-incomplete', code: safeCode(e),
    note: 'No blind rollback. Keep USB rescue; use --report if a trial was started.' })); process.exitCode = 1; });
}
