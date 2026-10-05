#!/usr/bin/env node
/** One-shot Radxa trial, managed by a TRANSIENT systemd unit. No installation. */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { deriveTrialConfig, summarizeTrialProbe, requireTrial as check, runTrial } from './lib/native-radxa-trial.mjs';

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

export function launchTrialNative(config, { spawnChild = spawn, readyMs = 45000, stopMs = 240000 } = {}) {
  const child = spawnChild(process.execPath, [path.join(ROOT, 'scripts/clean-vpn-native.mjs'), '--config', config, '--usb-profile'],
    { cwd: ROOT, env: ENV, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let ended = false, code, signal, statusReady = false, dnsReady = false, bytes = 0, stdout = '', stderr = '', broken = false;
  child.stdin.on('error', () => { broken = true; });
  child.on('error', () => { broken = true; });
  child.on('close', (c, s) => { ended = true; code = c; signal = s; });
  for (const [stream, kind] of [[child.stdout, 'out'], [child.stderr, 'err']]) {
    stream.setEncoding('utf8');
    stream.on('data', chunk => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > 256 * 1024) { broken = true; return; }
      if (kind === 'out') {
        stdout += chunk;
        let at;
        while ((at = stdout.indexOf('\n')) >= 0) {
          const line = stdout.slice(0, at); stdout = stdout.slice(at + 1);
          try { statusReady = JSON.parse(line).state === 'ready'; } catch { broken = true; }
        }
      } else {
        stderr = (stderr + chunk).slice(-4096);
        if (stderr.includes('native-control: DNS active')) dnsReady = true;
      }
    });
  }
  return {
    healthy: () => !ended && !broken,
    async ready(cancelled) {
      const deadline = performance.now() + readyMs;
      while (performance.now() < deadline) {
        check(!cancelled(), 'cancelled');
        check(!ended && !broken, 'native_start_failed');
        if (statusReady && dnsReady) return;
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

async function adapter() {
  let initialPid, config, scratch, fingerprint, buildLock;
  const legacyFingerprint = async () => {
    const wrapper = fs.readFileSync('/usr/local/bin/clean-vpn-run.sh');
    const effective = await system('show', OLD, '--property=ExecStart,FragmentPath,DropInPaths,Environment');
    const source = fs.readFileSync(path.join(ROOT, 'scripts/clean-vpn.js'));
    return createHash('sha256').update(wrapper).update(effective).update(source).digest('hex');
  };
  const requireOldInactive = async () => {
    check(await prop(OLD, 'ActiveState') === 'inactive' && await prop(OLD, 'MainPID') === '0', 'old_service_not_inactive');
  };
  return {
    async preflight() {
      await hostRequired(); await verifyGuard(); await snatReady();
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
      config = deriveTrialConfig(argv, { cwd, root: ROOT, exists: fs.existsSync });
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
    },
    async stopOld() { await run('systemctl', ['stop', OLD], 480000); await requireOldInactive(); },
    auditReleased, requireNoTun, requireOldInactive, verifyGuard, probe,
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
    launch: () => launchTrialNative(path.join(scratch, 'client.json')),
    async hold(seconds, cancelled, session) {
      const deadline = performance.now() + seconds * 1000;
      do {
        check(!cancelled(), 'cancelled'); check(session.healthy(), 'native_exited_during_trial');
        if (performance.now() >= deadline) break;
        await sleep();
      } while (true);
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
      const deadline = performance.now() + 60000;
      while (performance.now() < deadline) {
        try { await snatReady(); return; } catch { await sleep(); }
      }
      throw Error('old_ready_timeout');
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

async function worker(directory, holdSeconds) {
  await hostRequired();
  check(path.dirname(directory) === REPORTS && /^run-[a-zA-Z0-9]+$/.test(path.basename(directory)), 'invalid_worker_directory');
  privateDirectory(REPORTS); privateDirectory(directory);
  const owner = await prop(UNIT, 'MainPID');
  check(owner === String(process.pid), 'worker_requires_transient_unit');
  writeJson(path.join(REPORTS, 'current.json'), { directory });
  let cancelled = false;
  process.on('SIGTERM', () => { cancelled = true; });
  process.on('SIGINT', () => { cancelled = true; });
  const io = await adapter();
  const started = new Date().toISOString(), began = performance.now();
  const report = await runTrial(io, { holdSeconds, cancelled: () => cancelled, progress: stage => {
    try { writeJson(path.join(directory, 'progress.json'), { stage }); } catch { /* never interrupt rollback */ }
  } });
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
    console.log('Usage: node scripts/clean-vpn-native-trial.mjs --apply [--hold-seconds=0..300] | --report\nRun from authenticated USB rescue SSH :2222 as root, after build-clean-vpn-native.sh.\nTemporarily stops ONLY clean-vpn.service, tests native, audits cleanup and restores legacy.\nTransient systemd unit survives SSH loss. No install/enable/firewall flush/reboot.\nReal DNS/HTTPS and up to three 1 MiB downloads; not a speed benchmark.'); return;
  }
  await hostRequired();
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
  if (args[0] === '--worker' && args.length === 3 && /^\d{1,3}$/.test(args[2]) && Number(args[2]) <= 300)
    return worker(args[1], Number(args[2]));
  check(args[0] === '--apply' && args.length <= 2, 'use_apply_or_report_or_help');
  const match = args.length === 2 ? /^--hold-seconds=(\d{1,3})$/.exec(args[1]) : ['', '0'];
  check(match && Number(match[1]) <= 300, 'hold_seconds_must_be_0_to_300');
  const ssh = (process.env.SSH_CONNECTION || '').trim().split(/\s+/);
  check(ssh.length === 4 && /^192\.168\.7\.\d+$/.test(ssh[0]) && ssh[2] === '192.168.7.1' && ssh[3] === '2222', 'use_authenticated_usb_rescue_ssh_port_2222');
  const sockets = await run('ss', ['-Htn', 'state', 'established', '( sport = :2222 )']);
  check(sockets.split('\n').some(l => l.includes('192.168.7.1:2222') && l.includes(`${ssh[0]}:${ssh[1]}`)), 'usb_rescue_connection_not_found');
  const state = await prop(UNIT, 'ActiveState');
  check(!['active', 'activating', 'deactivating', 'reloading'].includes(state), 'trial_already_running');
  privateDirectory(REPORTS);
  const dir = fs.mkdtempSync(path.join(REPORTS, 'run-')); fs.chmodSync(dir, 0o700);
  await run('systemd-run', ['--quiet', '--collect', '--unit=clean-vpn-native-trial', '--service-type=exec',
    '--property=KillMode=mixed', '--property=TimeoutStopSec=600', '--property=RuntimeMaxSec=1500',
    '--property=StandardOutput=null', '--property=StandardError=null',
    `--working-directory=${ROOT}`, process.execPath, SELF, '--worker', dir, match[1]], 15000);
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
