#!/usr/bin/env node
// Mac-side AP test job. The launcher returns before changing Wi-Fi so it can
// be invoked through a reverse SSH tunnel that will disappear during the run.
import { spawn } from 'node:child_process';
import { closeSync, openSync } from 'node:fs';
import { access, mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { command, parseArgs } from './perf-lib.mjs';
import { discoverBoard } from './perf-network.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const jobs = path.join(root, 'device/perf-managed-results');
const self = fileURLToPath(import.meta.url);
const networksetup = '/usr/sbin/networksetup';
const ipconfig = '/usr/sbin/ipconfig';
const donePhases = new Set(['completed', 'failed', 'interrupted']);

export function validateJobId(id) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{6}Z-[a-f0-9]{8}$/.test(id)) throw Error('Invalid job ID');
  return id;
}
export function wifiInterface(text) {
  for (const section of text.split(/\n\s*\n/)) {
    if (/^Hardware Port: (?:Wi-Fi|AirPort)$/m.test(section)) {
      const device = /^Device: (en\d+)$/m.exec(section);
      if (device) return device[1];
    }
  }
  throw Error('Mac Wi-Fi interface not found in networksetup -listallhardwareports');
}
export function currentSSID(text) {
  const match = /^Current (?:Wi-Fi|AirPort) Network: (.+)$/m.exec(text.trim());
  return match?.[1]?.trim() || null;
}
export async function withTemporaryWifi({previous,ap,join,wait,run,restore}) {
  let switched = false, result, error, restoreError;
  try {
    if (previous !== ap) { switched = true; await join(ap); await wait(ap); }
    result = await run();
  } catch (e) { error = e; }
  finally {
    if (switched) {
      try { await restore(previous); await wait(previous); }
      catch (e) { restoreError = e; }
    }
  }
  return {result, error, restoreError, switched};
}

async function atomicJSON(file, value) {
  const tmp = `${file}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(value, null, 2) + '\n');
  await rename(tmp, file);
}
async function readJSON(file) { return JSON.parse(await readFile(file, 'utf8')); }
async function checkedMac(bin, args, options = {}) {
  const result = await command(bin, args, {timeout: 12000, ...options});
  if (result.code !== 0) throw Error(`${path.basename(bin)} ${args[0]} failed: ${(result.stderr || result.stdout).trim()}`);
  return result.stdout;
}
async function getSSID(iface) {
  return currentSSID(await checkedMac(networksetup, ['-getairportnetwork', iface]));
}
async function getRouter(iface) {
  const result = await command(ipconfig, ['getoption', iface, 'router'], {timeout: 5000});
  return result.code === 0 ? result.stdout.trim().split(/\s+/)[0] : null;
}
async function awaitWifi(iface, ssid, router, signal, timeoutMs = 90000) {
  const until = Date.now() + timeoutMs;
  do {
    if (signal?.aborted) throw Error('Interrupted');
    const actual = await getSSID(iface).catch(() => null);
    const gateway = actual === ssid ? await getRouter(iface) : null;
    if (actual === ssid && gateway && (!router || gateway === router)) return gateway;
    await delay(1500, undefined, {signal});
  } while (Date.now() < until);
  throw Error(`Wi-Fi ${JSON.stringify(ssid)} did not associate and receive expected DHCP router within ${timeoutMs / 1000}s`);
}
async function setSSID(iface, ssid) {
  // The AP must already be a saved network in macOS Keychain. No password is
  // stored in the job or exposed in process arguments.
  await checkedMac(networksetup, ['-setairportnetwork', iface, ssid], {timeout: 30000});
}
function launchDetached(args, logFile) {
  const fd = openSync(logFile, 'a', 0o600);
  try {
    const child = spawn(process.execPath, [self, ...args], {cwd: root, detached: true, stdio: ['ignore', fd, fd], env: process.env});
    child.unref();
    return child.pid;
  } finally { closeSync(fd); }
}
function runnerArgs(args, output) { return [...args, '--out', output]; }
function launchRunner(args, output, signal) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(root, 'device/scripts/perf-runner.mjs'), ...runnerArgs(args, output)],
      {cwd: root, stdio: 'inherit', env: process.env});
    let killer;
    const abort = () => { child.kill('SIGTERM'); killer = setTimeout(() => child.kill('SIGKILL'), 10000); killer.unref(); };
    signal.addEventListener('abort', abort, {once: true});
    child.on('error', reject);
    child.on('close', (code, sig) => { clearTimeout(killer); signal.removeEventListener('abort', abort); resolve({code, sig}); });
    if (signal.aborted) abort();
  });
}
async function reportPath(jobDir) {
  const parent = path.join(jobDir, 'perf');
  const entries = await readdir(parent, {withFileTypes: true}).catch(() => []);
  const dirs = entries.filter(e => e.isDirectory()).map(e => e.name).sort();
  for (const dir of dirs.reverse()) {
    const file = path.join(parent, dir, 'report.md');
    try { await access(file); return path.relative(jobDir, file); } catch {}
  }
  return null;
}
async function worker(id) {
  if (process.platform !== 'darwin') throw Error('Managed AP test runs only on macOS');
  const dir = path.join(jobs, validateJobId(id));
  const spec = await readJSON(path.join(dir, 'job.json'));
  const state = {id, phase: 'preflight', started: new Date().toISOString(), runner_exit_code: null,
    report: null, restored: false, error: null};
  const save = () => atomicJSON(path.join(dir, 'state.json'), state);
  const controller = new AbortController();
  const abort = () => controller.abort();
  process.on('SIGINT', abort); process.on('SIGTERM', abort);
  await save();
  let iface, previous, originalRouter, ap;
  try {
    iface = wifiInterface(await checkedMac(networksetup, ['-listallhardwareports']));
    previous = await getSSID(iface);
    originalRouter = await getRouter(iface);
    if (!previous || !originalRouter) throw Error('No active Wi-Fi with DHCP router to restore; refusing to switch');
    const options = parseArgs(spec.args);
    const board = await discoverBoard({...options, paths: 'usb'}, controller.signal, message => console.log(message));
    ap = board.initial.net.ap_ssid;
    if (!board.initial.net.ap_active || !ap || !board.initial.net.ap_ip) throw Error('Board SoftAP is not active or does not report SSID/IP');
    state.wifi = {interface: iface, previous_ssid: previous, previous_router: originalRouter,
      ap_ssid: ap, ap_router: board.initial.net.ap_ip};
    await save();
    // Separate process survives a worker crash and restores only when still on
    // the board AP. It does not change a Wi-Fi chosen later by the user.
    launchDetached(['watchdog', id, String(process.pid)], path.join(dir, 'watchdog.log'));
    const result = await withTemporaryWifi({previous, ap,
      join: async ssid => {state.phase = 'switching'; await save(); await setSSID(iface, ssid);},
      wait: ssid => awaitWifi(iface, ssid, ssid === ap ? board.initial.net.ap_ip : originalRouter,
        ssid === ap ? controller.signal : undefined),
      run: async () => {
        state.phase = 'running'; await save();
        const outcome = await launchRunner(spec.args, path.join(dir, 'perf'), controller.signal);
        state.runner_exit_code = outcome.code;
        state.report = await reportPath(dir);
        return outcome;
      },
      restore: async ssid => {state.phase = 'restoring'; await save(); await setSSID(iface, ssid);},
    });
    state.restored = !result.switched || !result.restoreError;
    state.error = result.error?.message || result.restoreError?.message || null;
    if (result.restoreError) state.restore_error = result.restoreError.message;
    state.phase = controller.signal.aborted ? 'interrupted' : result.error || result.restoreError ||
      ![0, 2].includes(result.result?.code) || !state.report ? 'failed' : 'completed';
  } catch (e) {
    state.error = e.message;
    state.phase = controller.signal.aborted ? 'interrupted' : 'failed';
    // Exceptions outside withTemporaryWifi occur before the Wi-Fi switch.
    state.restored = true;
  } finally {
    state.ended = new Date().toISOString();
    await save();
  }
}
async function watchdog(id, workerPid) {
  const dir = path.join(jobs, validateJobId(id));
  const deadline = Date.now() + 6 * 3600_000;
  while (Date.now() < deadline) {
    await delay(5000);
    const state = await readJSON(path.join(dir, 'state.json')).catch(() => null);
    if (!state?.wifi) {
      if (state && donePhases.has(state.phase)) return;
      continue;
    }
    if (state.restored) return;
    let alive = true;
    try { process.kill(workerPid, 0); } catch { alive = false; }
    if (alive) continue;
    if (!donePhases.has(state.phase)) {
      state.phase = 'interrupted'; state.ended = new Date().toISOString();
      state.error = 'Worker exited unexpectedly';
      await atomicJSON(path.join(dir, 'state.json'), state);
    }
    const {interface: iface, previous_ssid: previous, previous_router: router, ap_ssid: ap} = state.wifi;
    const current = await getSSID(iface).catch(() => null);
    if (current !== ap) {
      // The user or OS selected a different network. Never override it.
      state.restored = current === previous && await getRouter(iface) === router;
      await atomicJSON(path.join(dir, 'state.json'), state);
      return;
    }
    try {
      await setSSID(iface, previous);
      await awaitWifi(iface, previous, router, undefined, 30000);
      await atomicJSON(path.join(dir, 'watchdog.json'), {restored: true, time: new Date().toISOString()});
      state.restored = true;
      await atomicJSON(path.join(dir, 'state.json'), state);
      return;
    } catch (error) {
      await atomicJSON(path.join(dir, 'watchdog.json'), {restored: false, error: error.message, time: new Date().toISOString()});
    }
  }
}
async function start(args) {
  if (process.platform !== 'darwin') throw Error('Run device:perf:ap-managed on the Mac');
  if (!args.length) throw Error('Usage: npm run device:perf:ap-managed -- [user@]SERVER[:port] [--ap-tcp-paced|--ap-tcp-up] [options]');
  if (args.includes('--out') || args.includes('--usb-down-sweep') || args.includes('--usb-burst-sweep'))
    throw Error('Managed AP test owns its output directory and supports AP presets only');
  if (!args.includes('--ap-tcp-paced') && !args.includes('--ap-tcp-up')) args.push('--ap-tcp-paced');
  const options = parseArgs(args);
  if (options.help || options.paths !== 'ap') throw Error('Managed test requires AP-only TCP preset');
  await mkdir(jobs, {recursive: true});
  const stamp = new Date().toISOString().replaceAll(':', '').replace(/\.\d+Z$/, 'Z');
  const id = `${stamp}-${randomBytes(4).toString('hex')}`;
  const dir = path.join(jobs, id);
  await mkdir(dir, {recursive: false, mode: 0o700});
  await atomicJSON(path.join(dir, 'job.json'), {id, args, created: new Date().toISOString()});
  const pid = launchDetached(['worker', id], path.join(dir, 'worker.log'));
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline && !await access(path.join(dir, 'state.json')).then(() => true, () => false)) {
    try { process.kill(pid, 0); } catch { throw Error(`Mac AP worker did not start; see ${path.join(dir, 'worker.log')}`); }
    await delay(100);
  }
  if (!await access(path.join(dir, 'state.json')).then(() => true, () => false))
    throw Error(`Mac AP worker did not create state; see ${path.join(dir, 'worker.log')}`);
  // Stable machine-readable output; no raw test output enters the agent context.
  console.log(id);
}

if (process.argv[1] && path.resolve(process.argv[1]) === self) {
  const [mode, ...args] = process.argv.slice(2);
  const task = mode === 'worker' ? worker(args[0]) : mode === 'watchdog' ? watchdog(args[0], Number(args[1]))
    : start(process.argv.slice(2));
  task.catch(error => {console.error(error.message); process.exitCode = 1;});
}
