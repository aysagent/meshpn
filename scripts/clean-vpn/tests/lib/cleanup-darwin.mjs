import { execFileSync } from 'child_process';

const IP_EXIT = '10.99.0.1';
const IP_CLIENT = '10.99.0.2';

function listUtunNames() {
  try {
    const out = execFileSync('ifconfig', ['-l'], { encoding: 'utf8' });
    return out.trim().split(/\s+/).filter((n) => /^utun\d+$/.test(n));
  } catch {
    return [];
  }
}

function darwinUtunInet(ifname) {
  try {
    const out = execFileSync('ifconfig', [ifname], { encoding: 'utf8' });
    const m = out.match(/inet\s+(\d+\.\d+\.\d+\.\d+)\s+-->?\s+(\d+\.\d+\.\d+\.\d+)/);
    if (!m) return null;
    return { local: m[1], remote: m[2] };
  } catch {
    return null;
  }
}

/** @returns {string[]} utun names with test VPN addresses */
export function listTestVpnUtunNames() {
  /** @type {string[]} */
  const names = [];
  for (const name of listUtunNames()) {
    const inet = darwinUtunInet(name);
    if (inet?.local === IP_EXIT || inet?.local === IP_CLIENT) names.push(name);
  }
  return names;
}

function sleepMs(ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    /* spin */
  }
}

function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function signalPid(pid, sig) {
  try {
    process.kill(pid, sig);
    return true;
  } catch {
    return false;
  }
}

function psField(pid, field) {
  try {
    return execFileSync('ps', ['-p', String(pid), '-o', `${field}=`], { encoding: 'utf8' }).trim();
  } catch {
    return '';
  }
}

/** Transport-test clean-vpn (localhost 876x, not production VPN). */
export function isTestCleanVpnCmd(cmd) {
  if (!/clean-vpn\.js/.test(cmd)) return false;
  if (!/--role=(exit|client)\b/.test(cmd)) return false;
  return /127\.0\.0\.1:876\d/.test(cmd) || /--server=127\.0\.0\.1:876/.test(cmd);
}

/** @returns {number[]} */
export function listTestCleanVpnPids() {
  /** @type {number[]} */
  const pids = [];
  try {
    const out = execFileSync('pgrep', ['-lf', 'clean-vpn.js'], { encoding: 'utf8' });
    for (const line of out.trim().split('\n')) {
      if (!line) continue;
      const sp = line.indexOf(' ');
      if (sp < 0) continue;
      const pid = parseInt(line.slice(0, sp), 10);
      const cmd = line.slice(sp + 1);
      if (Number.isFinite(pid) && isTestCleanVpnCmd(cmd)) pids.push(pid);
    }
  } catch {
    /* none */
  }
  return pids;
}

/** @returns {number[]} */
export function listUtunHelperPids() {
  try {
    return execFileSync('pgrep', ['utun-helper'], { encoding: 'utf8' })
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((s) => parseInt(s, 10))
      .filter((n) => Number.isFinite(n));
  } catch {
    return [];
  }
}

function killGracefulThenForce(pid, graceMs = 2000) {
  if (!isAlive(pid)) return;
  signalPid(pid, 'SIGTERM');
  const deadline = Date.now() + graceMs;
  while (Date.now() < deadline && isAlive(pid)) sleepMs(50);
  if (isAlive(pid)) signalPid(pid, 'SIGKILL');
}

export function killProcessGroupGracefulThenForce(pid, graceMs = 2000) {
  if (!isAlive(pid)) return;
  try {
    process.kill(-pid, 'SIGTERM');
  } catch {
    signalPid(pid, 'SIGTERM');
  }
  const deadline = Date.now() + graceMs;
  while (Date.now() < deadline && isAlive(pid)) sleepMs(50);
  if (!isAlive(pid)) return;
  try {
    process.kill(-pid, 'SIGKILL');
  } catch {
    signalPid(pid, 'SIGKILL');
  }
}

function killOrphanUtunHelpers() {
  for (const pid of listUtunHelperPids()) {
    const ppid = parseInt(psField(pid, 'ppid'), 10);
    let orphan = !Number.isFinite(ppid) || ppid <= 1;
    if (!orphan) {
      const parentCmd = psField(ppid, 'command');
      if (!parentCmd || isTestCleanVpnCmd(parentCmd)) orphan = true;
    }
    if (orphan) killGracefulThenForce(pid, 500);
  }
}

/**
 * macOS: utun exists while utun-helper (or clean-vpn) holds the kernel FD.
 * ifconfig down alone does not remove the interface.
 *
 * @param {{ graceMs?: number, waitMs?: number, verbose?: boolean }} [opts]
 * @returns {{ ok: boolean, remaining: string[], killed: { cleanVpn: number[], utunHelper: number[] } }}
 */
export function cleanupStaleVpnUtunsDarwin(opts = {}) {
  const graceMs = opts.graceMs ?? 2500;
  const waitMs = opts.waitMs ?? 6000;
  const verbose = Boolean(opts.verbose);

  /** @type {number[]} */
  const killedCleanVpn = [];
  /** @type {number[]} */
  const killedHelper = [];

  for (const pid of listTestCleanVpnPids()) {
    if (verbose) console.log(`[cleanup] SIGTERM clean-vpn test pid ${pid}`);
    killProcessGroupGracefulThenForce(pid, graceMs);
    killedCleanVpn.push(pid);
  }

  for (const pid of listUtunHelperPids()) {
    const ppid = parseInt(psField(pid, 'ppid'), 10);
    let orphan = !Number.isFinite(ppid) || ppid <= 1;
    if (!orphan) {
      const parentCmd = psField(ppid, 'command');
      if (!parentCmd || isTestCleanVpnCmd(parentCmd)) orphan = true;
    }
    if (orphan) {
      if (verbose) console.log(`[cleanup] SIGTERM orphan utun-helper pid ${pid}`);
      killGracefulThenForce(pid, 500);
      killedHelper.push(pid);
    }
  }

  // Second pass: helpers whose parent died during step 1
  killOrphanUtunHelpers();

  if (listTestVpnUtunNames().length > 0) {
    if (verbose) console.warn('[cleanup] last resort: SIGKILL all utun-helper');
    for (const pid of listUtunHelperPids()) {
      signalPid(pid, 'SIGKILL');
      killedHelper.push(pid);
    }
  }

  const deadline = Date.now() + waitMs;
  while (Date.now() < deadline) {
    if (listTestVpnUtunNames().length === 0) {
      return { ok: true, remaining: [], killed: { cleanVpn: killedCleanVpn, utunHelper: killedHelper } };
    }
    sleepMs(100);
  }

  const remaining = listTestVpnUtunNames();
  if (remaining.length && verbose) {
    console.warn(`[cleanup] still present: ${remaining.join(', ')}`);
    try {
      const helpers = execFileSync('pgrep', ['-lf', 'utun-helper'], { encoding: 'utf8' }).trim();
      if (helpers) console.warn(`[cleanup] utun-helper:\n${helpers}`);
    } catch {
      /* none */
    }
  }

  return { ok: remaining.length === 0, remaining, killed: { cleanVpn: killedCleanVpn, utunHelper: killedHelper } };
}
