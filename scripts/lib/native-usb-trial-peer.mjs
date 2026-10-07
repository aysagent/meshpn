// SSH-authenticated operator observations, not independent wire/leak evidence.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { requireTrial as check } from './native-radxa-trial.mjs';
import { benchmarkPhases, validateBenchmarkResult } from './native-trial-benchmark.mjs';

export const peerPhases = ['baseline', 'native', 'blocked', 'recovered', 'restored', ...benchmarkPhases];
export const monotonicMs = () => Number(process.hrtime.bigint() / 1000000n);
const keys = ['token', 'phase', 'dnsPassed', 'httpsPassed', 'downloadBytes', 'exitIp', 'blockedAttempts', 'recoveryMs', 'elapsedMs'];
export function validatePeerResult(v, request) {
  if (benchmarkPhases.includes(request.phase)) return validateBenchmarkResult(v, request);
  check(v && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => k in v), 'invalid_peer_result');
  check(v.token === request.token && v.phase === request.phase && peerPhases.includes(v.phase), 'stale_peer_result');
  for (const k of ['dnsPassed', 'httpsPassed', 'downloadBytes', 'blockedAttempts', 'recoveryMs', 'elapsedMs'])
    check(Number.isSafeInteger(v[k]) && v[k] >= 0 && v[k] <= 2 * 1024 * 1024, 'invalid_peer_result');
  check([null, '154.62.226.216'].includes(v.exitIp) && v.dnsPassed <= 4 && v.httpsPassed <= 3
    && v.blockedAttempts <= 2 && v.recoveryMs <= 60000 && v.elapsedMs <= 120000, 'invalid_peer_result');
  const passed = v.phase === 'blocked'
    ? v.blockedAttempts === 2 && v.httpsPassed === 0 && v.dnsPassed === 0 && v.downloadBytes === 0 && v.exitIp === null
    : v.dnsPassed === 4 && v.httpsPassed === 3 && v.downloadBytes === 1048576 && v.exitIp === '154.62.226.216' && v.blockedAttempts === 0;
  return { phase: v.phase, status: passed ? 'passed' : 'failed', dnsPassed: v.dnsPassed,
    httpsPassed: v.httpsPassed, downloadBytes: v.downloadBytes, exitIp: v.exitIp,
    blockedAttempts: v.blockedAttempts, recoveryMs: v.recoveryMs, elapsedMs: v.elapsedMs };
}
function readJson(file) {
  const s = fs.lstatSync(file); check(s.isFile() && !s.isSymbolicLink() && s.size <= 4096, 'invalid_peer_file');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
function readPhase(directory) {
  const p = readJson(path.join(directory, 'peer-phase.json'));
  check(peerPhases.includes(p.phase) && /^[a-f0-9-]{36}$/.test(p.token)
    && Number.isSafeInteger(p.deadline) && typeof p.active === 'boolean', 'invalid_peer_phase');
  return p;
}
function writeJson(file, value) {
  const tmp = file + '.' + randomUUID();
  try { fs.writeFileSync(tmp, JSON.stringify(value), { mode: 0o600, flag: 'wx' }); fs.renameSync(tmp, file); }
  finally { try { fs.unlinkSync(tmp); } catch (e) { if (e.code !== 'ENOENT') throw e; } }
}
export function peerStatus(directory, peerIp, now = monotonicMs) {
  const file = path.join(directory, 'peer-phase.json');
  if (!fs.existsSync(file)) return { status: 'waiting' };
  const p = readPhase(directory);
  check(p.peerIp === peerIp, 'usb_peer_address_changed');
  return p.active && now() < p.deadline ? { status: 'probe', phase: p.phase, token: p.token }
    : { status: 'waiting' };
}
export function submitPeerResult(directory, peerIp, value, now = monotonicMs) {
  const p = readPhase(directory);
  check(p.active && p.peerIp === peerIp && now() < p.deadline, 'peer_phase_closed');
  validatePeerResult(value, p);
  // Nonce-specific exclusive file: replay/late writes cannot replace a result.
  fs.writeFileSync(path.join(directory, `peer-${p.token}.json`), JSON.stringify(value), { mode: 0o600, flag: 'wx' });
}
export function createPeerChannel(directory, peerIp, { now = monotonicMs, sleep = delay, cancelled = () => false } = {}) {
  let active;
  const close = () => { if (active) { active.active = false; writeJson(path.join(directory, 'peer-phase.json'), active); } };
  return {
    close,
    async phase(phase, target, healthy = () => true) {
      check(peerPhases.includes(phase), 'invalid_peer_phase');
      const started = now();
      active = { phase, token: randomUUID(), peerIp, active: true, deadline: started + (phase === 'blocked' ? 15000 : 120000) };
      writeJson(path.join(directory, 'peer-phase.json'), active);
      const resultFile = path.join(directory, `peer-${active.token}.json`);
      target[phase] = { status: 'waiting' };
      try {
        while (now() < active.deadline) {
          check(!cancelled(), 'cancelled'); check(healthy(), 'native_exited_during_trial');
          if (fs.existsSync(resultFile)) {
            const result = validatePeerResult(readJson(resultFile), active);
            target[phase] = { ...result, observedAfterMs: now() - started };
            check(result.status === 'passed', 'usb_peer_probe_failed');
            return;
          }
          await sleep(250);
        }
        throw Error('usb_peer_timeout');
      } catch (e) {
        if (target[phase].status === 'waiting') target[phase] = { status: 'failed',
          code: /^[a-z0-9_]{1,100}$/.test(e.message) ? e.message : 'peer_observation_failed', observedAfterMs: now() - started };
        throw e;
      } finally { close(); }
    },
  };
}

export async function exerciseNativePeer(peer, session, report, fault, now = monotonicMs) {
  await peer.phase('native', report.phases, session.healthy);
  report.fault = { kind: 'networkctl-wlan0-down-up', requestedPhysicalUplinkChange: true, downVerified: false,
    safeguard: 'independent-transient-unit-runtime-limit-and-ExecStopPost' };
  let attempted = false;
  try {
    attempted = true; await fault.start();
    await fault.requireDown();
    report.fault.downVerified = true;
    await peer.phase('blocked', report.phases, session.healthy);
    await fault.requireDown();
  } finally {
    if (attempted) {
      const began = now(); await fault.restore();
      report.fault.restoreCommandMs = now() - began;
    }
  }
  report.fault.recoveryClock = 'Mac recovered-phase start to first successful HTTPS; excludes restore command and phase discovery, not DHCP latency';
  await peer.phase('recovered', report.phases, session.healthy);
  check(!(session.diagnostics().stateCounts?.peer_address > 0), 'native_peer_address_rejected');
}
