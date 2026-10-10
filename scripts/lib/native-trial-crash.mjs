/** Explicit physical trial only; never a production crash/restart policy. */
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { requireTrial as check } from './native-radxa-trial.mjs';

// tcpdump emits header summaries, not packet bodies. Do not retain raw lines,
// source addresses, ports or stderr in the report. Capture has a positive
// control: the native USB phase must produce encrypted exit traffic.
export function startCrashCapture({ spawnChild = spawn, timeoutMs = 5000 } = {}) {
  const child = spawnChild('tcpdump', ['-nn', '-l', '-i', 'wlan0', '-Q', 'out', '-s', '96', '-tt',
    'ip and tcp dst port 443 and (dst host 1.1.1.1 or dst host 154.62.226.216)'],
  { env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let listening = false, ended = false, broken = false, stopping = false, code, signal;
  let direct = 0, tunnel = 0, dropped = null, captured = null, bytes = 0;
  const pending = { out: '', err: '' };
  child.on('error', () => { broken = true; });
  child.on('close', (c, s) => { ended = true; code = c; signal = s; });
  for (const [kind, stream] of [['out', child.stdout], ['err', child.stderr]]) {
    stream.setEncoding('utf8');
    stream.on('data', chunk => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > 2 * 1024 * 1024) { broken = true; child.kill('SIGINT'); return; }
      pending[kind] += chunk;
      let at;
      while ((at = pending[kind].indexOf('\n')) >= 0) {
        const line = pending[kind].slice(0, at); pending[kind] = pending[kind].slice(at + 1);
        if (!line) continue; // tcpdump prints a final blank stdout line on SIGINT.
        if (kind === 'out') {
          if (/^\d+\.\d+ IP [0-9.]+ > 1\.1\.1\.1\.443: /.test(line)) direct++;
          else if (/^\d+\.\d+ IP [0-9.]+ > 154\.62\.226\.216\.443: /.test(line)) tunnel++;
          else broken = true;
        } else {
          if (/^(?:tcpdump: )?listening on wlan0,/.test(line)) listening = true;
          const d = /^(\d+) packets? dropped by kernel$/.exec(line);
          const c = /^(\d+) packets? captured$/.exec(line);
          if (d) dropped = Number(d[1]);
          if (c) captured = Number(c[1]);
        }
      }
      if (pending[kind].length > 8192) broken = true;
    });
  }
  const healthy = () => listening && !ended && !broken;
  return {
    healthy,
    async ready() {
      const until = performance.now() + timeoutMs;
      while (!listening && !ended && !broken && performance.now() < until) await delay(25);
      check(healthy(), 'crash_capture_not_ready');
    },
    async stop() {
      const wasHealthy = healthy();
      if (!stopping) { stopping = true; if (!ended) child.kill('SIGINT'); }
      const until = performance.now() + timeoutMs;
      while (!ended && performance.now() < until) await delay(25);
      if (!ended) { child.kill('SIGKILL'); throw Error('crash_capture_stop_timeout'); }
      const complete = wasHealthy && !broken && code === 0 && !signal
        && !pending.out && dropped === 0 && captured === direct + tunnel && tunnel > 0;
      return { status: complete && direct === 0 ? 'passed' : 'failed',
        scope: 'wlan0-outbound-ipv4-tcp-443-to-1.1.1.1-only',
        directPackets: direct, encryptedExitPackets: tunnel, capturedPackets: captured, kernelDropped: dropped,
        complete, payloadStored: false };
    },
  };
}

export async function exerciseCrashPeer(peer, session, report, io) {
  report.fault = { kind: 'native-engine-sigkill', requestedPhysicalUplinkChange: false,
    crashVerified: false, fallbackRouteVerified: false };
  const capture = io.capture();
  try {
    await capture.ready();
    await peer.phase('native', report.phases, () => session.healthy() && capture.healthy());
    check(!(session.diagnostics().stateCounts?.peer_address > 0), 'native_peer_address_rejected');
    await io.requireUplink();
    await session.crash();
    report.fault.crashVerified = true;
    // Explicit audited recovery removes owned TUN/DNS/routes while the
    // independent kill-switch stays installed. This makes the direct default
    // route eligible, so failure isn't merely a dead TUN swallowing traffic.
    await io.release();
    await io.requireUplink();
    report.fault.fallbackRouteVerified = true;
    await peer.phase('blocked', report.phases, capture.healthy);
    await io.requireUplink();
  } finally {
    report.capture = await capture.stop();
  }
  check(report.capture.status === 'passed', 'crash_capture_failed');
}

// Call only after the wrapper has exited and our TUN identity is verified.
// Both journals must belong to this trial's TUN; no blind generic recovery.
export async function recoverCrashNetwork(index, io) {
  await io.guard(); await io.inactive();
  const host = io.openHost(); let dns, redirect;
  try {
    dns = io.openDns(); redirect = io.openRedirect?.();
    check(host.state?.tun === 'tun0' && host.state.links?.tun0?.ifindex === index
      && dns.state?.config?.tun === 'tun0' && dns.state.links?.tun0?.ifindex === index,
    'crash_journal_identity_changed');
    if (redirect) {
      check(redirect.state?.stage !== 'released'
        && redirect.state?.config?.interface === 'usb0', 'crash_redirect_identity_changed');
      redirect.audit();
    }
    await io.removeTun(index);
    // Host audit deliberately rejects linkdown routes. Removing only the
    // trial's unused persistent TUN lets the unchanged audit run normally.
    host.audit(); dns.restore({ apply: false });
    dns.restore(); host.restore(); redirect?.restore();
    await io.guard();
  } finally { redirect?.release(); dns?.release(); host.release(); }
}
