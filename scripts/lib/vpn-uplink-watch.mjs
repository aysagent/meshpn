import { spawn } from 'node:child_process';

/** Read-only netlink subscriber. Never retains or logs raw network messages. */
export function subscribeUplinkEvents(changed, failed, { spawnChild = spawn,
  schedule = setTimeout, cancel = clearTimeout } = {}) {
  let child, stopped = false, pending, killer, faulted = false;
  const fault = () => { if (!stopped && !faulted) { faulted = true; failed(); } };
  const data = () => {
    if (stopped || pending) return;
    pending = schedule(() => { pending = null; if (!stopped) changed(); }, 50);
    pending?.unref?.();
  };
  try {
    child = spawnChild('ip', ['-o', 'monitor', 'link', 'route', 'address'], { stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', data); child.stderr.on('data', fault);
    child.on('error', fault); child.once('close', () => { cancel(killer); fault(); });
  } catch { fault(); }
  return () => {
    if (stopped) return;
    stopped = true; cancel(pending);
    child?.stdout?.off('data', data);
    if (child && child.exitCode == null && child.signalCode == null) {
      child.kill('SIGTERM');
      killer = schedule(() => { if (child.exitCode == null && child.signalCode == null) child.kill('SIGKILL'); }, 2000);
      killer?.unref?.();
    }
  };
}

/** Repair owned bypasses even when the old TCP socket has not closed yet. */
export function watchVpnUplink({ repair, disconnect, reconnect, log = console.log,
  schedule = (fn, ms) => setInterval(fn, ms), cancel = clearInterval,
  subscribe = subscribeUplinkEvents }) {
  let stopped = false, unavailable = false, generation = 0;
  const tick = () => {
    if (stopped) return;
    try {
      const count = repair();
      if (count || unavailable) {
        generation++; disconnect(); unavailable = false;
        log(`[clean-vpn] uplink-watch: ready; repaired ${count} owned routes`);
        reconnect();
      }
    } catch (error) {
      if (!unavailable) {
        unavailable = true; generation++; disconnect();
        log(`[clean-vpn] uplink-watch: reconnect postponed: ${error.message}`);
      }
    }
  };
  // Full ownership audits fork several short-lived commands. Polling them
  // every second starves packet processing on slow CPUs. Netlink changes wake
  // the same audit immediately; a periodic audit remains as a safety net.
  let timer = schedule(tick, 10000); timer?.unref?.();
  const stopEvents = subscribe(tick, () => {
    if (stopped) return;
    log('[clean-vpn] uplink-watch: event monitor unavailable; polling every 1s');
    cancel(timer); timer = schedule(tick, 1000); timer?.unref?.(); tick();
  });
  return { get generation() { return generation; }, get available() { return !stopped && !unavailable; },
    stop() { if (stopped) return; stopped = true; generation++; cancel(timer); stopEvents(); } };
}
