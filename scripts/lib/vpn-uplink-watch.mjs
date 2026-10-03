/** Repair owned bypasses even when the old TCP socket has not closed yet. */
export function watchVpnUplink({ repair, disconnect, reconnect, log = console.log,
  schedule = fn => setInterval(fn, 3000), cancel = clearInterval }) {
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
  const timer = schedule(tick); timer?.unref?.();
  return { get generation() { return generation; },
    stop() { stopped = true; generation++; cancel(timer); } };
}
