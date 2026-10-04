/** A received HTTP/2 PING ACK proves liveness; writes/idle timers do not. */
export function watchH2Health(session, wire, { intervalMs = 2000, timeoutMs = 5000,
  schedule = setTimeout, cancel = clearTimeout, log = console.log } = {}) {
  let stopped = false, timer, deadline, pending = false;
  const stop = () => {
    if (stopped) return;
    stopped = true; cancel(timer); cancel(deadline);
    wire.off('close', stop); session.off('close', stop);
  };
  const fail = reason => {
    if (stopped) return;
    stop(); log(`[clean-vpn] h2-health: ${reason}; discard stale transport`);
    // No error injection into a stream whose owner may already have detached.
    wire.destroy();
  };
  const arm = () => { timer = schedule(probe, intervalMs); timer?.unref?.(); };
  const probe = () => {
    if (stopped) return;
    if (wire.destroyed || session.destroyed || session.closed) return stop();
    pending = true;
    deadline = schedule(() => fail('PING ACK timeout'), timeoutMs); deadline?.unref?.();
    try {
      const accepted = session.ping(error => {
        if (stopped || !pending) return;
        pending = false; cancel(deadline);
        if (error) return fail('PING failed');
        arm();
      });
      if (!accepted) fail('PING not accepted');
    } catch { fail('PING unavailable'); }
  };
  wire.once('close', stop); session.once('close', stop); arm();
  return { stop };
}
