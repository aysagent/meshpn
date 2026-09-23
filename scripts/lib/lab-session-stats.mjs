/** Test-only accounting of returned RelaySession handles; never retains closed sessions. */
export function labSessionStats() {
  const sessions = new Set();
  let cleanupFailures = 0;
  return {
    track(session) {
      if (!session) return;
      sessions.add(session);
      void session.closed.then(() => {
        if (session.sockets.size || session.timers.size) cleanupFailures++;
        sessions.delete(session);
      });
    },
    stats() {
      let relayTimers = 0;
      for (const session of sessions) relayTimers += session.timers.size;
      return { relaySessions: sessions.size, relayTimers, cleanupFailures };
    },
  };
}
