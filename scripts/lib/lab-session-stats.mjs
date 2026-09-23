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
    pressure(direction) {
      if (!['forward', 'reverse'].includes(direction)) throw new Error('invalid pressure direction');
      const sample = { blocked: 0, readable: 0, writable: 0, overBudget: false };
      for (const session of sessions) {
        if (session.state !== 'streaming' || session.sockets.size !== 2) continue;
        const pair = [...session.sockets];
        const [source, destination] = direction === 'forward' ? pair : pair.reverse();
        if (source.isPaused() && destination.writableNeedDrain) sample.blocked++;
        sample.readable = Math.max(sample.readable, source.readableLength);
        sample.writable = Math.max(sample.writable, destination.writableLength);
        if (source.readableLength > source.readableHighWaterMark + 65536 ||
            destination.writableLength > destination.writableHighWaterMark + 65536) sample.overBudget = true;
      }
      return sample;
    },
  };
}
