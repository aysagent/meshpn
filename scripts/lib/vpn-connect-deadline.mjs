/** Per-attempt cancellation. Does not alter global TCP/sysctl policy. */
export function watchConnectDeadline(socket, fail, { signal, tcpMs = 3000, totalMs = 10000,
  schedule = setTimeout, cancel = clearTimeout } = {}) {
  let stopped = false, tcp, total;
  const stop = () => {
    if (stopped) return;
    stopped = true; cancel(tcp); cancel(total);
    socket.off('connect', connected); signal?.removeEventListener('abort', aborted);
  };
  const failed = message => {
    if (stopped) return;
    stop(); fail(new Error(message));
  };
  const connected = () => { cancel(tcp); tcp = null; };
  const aborted = () => failed('TLS attempt cancelled: uplink changed or client stopped');
  if (signal?.aborted) { aborted(); return stop; }
  socket.once('connect', connected); signal?.addEventListener('abort', aborted, { once: true });
  tcp = schedule(() => failed('TLS TCP connect deadline'), tcpMs); tcp?.unref?.();
  total = schedule(() => failed('TLS handshake/response deadline'), totalMs); total?.unref?.();
  return stop;
}
