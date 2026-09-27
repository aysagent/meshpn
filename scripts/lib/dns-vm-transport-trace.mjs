/** Bounded, content-free instrumentation for the separately gated VM preload.
 * No timers, error listeners, socket writes, endpoint names or query contents. */
function phaseTrace({ now, cpu, wall = Date.now, limit = 24 }) {
  const events = [], start = now(), cpuStart = cpu();
  const record = (phase, id) => {
    try {
      const c = cpu();
      events.push({ phase, id, wallMs: wall(), ms: Math.round(now() - start), cpuMs: Math.round((c.user + c.system - cpuStart.user - cpuStart.system) / 1000) });
      if (events.length > limit) events.shift();
    } catch { /* Observing must not affect the operation. */ }
  };
  return { record, snapshot: () => events.map((e) => ({ ...e })) };
}
export function traceVmTransport({ tls, net, https, ...options }) {
  const { record, snapshot } = phaseTrace(options), restore = []; let nextId = 0;
  for (const [object, method, kind, signals] of [
    [tls, 'connect', 'tls', ['secureConnect', 'close']],
    [net, 'connect', 'tcp', ['connect', 'close']],
    [https, 'request', 'http', ['finish', 'response', 'close']],
  ]) {
    const original = object[method];
    const wrapped = function (...args) {
      const id = ++nextId; record(`${kind}:call`, id);
      const result = Reflect.apply(original, this, args);
      record(`${kind}:return`, id);
      for (const signal of signals) result.once(signal, () => record(`${kind}:${signal}`, id));
      return result;
    };
    object[method] = wrapped;
    restore.push(() => { if (object[method] === wrapped) object[method] = original; });
  }
  return { snapshot, close: () => { for (const undo of restore) undo(); } };
}

/** Origin-side phases. Caller enables this only inside the gated VM fixture.
 * Wall time correlates separate processes; monotonic time measures durations. */
export function traceVmHttpsServer(server, options) {
  const { record, snapshot } = phaseTrace(options), ids = new WeakMap(); let nextId = 0;
  const id = (socket) => { if (!ids.has(socket)) ids.set(socket, ++nextId); return ids.get(socket); };
  const connection = (socket) => record('origin:connection', id(socket));
  const secure = (socket) => record('origin:secureConnection', id(socket));
  const request = (req, res) => {
    const n = id(req.socket); record('origin:request', n);
    req.prependOnceListener('end', () => record('origin:requestEnd', n));
    res.once('finish', () => record('origin:responseFinish', n));
    res.once('close', () => record('origin:responseClose', n));
  };
  server.on('connection', connection); server.on('secureConnection', secure); server.on('request', request);
  return { snapshot, close() {
    server.removeListener('connection', connection); server.removeListener('secureConnection', secure); server.removeListener('request', request);
  } };
}
