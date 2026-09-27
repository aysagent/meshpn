/** Bounded, content-free instrumentation for the separately gated VM preload.
 * No timers, error listeners, socket writes, endpoint names or query contents. */
export function traceVmTransport({ tls, net, https, now, cpu, limit = 24 }) {
  const events = [], restore = [], start = now(), cpuStart = cpu(); let nextId = 0;
  const record = (phase, id) => {
    try {
      const c = cpu();
      events.push({ phase, id, ms: Math.round(now() - start), cpuMs: Math.round((c.user + c.system - cpuStart.user - cpuStart.system) / 1000) });
      if (events.length > limit) events.shift();
    } catch { /* Observing must not affect the operation. */ }
  };
  for (const [object, method, kind, signals] of [
    [tls, 'connect', 'tls', ['secureConnect', 'close']],
    [net, 'connect', 'tcp', ['connect', 'close']],
    [https, 'request', 'http', ['response', 'close']],
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
  return { snapshot: () => events.map((e) => ({ ...e })), close: () => { for (const undo of restore) undo(); } };
}
