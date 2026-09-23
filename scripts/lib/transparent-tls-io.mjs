/** Bounded I/O and lifecycle shared by the two transparent relay endpoints. */
import { parseFirstTlsClientHelloFromTcpBuf } from './tls-clienthello-ja3.mjs';

export const TRANSPARENT_TLS_LIMITS = Object.freeze({
  maxHelloBytes: 64 * 1024,
  maxPendingBytes: 128 * 1024,
  helloTimeoutMs: 10_000,
  connectTimeoutMs: 10_000,
  writeTimeoutMs: 30_000,
});

export function relayError(code, message = code, cause) {
  return Object.assign(new Error(message, cause ? { cause } : undefined), { code });
}

export function relayLimits(overrides = {}) {
  const limits = { ...TRANSPARENT_TLS_LIMITS, ...overrides };
  for (const [key, value] of Object.entries(limits)) {
    if (!(key in TRANSPARENT_TLS_LIMITS) || !Number.isSafeInteger(value) || value < 1 || value > 0x7fffffff) {
      throw relayError('TLS_RELAY_CONFIG', `Invalid transparent TLS limit: ${key}`);
    }
  }
  if (limits.maxHelloBytes > 512 * 1024) throw relayError('TLS_RELAY_CONFIG', 'maxHelloBytes exceeds parser limit');
  return limits;
}

export class RelaySession {
  constructor(socket, options = {}) {
    this.limits = relayLimits(options.limits);
    this.onSessionError = options.onSessionError;
    this.controller = new AbortController();
    this.signal = this.controller.signal;
    this.sockets = new Set();
    this.timers = new Set();
    this.state = 'hello';
    this.closed = new Promise((resolve) => { this.resolveClosed = resolve; });
    this.add(socket);
  }

  timer(ms, callback) {
    const timer = setTimeout(() => {
      this.timers.delete(timer);
      callback();
    }, ms);
    timer.unref?.();
    this.timers.add(timer);
    return () => { clearTimeout(timer); this.timers.delete(timer); };
  }

  add(socket, connectingFailure) {
    this.check();
    if (socket.closed) {
      this.fail(relayError('TLS_RELAY_CLOSED'));
      return socket;
    }
    // Own the two FIN directions independently. Node net.Socket defaults to
    // allowHalfOpen=false and otherwise ends/rejects reverse writes after FIN,
    // before the other peer's final TLS records or application bytes arrive.
    // pump() propagates each EOF; onEnd's absolute close timer bounds the wait.
    socket.allowHalfOpen = true;
    this.sockets.add(socket);
    const onError = (cause) => {
      const error = relayError('TLS_RELAY_SOCKET', 'TLS relay socket failed', cause);
      if (!connectingFailure?.(error)) this.fail(error);
    };
    const onEnd = () => {
      if (this.state !== 'streaming') {
        const error = relayError('TLS_RELAY_EOF', 'EOF before relay is ready');
        if (!connectingFailure?.(error)) this.fail(error);
      }
      else if (!this.cancelCloseTimer) {
        this.cancelCloseTimer = this.timer(this.limits.writeTimeoutMs, () => {
          this.fail(relayError('TLS_RELAY_CLOSE_TIMEOUT'));
        });
      }
    };
    const onClose = () => {
      socket.off('error', onError);
      socket.off('end', onEnd);
      this.sockets.delete(socket);
      if (this.signal.aborted) {
        if (!this.sockets.size) this.resolveClosed(this.error ?? null);
        return;
      }
      if (connectingFailure?.(relayError('TLS_RELAY_CLOSED'))) return;
      if (this.state !== 'streaming' || !socket.readableEnded || !socket.writableFinished) {
        this.fail(relayError('TLS_RELAY_CLOSED', 'TLS relay peer closed'));
      } else if (!this.sockets.size) this.finish();
    };
    // Keep the error guard until close, including errors queued before destroy().
    socket.on('error', onError);
    socket.on('end', onEnd);
    socket.once('close', onClose);
    if (socket.destroyed) this.fail(relayError('TLS_RELAY_CLOSED'));
    return socket;
  }

  check() {
    if (this.signal.aborted) throw this.signal.reason;
  }

  finish(error) {
    if (this.signal.aborted) return;
    this.state = 'closed';
    this.error = error;
    this.controller.abort(error ?? relayError('TLS_RELAY_DONE'));
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
    if (!this.sockets.size) this.resolveClosed(error ?? null);
  }

  fail(error) {
    if (this.signal.aborted) return;
    this.finish(error);
    for (const socket of this.sockets) socket.destroy();
    try { this.onSessionError?.(error); } catch { /* diagnostics cannot prevent teardown */ }
  }

  wait(socket, event, ms, code) {
    this.check();
    return new Promise((resolve, reject) => {
      const cleanup = () => {
        cancel();
        socket.off(event, done);
        this.signal.removeEventListener('abort', aborted);
      };
      const done = () => { cleanup(); resolve(); };
      const aborted = () => { cleanup(); reject(this.signal.reason); };
      const cancel = this.timer(ms, () => this.fail(relayError(code)));
      socket.once(event, done);
      this.signal.addEventListener('abort', aborted, { once: true });
    });
  }

  async connect(factory) {
    this.check();
    this.state = 'connecting';
    let socket;
    try { socket = factory(); }
    catch (cause) { throw relayError('TLS_RELAY_CONNECT', 'TLS relay connect failed', cause); }
    this.add(socket);
    socket.pause();
    this.check();
    if (!socket.connecting && socket.remoteAddress) return socket;
    await this.wait(socket, 'connect', this.limits.connectTimeoutMs, 'TLS_RELAY_CONNECT_TIMEOUT');
    return socket;
  }

  /** A provisional TCP candidate. Only pre-connect failures are recoverable.
   * Retired sockets remain owned until close, including queued error events.
   * After connect, ordinary session fail-closed lifecycle resumes immediately.
   */
  connectCandidate(factory, attemptTimeoutMs) {
    this.check();
    this.state = 'connecting';
    return new Promise((resolve, reject) => {
      let socket, state = 'pending', cancel = () => {};
      const cleanup = () => {
        cancel();
        socket?.off('connect', connected);
        this.signal.removeEventListener('abort', aborted);
      };
      const failed = (error) => {
        if (state === 'connected') return false;
        if (state === 'failed') return true;
        state = 'failed';
        cleanup();
        socket?.destroy();
        reject(error);
        return true;
      };
      const aborted = () => failed(this.signal.reason);
      const connected = () => {
        if (state !== 'pending') return;
        state = 'connected'; cleanup(); resolve(socket);
      };
      try {
        socket = factory();
        this.add(socket, failed);
        socket.pause();
        this.check();
      } catch (cause) {
        failed(cause?.code?.startsWith('TLS_RELAY_') ? cause
          : relayError('TLS_RELAY_CONNECT', 'TLS relay connect failed', cause));
        return;
      }
      if (state !== 'pending') return;
      this.signal.addEventListener('abort', aborted, { once: true });
      socket.once('connect', connected);
      if (attemptTimeoutMs !== undefined) {
        cancel = this.timer(attemptTimeoutMs, () => failed(relayError('TLS_RELAY_CONNECT_ATTEMPT_TIMEOUT')));
      }
      if (!socket.connecting && socket.remoteAddress) connected();
    });
  }

  async write(socket, buffer) {
    this.check();
    if (buffer.length > this.limits.maxPendingBytes) throw relayError('TLS_RELAY_PENDING_LIMIT');
    if (!buffer.length) return;
    if (!socket.write(buffer)) {
      await this.wait(socket, 'drain', this.limits.writeTimeoutMs, 'TLS_RELAY_WRITE_TIMEOUT');
    }
  }

  pump(source, destination, transform, onEnd) {
    this.check();
    let cancelDrainTimer;
    const drain = () => {
      cancelDrainTimer?.();
      cancelDrainTimer = undefined;
      if (!this.signal.aborted) source.resume();
    };
    const data = (chunk) => {
      try {
        const bytes = transform ? transform(chunk) : chunk;
        if (bytes.length && !destination.write(bytes)) {
          source.pause();
          destination.once('drain', drain);
          cancelDrainTimer = this.timer(this.limits.writeTimeoutMs, () => {
            this.fail(relayError('TLS_RELAY_WRITE_TIMEOUT'));
          });
        }
      } catch (cause) {
        this.fail(cause?.code?.startsWith('TLS_RELAY_') ? cause
          : relayError('TLS_RELAY_WRITE', 'TLS relay write failed', cause));
      }
    };
    const end = () => {
      try { onEnd?.(); destination.end(); }
      catch (error) { this.fail(error); }
    };
    const cleanup = () => {
      source.pause();
      source.off('data', data);
      source.off('end', end);
      destination.off('drain', drain);
      cancelDrainTimer?.();
    };
    source.on('data', data);
    source.once('end', end);
    this.signal.addEventListener('abort', cleanup, { once: true });
    if (source.readableEnded) end();
    else source.resume();
  }

  async bridge(source, destination, prelude, guard) {
    this.check();
    this.state = 'streaming';
    guard?.start();
    // Read the response even if writing the prelude is blocked (full duplex).
    this.pump(destination, source, guard?.reverse, guard && (() => guard.end('server')));
    await this.write(destination, prelude);
    this.pump(source, destination, guard?.forward, guard && (() => guard.end('client')));
  }
}

/** Preserve the coalesced tail and pause before yielding to connect/DNS. */
export function readRelayHello(socket, session, initialBuf) {
  session.check();
  socket.pause();
  const { maxHelloBytes, maxPendingBytes, helloTimeoutMs } = session.limits;
  return new Promise((resolve, reject) => {
    let chunks = [];
    let length = 0;
    let nextParseAt = 5;
    const cleanup = () => {
      socket.pause();
      socket.off('data', data);
      session.signal.removeEventListener('abort', aborted);
      cancel();
      chunks = [];
    };
    const aborted = () => { cleanup(); reject(session.signal.reason); };
    const cancel = session.timer(helloTimeoutMs, () => session.fail(relayError('TLS_RELAY_HELLO_TIMEOUT')));
    function data(chunk) {
      if (length + chunk.length > maxHelloBytes + maxPendingBytes) {
        session.fail(relayError('TLS_RELAY_PENDING_LIMIT'));
        return;
      }
      chunks.push(chunk);
      length += chunk.length;
      if (length < nextParseAt) return;
      const buffer = Buffer.concat(chunks, length);
      const parsed = parseFirstTlsClientHelloFromTcpBuf(buffer.subarray(0, maxHelloBytes));
      if (parsed.needMore) {
        nextParseAt = parsed.minTotal ?? length + 1;
        if (nextParseAt > maxHelloBytes || length >= maxHelloBytes) session.fail(relayError('TLS_RELAY_HELLO_LIMIT'));
        return;
      }
      if (!parsed.ok || !parsed.sni?.[0]) {
        session.fail(relayError('TLS_RELAY_HELLO', 'Invalid ClientHello or missing plaintext SNI'));
        return;
      }
      if (buffer.length - parsed.bytesConsumed > maxPendingBytes) {
        session.fail(relayError('TLS_RELAY_PENDING_LIMIT'));
        return;
      }
      cleanup();
      resolve({ buffer, parsed });
    }
    socket.on('data', data);
    session.signal.addEventListener('abort', aborted, { once: true });
    if (initialBuf?.length) data(initialBuf);
    // A resolved initial buffer must stay paused; remaining cases need more data.
    if (!session.signal.aborted && socket.listeners('data').includes(data)) socket.resume();
  });
}
