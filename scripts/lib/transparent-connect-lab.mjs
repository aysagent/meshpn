/** Explicit CONNECT front door for the loopback lab, never a general proxy. */
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { RelaySession, relayError } from './transparent-tls-io.mjs';
import { labSessionStats } from './lab-session-stats.mjs';

export async function startLabConnectProxy(lab, {
  port = 0, maxConnections = 32, headerTimeoutMs = 3000,
  connectTimeoutMs = 3000, idleTimeoutMs = 30_000, closeTimeoutMs = 3000,
} = {}) {
  if (!Number.isInteger(port) || (port !== 0 && (port < 1024 || port > 65535))) throw new Error('invalid CONNECT port');
  if (lab.host !== '127.0.0.1' || lab.originName !== 'localhost' ||
      !Number.isInteger(lab.clientPort) || lab.clientPort < 1024 || lab.clientPort > 65535 ||
      !Number.isInteger(lab.originPort) || lab.originPort < 1024 || lab.originPort > 65535) {
    throw new Error('CONNECT lab requires fixed localhost origin and loopback relay');
  }
  if (!Number.isInteger(maxConnections) || maxConnections < 1 || maxConnections > 1024) throw new Error('invalid connection limit');
  for (const value of [headerTimeoutMs, connectTimeoutMs, idleTimeoutMs, closeTimeoutMs]) {
    if (!Number.isInteger(value) || value < 10 || value > 120_000) throw new Error('invalid CONNECT deadline');
  }
  const authority = `localhost:${lab.originPort}`;
  const clients = new Set(), upstreams = new Set(), headerTimers = new Map();
  const relay = labSessionStats();
  let closing = false, closePromise, accepted = 0, rejected = 0, tunnels = 0;
  const clearHeader = (socket) => { clearTimeout(headerTimers.get(socket)); headerTimers.delete(socket); };
  function reject(socket, status) {
    clearHeader(socket);
    rejected++;
    if (socket.destroyed) return;
    socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`, () => socket.destroy());
  }
  const server = http.createServer({ maxHeaderSize: 8192, allowHalfOpen: true }, (_req, res) => {
    clearHeader(res.socket);
    rejected++;
    res.writeHead(405, { connection: 'close', 'content-length': '0' });
    res.end();
  });
  server.maxHeadersCount = 0; // enforce our own count; do not silently truncate
  server.on('connection', (socket) => {
    socket.on('error', () => {});
    if (closing || clients.size >= maxConnections) { reject(socket, '503 Service Unavailable'); return; }
    clients.add(socket);
    accepted++;
    socket.once('close', () => { clearHeader(socket); clients.delete(socket); });
    socket.setTimeout(idleTimeoutMs, () => socket.destroy());
    const timer = setTimeout(() => reject(socket, '408 Request Timeout'), headerTimeoutMs);
    timer.unref();
    headerTimers.set(socket, timer);
  });
  server.on('clientError', (error, socket) => reject(socket,
    error.code === 'HPE_HEADER_OVERFLOW' ? '431 Request Header Fields Too Large' : '400 Bad Request'));
  server.on('connect', (req, socket, head) => {
    clearHeader(socket);
    socket.pause();
    if (closing || !clients.has(socket)) { socket.destroy(); return; }
    const hostCount = req.rawHeaders.filter((_, i) => i % 2 === 0 && req.rawHeaders[i].toLowerCase() === 'host').length;
    if (req.rawHeaders.length > 64) { reject(socket, '431 Request Header Fields Too Large'); return; }
    if (req.httpVersion !== '1.1' || hostCount !== 1 || req.headers['content-length'] !== undefined ||
        req.headers['transfer-encoding'] !== undefined || head.length > 65536) {
      reject(socket, '400 Bad Request'); return;
    }
    if (req.url.toLowerCase() !== authority || req.headers.host?.toLowerCase() !== authority) {
      reject(socket, '403 Forbidden'); return;
    }
    const session = new RelaySession(socket, { limits: { connectTimeoutMs, writeTimeoutMs: closeTimeoutMs } });
    relay.track(session);
    (async () => {
      const upstream = await session.connect(() => {
        const s = net.connect({ host: '127.0.0.1', port: lab.clientPort });
        upstreams.add(s);
        s.once('close', () => upstreams.delete(s));
        return s;
      });
      await session.write(socket, Buffer.from('HTTP/1.1 200 Connection Established\r\n\r\n'));
      tunnels++;
      await session.bridge(socket, upstream, head);
    })().catch((error) => {
      // RelaySession may already have destroyed the pair on connect failure.
      // Never send a false 200 or reconnect to a destination supplied by the user.
      session.fail(error?.code?.startsWith('TLS_RELAY_') ? error : relayError('TLS_RELAY_CONNECT'));
    });
  });
  function close() {
    if (closePromise) return closePromise;
    closing = true;
    for (const timer of headerTimers.values()) clearTimeout(timer);
    headerTimers.clear();
    closePromise = (async () => {
      const stopped = server.listening ? new Promise((resolve) => server.close(resolve)) : Promise.resolve();
      await Promise.all([...clients, ...upstreams].map((socket) => new Promise((resolve) => {
        if (socket.closed) return resolve();
        socket.once('close', resolve);
        socket.destroy();
      })));
      await stopped;
    })();
    return closePromise;
  }
  try {
    server.listen(port, '127.0.0.1');
    await once(server, 'listening');
    return { host: '127.0.0.1', port: server.address().port, authority, close,
      stats: () => ({ accepted, rejected, tunnels, clients: clients.size, upstreams: upstreams.size,
        headerTimers: headerTimers.size, ...relay.stats() }) };
  } catch (error) { await close(); throw error; }
}
