/** Loopback-only bounded capture page. No routes, trust store or engine mutation. */
import net from 'node:net';
import http2 from 'node:http2';
import { randomBytes, constants } from 'node:crypto';
import { once } from 'node:events';
import { BrowserCapture } from './native-browser-capture.mjs';
import { parseFirstTlsClientHelloFromTcpBuf } from './tls-clienthello-ja3.mjs';

export async function startBrowserCapture({ cert, key, metadata, maxSamples = 32, lifetimeMs = 180000 }) {
  if (!Number.isInteger(lifetimeMs) || lifetimeMs < 1000 || lifetimeMs > 600000) throw Error('capture_lifetime');
  const capture = new BrowserCapture(metadata, { maxSamples });
  const token = randomBytes(24).toString('hex');
  const sockets = new Set(), sessions = new Set(), connections = new Map();
  let front, timer, closed = false;
  const backend = http2.createSecureServer({ cert, key, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
    allowHTTP1: false, secureOptions: constants.SSL_OP_NO_TICKET, numTickets: 0,
    handshakeTimeout: 5000, maxSessionMemory: 2, maxHeaderListPairs: 32,
    settings: { maxConcurrentStreams: 4, maxHeaderListSize: 8192 } });
  backend.on('error', () => {});
  backend.on('tlsClientError', () => {});
  backend.on('session', session => {
    sessions.add(session); session.setTimeout(10000, () => session.destroy());
    session.on('error', () => {}); session.on('close', () => sessions.delete(session));
  });
  const headers = { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" };
  backend.on('request', (req, res) => {
    req.on('error', () => {}); res.on('error', () => {});
    const authority = `localhost:${front.address()?.port}`;
    if (req.method !== 'GET' || req.headers[':authority'] !== authority || req.headers.origin
      || ![`/capture/${token}`, `/bundle/${token}`].includes(req.url)) {
      res.writeHead(404, headers); res.end(); return;
    }
    if (req.url === `/bundle/${token}`) {
      res.writeHead(200, { ...headers, 'content-type': 'application/json',
        'content-disposition': 'attachment; filename="browser-capture.json"' });
      res.end(JSON.stringify(capture.snapshot(), null, 2)); return;
    }
    const connection = connections.get(req.socket.remotePort);
    if (!connection || (!connection.wire && !connection.saved)) { res.writeHead(409, headers); res.end('Capture unavailable'); return; }
    try {
      if (!connection.saved) {
        capture.add(connection.wire, { alpn: req.socket.alpnProtocol, tlsVersion: req.socket.getProtocol(),
          sessionReused: req.socket.isSessionReused() });
        connection.saved = true; connection.wire = null;
      }
      const assessment = capture.snapshot().assessment;
      res.writeHead(200, { ...headers, 'content-type': 'text/html; charset=utf-8' });
      // Only fixed text, bounded numeric counts and the generated hex token enter HTML.
      res.end(`<!doctype html><html lang="ru"><meta charset="utf-8"><title>Захват TLS</title>
<h1>ClientHello сохранён</h1><p>Образцов: ${assessment.sampleCount}. Статус: ${assessment.status}.</p>
<p>Для следующего cold-образца нужен новый процесс браузера с отдельным профилем.
Обновление страницы не гарантирует новое TLS-соединение.</p>
<p>Это измерение; профиль VPN не изменён. Совпадение JA3/JA4 не доказывает сходство всего браузера.</p>
<a href="/bundle/${token}">Скачать измерения и отчёт совместимости</a></html>`);
    } catch {
      res.writeHead(capture.size >= maxSamples ? 429 : 422, headers); res.end('Capture refused');
    }
  });
  async function close() {
    if (closed) return; closed = true; clearTimeout(timer);
    for (const s of sessions) s.destroy();
    for (const s of sockets) s.destroy();
    connections.clear();
    await Promise.all([front, backend].filter(s => s?.listening).map(s => new Promise(r => s.close(r))));
  }
  try {
    backend.listen(0, '127.0.0.1'); await once(backend, 'listening');
    front = net.createServer({ pauseOnConnect: true }, client => {
      if (connections.size >= 8) { client.destroy(); return; }
      const upstream = net.connect(backend.address().port, '127.0.0.1');
      const connection = { wire: null, saved: false }; let port, bytes = Buffer.alloc(0), done = false;
      for (const socket of [client, upstream]) {
        sockets.add(socket); socket.setTimeout(10000, () => socket.destroy());
        socket.on('error', () => { client.destroy(); upstream.destroy(); });
        socket.on('close', () => { sockets.delete(socket); connections.delete(port); client.destroy(); upstream.destroy(); });
      }
      client.on('data', chunk => {
        if (done) return;
        if (bytes.length + chunk.length > 65536) { client.destroy(); return; }
        bytes = Buffer.concat([bytes, chunk]);
        const parsed = parseFirstTlsClientHelloFromTcpBuf(bytes);
        if (parsed.ok) { connection.wire = Buffer.from(bytes.subarray(0, parsed.bytesConsumed)); done = true; bytes = null; }
        else if (!parsed.needMore) client.destroy();
      });
      upstream.once('connect', () => {
        port = upstream.localPort; connections.set(port, connection);
        client.pipe(upstream); upstream.pipe(client); client.resume();
      });
    });
    front.maxConnections = 8;
    front.listen(0, '127.0.0.1'); await once(front, 'listening');
    timer = setTimeout(() => { void close(); }, lifetimeMs);
    return { url: `https://localhost:${front.address().port}/capture/${token}`,
      bundleUrl: `https://localhost:${front.address().port}/bundle/${token}`,
      snapshot: () => capture.snapshot(), close };
  } catch (error) { await close(); throw error; }
}
