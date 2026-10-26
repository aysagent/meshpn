/** Loopback-only bounded capture page. No routes, trust store or engine mutation. */
import net from 'node:net';
import http2 from 'node:http2';
import tls from 'node:tls';
import { Http2PrefixObserver } from './http2-prefix-observer.mjs';
import { randomBytes, constants } from 'node:crypto';
import { once } from 'node:events';
import { BrowserCapture } from './native-browser-capture.mjs';
import { parseFirstTlsClientHelloFromTcpBuf } from './tls-clienthello-ja3.mjs';

export async function startBrowserCapture({ cert, key, metadata, maxSamples = 32, lifetimeMs = 180000, nativeProbe = false }) {
  if (!Number.isInteger(lifetimeMs) || lifetimeMs < 1000 || lifetimeMs > 600000) throw Error('capture_lifetime');
  const capture = new BrowserCapture(metadata, { maxSamples });
  const token = randomBytes(24).toString('hex');
  const sockets = new Set(), sessions = new Set(), connections = new Map();
  if(typeof nativeProbe!=='boolean')throw Error('capture_probe_mode');
  const requests = new Map();
  let front, terminator, timer, closing;
  // Explicit loopback TLS -> H2 bridge keeps an independent view of plaintext
  // before Node/nghttp2 owns it. No TLS key log or HPACK payload is exported.
  const backend = http2.createServer({ maxSessionMemory: 2, maxHeaderListPairs: 32,
    settings: { maxConcurrentStreams: 4, maxHeaderListSize: 8192 } });
  const track = socket => {
    sockets.add(socket); socket.setTimeout(10000, () => socket.destroy());
    socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
  };
  backend.on('connection', track); backend.maxConnections = 8;
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
    const connection = requests.get(req.socket.remotePort);
    const probeRequest = nativeProbe && req.method === 'POST' && req.url === '/clean-vpn' && req.headers[':authority'] === 'localhost';
    if (!probeRequest && (req.method !== 'GET' || req.headers[':authority'] !== authority || req.headers.origin
      || ![`/capture/${token}`, `/bundle/${token}`].includes(req.url))) {
      res.writeHead(404, headers); res.end(); return;
    }
    if (req.url === `/bundle/${token}`) {
      res.writeHead(200, { ...headers, 'content-type': 'application/json',
        'content-disposition': 'attachment; filename="browser-capture.json"' });
      res.end(JSON.stringify(capture.snapshot(), null, 2)); return;
    }
    if (!connection || (!connection.wire && !connection.saved)) { res.writeHead(409, headers); res.end('Capture unavailable'); return; }
    try {
      if (!connection.saved) {
        capture.add(connection.wire, connection.negotiated, connection.http2.snapshot(req.rawHeaders, req.stream.id));
        connection.saved = true; connection.wire = null;
      }
      if(probeRequest) {
        // Measurement only: never authenticate a VPN, echo or accept packets.
        req.resume(); res.writeHead(403, headers); res.end(); return;
      }
      const assessment = capture.snapshot().assessment;
      res.writeHead(200, { ...headers, 'content-type': 'text/html; charset=utf-8' });
      // Only fixed text, bounded numeric counts and the generated hex token enter HTML.
      res.end(`<!doctype html><html lang="ru"><meta charset="utf-8"><title>Захват TLS</title>
<h1>ClientHello сохранён</h1><p>Полных HTTP/2-образцов: ${assessment.http2CompleteSamples}. Измеряются SETTINGS, окна и разрешённые поля заголовков.</p><p>Образцов: ${assessment.sampleCount}. Статус: ${assessment.status}.</p>
<p>Для следующего cold-образца нужен новый процесс браузера с отдельным профилем.
Обновление страницы не гарантирует новое TLS-соединение.</p>
<p>Это измерение; профиль VPN не изменён. Совпадение JA3/JA4 не доказывает сходство всего браузера.</p>
<a href="/bundle/${token}">Скачать измерения и отчёт совместимости</a></html>`);
    } catch {
      res.writeHead(capture.size >= maxSamples ? 429 : 422, headers); res.end('Capture refused');
    }
  });
  function close() {
    if (closing) return closing; clearTimeout(timer);
    for (const s of sessions) s.destroy();
    for (const s of sockets) s.destroy();
    connections.clear(); requests.clear();
    closing = Promise.all([front, terminator, backend].filter(s => s?.listening).map(s => new Promise(r => s.close(r)))).then(()=>{});
    return closing;
  }
  try {
    backend.listen(0, '127.0.0.1'); await once(backend, 'listening');
    terminator = tls.createServer({ cert, key, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
      ALPNProtocols: ['h2'], secureOptions: constants.SSL_OP_NO_TICKET, numTickets: 0, handshakeTimeout: 5000 }, socket => {
      track(socket); socket.pause();
      const connection = connections.get(socket.remotePort);
      if(!connection || socket.alpnProtocol !== 'h2') { socket.destroy(); return; }
      connection.negotiated = { alpn: socket.alpnProtocol, tlsVersion: socket.getProtocol(), sessionReused: socket.isSessionReused() };
      connection.http2 = new Http2PrefixObserver();
      const upstream = net.connect(backend.address().port, '127.0.0.1'); track(upstream); let requestPort;
      for(const s of [socket,upstream]) {
        s.on('error',()=>{ socket.destroy(); upstream.destroy(); });
        s.on('close',()=>{ requests.delete(requestPort); socket.destroy(); upstream.destroy(); });
      }
      socket.on('data', bytes=>connection.http2.feed(bytes));
      upstream.once('connect',()=>{
        requestPort=upstream.localPort; requests.set(requestPort,connection);
        socket.pipe(upstream); upstream.pipe(socket); socket.resume();
      });
    });
    terminator.on('error',()=>{}); terminator.on('tlsClientError',()=>{});
    terminator.on('connection',track); terminator.maxConnections=8;
    terminator.listen(0,'127.0.0.1'); await once(terminator,'listening');
    front = net.createServer({ pauseOnConnect: true }, client => {
      if (connections.size >= 8) { client.destroy(); return; }
      const upstream = net.connect(terminator.address().port, '127.0.0.1');
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
