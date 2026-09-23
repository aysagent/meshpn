/** Loopback-only integration harness. No TUN, native addons, DNS or firewall changes. */
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import http2 from 'node:http2';
import net from 'node:net';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';
import {
  attachTransparentTlsClientSession,
  wireTransparentTlsEncSniSession,
} from './transparent-tls-runtime.mjs';
import { ja3FromTcpBuf, parseFirstTlsClientHelloFromTcpBuf } from './tls-clienthello-ja3.mjs';
import { ja4FromTcpBuf } from './tls-clienthello-ja4.mjs';

export const LAB_CERT_PATH = fileURLToPath(new URL('../fixtures/boring-tls-local.cert.pem', import.meta.url));
const LAB_KEY_PATH = fileURLToPath(new URL('../fixtures/boring-tls-local.key.pem', import.meta.url));
const HOST = '127.0.0.1';
const MAX_CAPTURE_BYTES = 64 * 1024;
const MAX_CAPTURES = 128;
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const MAX_SESSION_BYTES = 64 * 1024;

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function validatePort(port) {
  if (!Number.isInteger(port) || (port !== 0 && (port < 1024 || port > 65535))) {
    throw new Error('Lab ports must be 0 (automatic) or an integer in 1024..65535');
  }
}

/** Passive capture of up to two plaintext ClientHellos; no runtime guard reuse. */
function captureHello(socket, stage, captures, diagnose) {
  let pending = Buffer.alloc(0);
  let records = [];
  let size = 0;
  let chunkCount = 0;
  let flight = 0;
  let opaqueBytes = 0;
  let stopped = false;
  const cleanup = () => {
    stopped = true;
    socket.off('data', onData);
    socket.off('close', cleanup);
    pending = Buffer.alloc(0);
    records = [];
  };
  const onData = (chunk) => {
    chunkCount++;
    if (pending.length + chunk.length + size > MAX_CAPTURE_BYTES) {
      diagnose(`${stage}: capture limit exceeded`);
      cleanup();
      return;
    }
    pending = Buffer.concat([pending, chunk]);
    while (pending.length >= 5) {
      const type = pending[0];
      // Skip bounded opaque early data so an HRR's CH2 can still be captured.
      if (type !== 0x16 && type !== 0x14 && type !== 0x17) { cleanup(); return; }
      const length = pending.readUInt16BE(3) + 5;
      if (pending.length < length) return;
      const record = pending.subarray(0, length);
      pending = pending.subarray(length);
      if (type === 0x17) {
        opaqueBytes += length;
        if (!flight || records.length || opaqueBytes > MAX_CAPTURE_BYTES) { cleanup(); return; }
        continue;
      }
      if (type === 0x14) continue;
      records.push(record);
      size += length;
      const bytes = Buffer.concat(records, size);
      const parsed = parseFirstTlsClientHelloFromTcpBuf(bytes);
      if (parsed.needMore) continue;
      if (!parsed.ok) { diagnose(`${stage}: ${parsed.reason}`); cleanup(); return; }
      const prefix = Buffer.from(bytes.subarray(0, parsed.bytesConsumed));
      const body = Buffer.from(parsed.clientHelloBody);
      captures.push({
        stage, flight: ++flight, peerPort: socket.remotePort,
        id: body.subarray(2, 34).toString('hex'), body, prefix,
        sni: parsed.sni[0], records: records.map((r) => r.readUInt16BE(3)), chunkCount,
        ja3: ja3FromTcpBuf(prefix)?.ja3Digest,
        ja4: ja4FromTcpBuf(prefix)?.fingerprint,
      });
      if (captures.length > MAX_CAPTURES) captures.shift();
      records = [];
      size = 0;
      chunkCount = 0;
      if (flight === 2) { cleanup(); return; }
    }
  };
  socket.on('data', onData);
  socket.once('close', cleanup);
}
/**
 * All listeners bind IPv4 loopback; all outgoing sockets are pinned to loopback.
 * The extra origin tap observes raw TLS before forwarding to the local HTTPS server.
 * Only the real runtime functions perform SNI rewrite/restore.
 */
export async function startTransparentTlsLab({
  clientPort = 0, exitPort = 0, originPort = 0,
  originName = 'localhost', publicName = 'relay.test',
  clientPsk, sessionTimeoutMs = 10_000, originTls = {}, clientLimits, exitLimits,
  externalOriginPort,
} = {}) {
  for (const port of [clientPort, exitPort, originPort]) validatePort(port);
  if (externalOriginPort !== undefined) {
    validatePort(externalOriginPort);
    if (!externalOriginPort) throw new Error('external origin must have a bound loopback port');
  }
  if (!Number.isInteger(sessionTimeoutMs) || (sessionTimeoutMs !== 0 && sessionTimeoutMs < 100)) {
    throw new Error('sessionTimeoutMs must be 0 (disabled) or an integer >= 100');
  }
  const psk = randomBytes(32);
  const cert = readFileSync(LAB_CERT_PATH);
  const key = readFileSync(LAB_KEY_PATH);
  const captures = [];
  const diagnostics = [];
  const runtimeErrors = [];
  const onRuntimeError = (role) => (error) => {
    runtimeErrors.push({ role, code: error.code });
    if (runtimeErrors.length > MAX_CAPTURES) runtimeErrors.shift();
  };
  // Keep diagnostics bounded too, including repeated malformed connections in --serve.
  const diagnose = (message) => {
    diagnostics.push(message);
    if (diagnostics.length > MAX_CAPTURES) diagnostics.splice(0, diagnostics.length - MAX_CAPTURES);
  };
  const sockets = new Set();
  const servers = [];
  let closing = false;
  let closePromise;
  let originConnections = 0;
  let tlsConnections = 0;
  let resumedTlsConnections = 0;
  let requests = 0;

  function track(socket) {
    sockets.add(socket);
    socket.on('error', (error) => diagnose(error.message));
    socket.once('close', () => sockets.delete(socket));
    // This is harness containment, not a claim that production relay has this timeout.
    if (sessionTimeoutMs) socket.setTimeout(sessionTimeoutMs, () => socket.destroy());
    if (closing) socket.destroy();
    return socket;
  }

  async function listen(server, port) {
    servers.push(server);
    server.on('connection', track);
    server.on('error', (error) => diagnose(error.message));
    server.listen(port, HOST);
    await once(server, 'listening');
    return server.address().port;
  }

  function close() {
    if (closePromise) return closePromise;
    closing = true;
    const stopped = Promise.all(servers.map((server) => new Promise((resolve) => {
      if (!server.listening) return resolve();
      server.close(() => resolve());
    })));
    const destroyTracked = () => Promise.all([...sockets].map((socket) => new Promise((resolve) => {
      if (socket.closed) {
        sockets.delete(socket);
        return resolve();
      }
      socket.once('close', resolve);
      socket.destroy();
    })));
    closePromise = (async () => {
      await destroyTracked();
      await stopped;
      // Include sockets accepted during the shutdown race, if any.
      while (sockets.size) await destroyTracked();
    })();
    return closePromise;
  }

  try {
    const originContext = {
      key, cert, allowHTTP1: true, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3',
      sessionIdContext: 'transparent-tls-lab',
      ...originTls,
    };
    const origin = http2.createSecureServer(originContext);
    const originH2Sessions = new Set();
    origin.on('secureConnection', (socket) => {
      track(socket);
      tlsConnections++;
      if (socket.isSessionReused()) resumedTlsConnections++;
    });
    origin.on('session', (session) => {
      originH2Sessions.add(session);
      session.once('close', () => originH2Sessions.delete(session));
      session.on('error', (error) => diagnose(error.message));
      session.setTimeout(sessionTimeoutMs, () => session.destroy());
    });
    origin.on('tlsClientError', (error) => diagnose(error.message));
    origin.on('request', (req, res) => {
      requests++;
      const body = [];
      let size = 0;
      req.on('error', (error) => diagnose(error.message));
      res.on('error', (error) => diagnose(error.message));
      req.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          req.destroy(new Error('lab request body limit exceeded'));
          return;
        }
        body.push(chunk);
      });
      req.on('end', () => {
        if (req.url === '/browser') {
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
          res.end('<!doctype html><title>Transparent TLS lab</title><link rel="icon" href="data:,"><p>Loopback browser test origin.</p>');
          return;
        }
        const payload = Buffer.concat(body);
        const reply = req.url === '/echo' ? payload : Buffer.from(JSON.stringify({
          ok: true, origin: 'transparent-tls-loopback-lab',
          httpVersion: req.httpVersion, tlsVersion: req.socket.getProtocol(),
          alpn: req.socket.alpnProtocol, servername: req.socket.servername,
          sessionReused: req.socket.isSessionReused(),
          userAgent: String(req.headers['user-agent'] ?? '').slice(0, 1024),
          receivedBytes: payload.length, receivedSha256: sha256(payload),
        }));
        res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': reply.length });
        res.end(reply);
      });
    });
    // Programmatic test hook only: the destination address is still fixed loopback.
    const backendPort = externalOriginPort ?? await listen(origin, 0);

    const originTap = net.createServer({ allowHalfOpen: true }, (socket) => {
      originConnections++;
      captureHello(socket, 'origin', captures, diagnose);
      const upstream = track(net.connect({ host: HOST, port: backendPort, allowHalfOpen: true }));
      socket.pipe(upstream).pipe(socket);
      socket.once('close', () => upstream.destroy());
      upstream.once('close', () => socket.destroy());
    });
    const boundOriginPort = await listen(originTap, originPort);

    const exit = net.createServer((socket) => {
      captureHello(socket, 'exit', captures, diagnose);
      wireTransparentTlsEncSniSession(socket, {
        vpnSecretBuf: psk, publicName, logOpts: {},
        limits: exitLimits, onSessionError: onRuntimeError('exit'),
        connectOrigin(hostname, port) {
          // The lab is never a general proxy, even with forged route metadata.
          if (hostname !== originName || port !== boundOriginPort) {
            throw new Error('lab denies destination outside its configured origin');
          }
          return track(net.connect({ host: HOST, port: boundOriginPort }));
        },
      });
    });
    const boundExitPort = await listen(exit, exitPort);

    const client = net.createServer((socket) => {
      captureHello(socket, 'client', captures, diagnose);
      attachTransparentTlsClientSession(socket, {
        upstreamHost: HOST, upstreamPort: boundExitPort,
        vpnSecretBuf: clientPsk ?? psk, publicName,
        explicitDestination: { address: HOST, port: boundOriginPort },
        logOpts: {}, limits: clientLimits, onSessionError: onRuntimeError('client'),
      }).catch((error) => {
        diagnose(error.message);
        socket.destroy();
      });
    });
    const boundClientPort = await listen(client, clientPort);

    return {
      host: HOST, originName, publicName, cert, captures, diagnostics, runtimeErrors, track, close,
      clientPort: boundClientPort, exitPort: boundExitPort, originPort: boundOriginPort,
      stats: () => ({ originConnections, sockets: sockets.size,
        tlsConnections: externalOriginPort ? null : tlsConnections,
        resumedTlsConnections: externalOriginPort ? null : resumedTlsConnections,
        requests: externalOriginPort ? null : requests }),
      // Lab-only controls, no ticket key material returned to the caller or logged.
      async drainOriginHttp2() {
        if (closing) throw new Error('lab is closing');
        if (externalOriginPort) throw new Error('external origin controls its own HTTP/2 sessions');
        // GOAWAY followed by graceful session close; do not erase browser TLS tickets.
        // Only call between completed requests. Hanging streams fail this test control.
        await Promise.all([...originH2Sessions].map(async (session) => {
          const closed = once(session, 'close', { signal: AbortSignal.timeout(5000) });
          session.close();
          await closed;
        }));
      },
      rotateTicketKeys() {
        if (closing) throw new Error('lab is closing');
        if (externalOriginPort) throw new Error('external origin controls its own TLS context');
        origin.setTicketKeys(randomBytes(48));
      },
      setOriginGroups(ecdhCurve) {
        if (closing) throw new Error('lab is closing');
        if (externalOriginPort) throw new Error('external origin controls its own TLS context');
        if (typeof ecdhCurve !== 'string' || !ecdhCurve) throw new Error('non-empty ecdhCurve required');
        origin.setSecureContext({ ...originContext, ecdhCurve, ticketKeys: origin.getTicketKeys() });
      },
    };
  } catch (error) {
    await close();
    throw error;
  }
}

/** Check one real session by its ClientHello random, not by connection timing/order. */
export function assertRelayTrace(lab, id, flight = 1) {
  const client = id
    ? lab.captures.find((c) => c.stage === 'client' && c.id === id && c.flight === flight)
    : lab.captures.findLast((c) => c.stage === 'client' && c.flight === flight);
  assert.ok(client, 'captured application ClientHello');
  const exit = lab.captures.find((c) => c.stage === 'exit' && c.id === client.id && c.flight === flight);
  const origin = lab.captures.find((c) => c.stage === 'origin' && c.id === client.id && c.flight === flight);
  assert.ok(exit, 'captured enc-SNI ClientHello at exit');
  assert.ok(origin, 'captured restored ClientHello at origin');
  assert.equal(client.sni, lab.originName);
  assert.notEqual(exit.sni, client.sni);
  assert.ok(exit.sni.endsWith(`.${lab.publicName}`));
  assert.equal(origin.sni, client.sni);
  assert.deepEqual(origin.body, client.body, 'origin receives identical handshake body');
  assert.deepEqual(origin.prefix, client.prefix, 'origin receives identical TLS records including coalesced bytes');
  assert.notDeepEqual(exit.body, client.body, 'SNI actually changed on client→exit leg');
  assert.ok(client.ja3 && client.ja4, 'both fingerprints were parsed');
  for (const capture of [exit, origin]) {
    assert.equal(capture.ja3, client.ja3, `${capture.stage}: JA3 preserved`);
    assert.equal(capture.ja4, client.ja4, `${capture.stage}: JA4 preserved`);
  }
  return {
    ja3: client.ja3, ja4: client.ja4, clientHelloSha256: sha256(client.body),
    restored: true, recordsRestored: true,
    records: { client: client.records, exit: exit.records, origin: origin.records },
  };
}

/** Real verified HTTPS request. No certificate bypass; transport destination is explicit. */
export async function requestThroughLab(lab, {
  httpVersion = '1.1', body = Buffer.alloc(0), path = '/', ca = lab.cert,
  tlsOptions = {}, port = lab.clientPort, timeoutMs = 5000, captureSession = false,
} = {}) {
  const socket = lab.track(tls.connect({
    host: lab.host, port, servername: lab.originName, ca,
    minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
    ALPNProtocols: httpVersion === '2' ? ['h2'] : ['http/1.1'],
    ...tlsOptions, rejectUnauthorized: true,
  }));
  let capturedSession;
  const onSession = (state) => {
    if (state.length > MAX_SESSION_BYTES) {
      socket.destroy(new Error('lab session state limit exceeded'));
      return;
    }
    capturedSession = Buffer.from(state);
  };
  // TLS 1.3 tickets arrive after secureConnect. Keep at most one and only opt-in.
  if (captureSession) socket.once('session', onSession);
  let session;
  const deadline = setTimeout(() => {
    socket.destroy(new Error('lab request deadline exceeded'));
    session?.destroy();
  }, timeoutMs);
  try {
    await once(socket, 'secureConnect');
    assert.equal(socket.authorized, true);
    assert.equal(socket.alpnProtocol, httpVersion === '2' ? 'h2' : 'http/1.1');
    const tlsVersion = socket.getProtocol();
    const sessionReused = socket.isSessionReused();
    const clientHelloId = lab.captures.findLast((c) => c.stage === 'client' &&
      c.flight === 1 && c.peerPort === socket.localPort)?.id;
    const result = (payload) => {
      const response = { body: payload, tlsVersion, httpVersion, sessionReused, clientHelloId };
      // Resumable state is sensitive: opt-in, memory-only, omitted by JSON.stringify.
      if (captureSession) Object.defineProperty(response, 'session', { value: capturedSession });
      return response;
    };
    if (httpVersion === '2') {
      session = http2.connect(`https://${lab.originName}:${lab.originPort}`, {
        createConnection: () => socket,
      });
      // Always consume errors, including races during shutdown after an assertion.
      session.on('error', () => {});
      const req = session.request({ ':method': 'POST', ':path': path });
      let status;
      const chunks = [];
      req.on('response', (headers) => { status = headers[':status']; });
      req.on('data', (chunk) => chunks.push(chunk));
      const ended = once(req, 'end');
      req.end(body);
      await ended;
      assert.equal(status, 200);
      return result(Buffer.concat(chunks));
    }
    const chunks = [];
    socket.on('data', (chunk) => chunks.push(chunk));
    const ended = once(socket, 'end');
    socket.write(`POST ${path} HTTP/1.1\r\nHost: ${lab.originName}:${lab.originPort}\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`);
    socket.write(body);
    await ended;
    const response = Buffer.concat(chunks);
    const split = response.indexOf('\r\n\r\n');
    assert.ok(split > 0, 'complete HTTP/1.1 response headers');
    const headers = response.subarray(0, split).toString('latin1');
    assert.match(headers, /^HTTP\/1\.1 200 /);
    const payload = response.subarray(split + 4);
    assert.equal(payload.length, Number(/\r\ncontent-length: (\d+)/i.exec(headers)?.[1]));
    return result(payload);
  } finally {
    clearTimeout(deadline);
    socket.off('session', onSession);
    session?.destroy();
    socket.destroy();
  }
}
