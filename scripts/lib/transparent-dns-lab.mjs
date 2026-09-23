/** Synthetic local DoH origin + real transparent relay + explicit UDP/TCP stub. */
import https from 'node:https';
import dgram from 'node:dgram';
import net from 'node:net';
import { readFileSync } from 'node:fs';
import { once } from 'node:events';
import { startTransparentTlsLab, LAB_CERT_PATH } from './transparent-tls-lab.mjs';
import { startLabDohStub } from './lab-doh-stub.mjs';
import { compileLabDnsUpstream } from './dns-upstream-config.mjs';
import { DNS_MAX_BYTES, parseDnsQuery, fixtureDnsAnswer, dnsError } from './lab-dns-wire.mjs';

export async function startTransparentDnsLab({ mode = 'normal', ca, servername = 'localhost', timeoutMs = 1000,
  maxInflight = 8, maxTcpConnections = 8, tcpLifetimeMs = 3000, observeWire, upstreamConfig } = {}) {
  if (upstreamConfig !== undefined && (ca !== undefined || servername !== 'localhost')) throw dnsError('DNS_CONFIG');
  let profile = upstreamConfig === undefined ? undefined : compileLabDnsUpstream(upstreamConfig);
  if (profile) servername = profile.hostname;
  const cert = readFileSync(LAB_CERT_PATH);
  const key = readFileSync(new URL('../fixtures/boring-tls-local.key.pem', import.meta.url));
  const sockets = new Set();
  let requests = 0, closed = false, closePromise, relay, stub;
  const modes = new Set(['normal', 'nxdomain', 'large', 'ttl-zero', 'hold', 'reset', 'redirect', 'bad-type', 'encoding',
    'oversize', 'chunked-oversize', 'bad-id', 'bad-question', 'bad-body', 'partial']);
  const setMode = (value) => { if (!modes.has(value)) throw dnsError('DNS_LAB_MODE'); mode = value; };
  setMode(mode);
  const origin = https.createServer({ key, cert, minVersion: 'TLSv1.3', maxHeaderSize: 8192 }, (req, res) => {
    req.on('error', () => {}); res.on('error', () => {});
    if (req.method !== 'POST' || req.url !== (profile?.path ?? '/dns-query')
      || (profile && req.headers.host !== profile.authority) || req.headers['content-type'] !== 'application/dns-message') {
      res.writeHead(400).end(); return;
    }
    const chunks = []; let size = 0;
    req.on('data', (chunk) => { size += chunk.length; if (size > DNS_MAX_BYTES) req.destroy(); else chunks.push(chunk); });
    req.on('end', () => {
      const query = Buffer.concat(chunks, size);
      try { parseDnsQuery(query); } catch { res.writeHead(400).end(); return; }
      requests++;
      if (mode === 'hold') return;
      if (mode === 'reset') { res.socket.destroy(); return; }
      if (mode === 'redirect') { res.writeHead(302, { location: 'http://127.0.0.1:53/dns-query' }).end(); return; }
      const reply = fixtureDnsAnswer(query, { count: mode === 'large' ? 40 : 1, ttl: mode === 'ttl-zero' ? 0 : 30,
        rcode: mode === 'nxdomain' ? 3 : 0 });
      if (mode === 'bad-id') reply.writeUInt16BE(42);
      if (mode === 'bad-question') reply[13] ^= 1;
      let body = mode === 'bad-body' ? Buffer.from('not dns') : reply;
      if (mode === 'oversize' || mode === 'chunked-oversize') body = Buffer.alloc(DNS_MAX_BYTES + 1);
      const headers = { 'content-type': mode === 'bad-type' ? 'text/html' : 'application/dns-message',
        'cache-control': 'no-store' };
      if (mode !== 'chunked-oversize') headers['content-length'] = body.length;
      if (mode === 'encoding') headers['content-encoding'] = 'gzip';
      res.writeHead(200, headers);
      if (mode === 'partial') { res.write(body.subarray(0, 4)); return; }
      res.end(body);
    });
  });
  origin.on('connection', (socket) => {
    sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket));
    if (closed) socket.destroy();
  });
  origin.on('tlsClientError', () => {});
  async function stopOrigin() {
    const stopped = new Promise((resolve) => origin.listening ? origin.close(resolve) : resolve());
    const closedSockets = [...sockets].map((socket) => new Promise((resolve) => {
      socket.once('close', resolve); socket.destroy();
    }));
    await Promise.all([stopped, ...closedSockets]);
  }
  async function close() {
    if (closePromise) return closePromise;
    closed = true;
    closePromise = (async () => { await stub?.close(); await relay?.close(); await stopOrigin(); })();
    return closePromise;
  }
  try {
    origin.listen(0, '127.0.0.1'); await once(origin, 'listening');
    const originPort = origin.address().port;
    // The ordinary smoke/pcap/soak now exercises the same identity contract.
    // Legacy ca/servername overrides remain only for existing fault injection.
    if (!profile && ca === undefined && servername === 'localhost') profile = compileLabDnsUpstream({
      schema: 1, transport: 'doh', hostname: 'localhost', port: originPort, path: '/dns-query',
      bootstrap: { addresses: ['127.0.0.1'] }, trust: { mode: 'custom', certificates: [cert.toString()] },
    });
    relay = await startTransparentTlsLab({ originName: servername, externalOriginPort: originPort, observeWire, sessionTimeoutMs: 0 });
    const target = profile ? { profile, relayPort: relay.clientPort } : { upstream: { address: '127.0.0.1', port: relay.clientPort,
      servername, authority: `localhost:${originPort}`, ca: ca === undefined ? cert : ca } };
    stub = await startLabDohStub({ ...target, timeoutMs, maxInflight, maxTcpConnections, tcpLifetimeMs });
    return { stub, relay, resolverPort: originPort, setMode, stopOrigin, close,
      async restartOrigin() {
        if (closed || origin.listening) throw dnsError('DNS_LAB_STATE');
        origin.listen(originPort, '127.0.0.1'); await once(origin, 'listening');
      }, stats: () => ({ stub: stub.stats(), resolverRequests: requests, resolverSockets: sockets.size }) };
  } catch (error) { await close(); throw error; }
}

/** Explicit clients: numerical loopback only, never the system resolver. */
export async function queryLabDns(port, packet, { tcp = false, timeoutMs = 3000, fragment = false } = {}) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw dnsError('DNS_CONFIG');
  if (tcp) {
    const socket = net.connect({ host: '127.0.0.1', port });
    const timer = setTimeout(() => socket.destroy(dnsError('DNS_CLIENT_TIMEOUT')), timeoutMs);
    try {
      await once(socket, 'connect');
      const frame = Buffer.alloc(packet.length + 2); frame.writeUInt16BE(packet.length); packet.copy(frame, 2);
      const reply = new Promise((resolve, reject) => {
        let pending = Buffer.alloc(0);
        socket.on('error', reject); socket.on('end', () => reject(dnsError('DNS_CLIENT_EOF')));
        socket.on('data', (chunk) => {
          pending = Buffer.concat([pending, chunk]);
          if (pending.length > DNS_MAX_BYTES + 2) { reject(dnsError('DNS_CLIENT_SIZE')); return; }
          if (pending.length >= 2 && pending.length === pending.readUInt16BE(0) + 2) resolve(Buffer.from(pending.subarray(2)));
        });
      });
      if (fragment) { socket.write(frame.subarray(0, 1)); await new Promise((done) => setImmediate(done)); socket.end(frame.subarray(1)); }
      else socket.end(frame);
      return await reply;
    } finally { clearTimeout(timer); socket.destroy(); }
  }
  const socket = dgram.createSocket('udp4');
  let timer;
  try {
    await new Promise((resolve, reject) => { socket.once('error', reject); socket.connect(port, '127.0.0.1', resolve); });
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(dnsError('DNS_CLIENT_TIMEOUT')), timeoutMs);
      socket.once('error', reject); socket.once('message', resolve); socket.send(packet);
    });
  } finally { clearTimeout(timer); socket.close(); }
}
