/** Explicit loopback-only UDP/TCP -> DoH POST adapter. No OS DNS or fallback. */
import dgram from 'node:dgram';
import net from 'node:net';
import https from 'node:https';
import { once } from 'node:events';
import { DNS_MAX_BYTES, dnsError, parseDnsQuery, validateDnsResponse, dnsFailure } from './lab-dns-wire.mjs';
import { labDnsUpstreamTarget } from './dns-upstream-config.mjs';
import { dnsExitTransportTarget } from './dns-exit-transport.mjs';

export async function startLabDohStub({ port = 0, upstream, profile, relayPort, exitTransport, timeoutMs = 1500, maxInflight = 16,
  maxTcpConnections = 16, tcpLifetimeMs = 5000 } = {}) {
  if (exitTransport !== undefined) {
    if (upstream !== undefined || profile !== undefined || relayPort !== undefined) throw dnsError('DNS_CONFIG');
    upstream = dnsExitTransportTarget(exitTransport);
  } else if (profile !== undefined) {
    if (upstream !== undefined) throw dnsError('DNS_CONFIG');
    upstream = labDnsUpstreamTarget(profile, relayPort);
  } else if (relayPort !== undefined) throw dnsError('DNS_CONFIG');
  const contracted = profile !== undefined || exitTransport !== undefined;
  if (!upstream || (!exitTransport && upstream.address !== '127.0.0.1') || !Number.isInteger(upstream.port)
    || upstream.port < (exitTransport ? 1 : 1024) || upstream.port > 65535
    || typeof upstream.servername !== 'string' || !/^[a-z0-9.-]{1,253}$/i.test(upstream.servername)
    || typeof upstream.authority !== 'string' || (!contracted && !/^localhost:\d{1,5}$/.test(upstream.authority))
    || !Number.isInteger(port) || (port !== 0 && (port < 1024 || port > 65535))) throw dnsError('DNS_CONFIG');
  for (const [value, min, max] of [[timeoutMs, 10, 10000], [maxInflight, 1, 64], [maxTcpConnections, 1, 64], [tcpLifetimeMs, 50, 30000]]) {
    if (!Number.isInteger(value) || value < min || value > max) throw dnsError('DNS_CONFIG');
  }
  // Copy caller configuration; nothing received from a DNS client selects a URL.
  const target = { ...upstream };
  const tcpSockets = new Set(), tlsSockets = new Set(), requests = new Set(), jobs = new Set(), timers = new Set();
  let inflight = 0, peakInflight = 0, closing = false, closePromise, udpBound = false;
  const counts = { queries: 0, forwarded: 0, succeeded: 0, failed: 0, rejected: 0 };
  const errors = {};
  const timer = (ms, fn) => {
    const handle = setTimeout(() => { timers.delete(handle); fn(); }, ms); timers.add(handle);
    return () => { clearTimeout(handle); timers.delete(handle); };
  };
  const track = (socket, set) => {
    set.add(socket); socket.on('error', () => {});
    socket.once('close', () => set.delete(socket)); return socket;
  };
  function doh(query, signal) {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) { reject(dnsError('DNS_ABORTED')); return; }
      let done = false, req;
      const finish = (error, reply) => {
        if (done) return; done = true; cancel();
        signal?.removeEventListener('abort', aborted);
        if (req) { requests.delete(req); req.destroy(); }
        if (error) reject(error); else resolve(reply);
      };
      const cancel = timer(timeoutMs, () => finish(dnsError('DNS_TIMEOUT')));
      const aborted = () => finish(dnsError('DNS_ABORTED'));
      signal?.addEventListener('abort', aborted, { once: true });
      try {
        req = https.request({ host: target.address, port: target.port, servername: target.servername,
          ca: target.ca, rejectUnauthorized: true, minVersion: 'TLSv1.3', agent: exitTransport ? target.agent : false,
          ...(contracted ? { checkServerIdentity: target.checkServerIdentity } : {}),
          method: 'POST', path: contracted ? target.path : '/dns-query', maxHeaderSize: 8192,
          lookup: () => { throw dnsError('DNS_BOOTSTRAP_FORBIDDEN'); },
          headers: { host: target.authority, accept: 'application/dns-message', 'content-type': 'application/dns-message',
            'content-length': query.length, 'cache-control': 'no-store' },
        }, (res) => {
          res.on('aborted', () => finish(dnsError('DNS_HTTP')));
          res.on('error', () => finish(dnsError('DNS_HTTP')));
          const length = res.headers['content-length'];
          if (res.statusCode !== 200 || res.headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/dns-message'
            || res.headers['content-encoding'] || (length !== undefined && (!/^\d+$/.test(length) || Number(length) > DNS_MAX_BYTES))) {
            res.resume(); finish(dnsError('DNS_HTTP')); return;
          }
          const chunks = []; let size = 0;
          res.on('data', (chunk) => {
            if (done) return;
            size += chunk.length;
            if (size > DNS_MAX_BYTES) { finish(dnsError('DNS_SIZE')); return; }
            chunks.push(chunk);
          });
          res.on('end', () => {
            if (done) return;
            try {
              const reply = Buffer.concat(chunks, size); validateDnsResponse(reply, query); finish(null, reply);
            } catch { finish(dnsError('DNS_RESPONSE')); }
          });
        });
        requests.add(req);
        req.on('socket', (socket) => { track(socket, tlsSockets); if (closing || done) socket.destroy(); });
        req.on('error', () => finish(dnsError('DNS_UPSTREAM')));
        req.end(query);
      } catch { finish(dnsError('DNS_UPSTREAM')); }
    });
  }
  async function resolveQuery(query, udp, signal) {
    counts.queries++;
    let parsed;
    try { parsed = parseDnsQuery(query); } catch { counts.rejected++; return null; }
    if (closing) return null;
    if (inflight >= maxInflight) { counts.rejected++; return dnsFailure(query); }
    inflight++; peakInflight = Math.max(peakInflight, inflight); counts.forwarded++;
    try {
      const upstreamQuery = Buffer.from(query); upstreamQuery.writeUInt16BE(0);
      const reply = await doh(upstreamQuery, signal);
      counts.succeeded++;
      if (udp && reply.length > parsed.udpSize) return dnsFailure(query, reply.readUInt16BE(2) & 15, true);
      reply.writeUInt16BE(parsed.id); return reply;
    } catch (error) {
      counts.failed++; errors[error.code] = (errors[error.code] ?? 0) + 1;
      return dnsFailure(query);
    } finally { inflight--; }
  }
  function run(query, udp, reply, signal) {
    const job = resolveQuery(query, udp, signal).then((bytes) => { if (!closing) reply(bytes); });
    jobs.add(job); job.finally(() => jobs.delete(job)).catch(() => {});
    return job;
  }
  const udp = dgram.createSocket('udp4'); udp.on('error', () => {});
  udp.on('message', (query, peer) => {
    if (peer.address !== '127.0.0.1' || query.length > DNS_MAX_BYTES) { counts.rejected++; return; }
    run(query, true, (reply) => { if (reply) udp.send(reply, peer.port, peer.address, () => {}); });
  });
  const tcp = net.createServer({ allowHalfOpen: true }, (socket) => {
    socket.on('error', () => {});
    if (closing || tcpSockets.size >= maxTcpConnections) { socket.destroy(); return; }
    track(socket, tcpSockets);
    const controller = new AbortController(); socket.once('close', () => controller.abort());
    const cancel = timer(tcpLifetimeMs, () => socket.destroy()); socket.once('close', cancel);
    let pending = Buffer.alloc(0), busy = false;
    const pump = () => {
      if (busy || socket.destroyed) return;
      if (pending.length < 2) { if (socket.readableEnded) socket.end(); return; }
      const length = pending.readUInt16BE(0);
      if (length < 12 || length > DNS_MAX_BYTES) { counts.rejected++; socket.destroy(); return; }
      if (pending.length < length + 2) { if (socket.readableEnded) socket.destroy(); return; }
      const query = Buffer.from(pending.subarray(2, length + 2)); pending = pending.subarray(length + 2);
      // Continue reading into the bounded two-frame buffer so RST/close is
      // observable while DoH is pending. Overflow closes, never grows a queue.
      busy = true;
      run(query, false, (reply) => {
        if (!reply) { socket.destroy(); return; }
        if (socket.destroyed) return;
        const frame = Buffer.alloc(reply.length + 2); frame.writeUInt16BE(reply.length); reply.copy(frame, 2);
        socket.write(frame, () => { busy = false; pump(); });
      }, controller.signal);
    };
    socket.on('data', (chunk) => {
      if (pending.length + chunk.length > 2 * (DNS_MAX_BYTES + 2)) { counts.rejected++; socket.destroy(); return; }
      pending = Buffer.concat([pending, chunk]); pump();
    });
    socket.on('end', pump);
  });
  function close() {
    if (closePromise) return closePromise;
    closing = true;
    closePromise = (async () => {
      const tcpClosed = new Promise((resolve) => tcp.listening ? tcp.close(resolve) : resolve());
      const udpClosed = new Promise((resolve) => udpBound ? udp.close(resolve) : resolve());
      for (const req of requests) req.destroy();
      const socketClosed = [...tcpSockets, ...tlsSockets].map((socket) => new Promise((resolve) => {
        socket.once('close', resolve); socket.destroy();
      }));
      await Promise.all([...jobs, tcpClosed, udpClosed, ...socketClosed]);
      for (const handle of timers) clearTimeout(handle); timers.clear();
    })();
    return closePromise;
  }
  try {
    tcp.listen(port, '127.0.0.1'); await once(tcp, 'listening');
    udp.bind(tcp.address().port, '127.0.0.1'); await once(udp, 'listening'); udpBound = true;
  } catch (error) { await close(); try { udp.close(); } catch {} throw error; }
  return { port: tcp.address().port, close, stats: () => ({ ...counts, errors: { ...errors }, inflight, peakInflight,
    tcpSockets: tcpSockets.size, tlsSockets: tlsSockets.size, requests: requests.size, jobs: jobs.size, timers: timers.size }) };
}
