/** Bounded plain-DNS listener for tunnel forwarding. The caller owns TUN
 * routing and firewall scope; this server never installs or changes either. */
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import { once } from 'node:events';
import { DNS_MAX_BYTES, DNS_UDP_MAX_BYTES, parseDnsQuery, validateDnsResponse, dnsFailure, truncateDnsResponse } from './lab-dns-wire.mjs';

export const TUNNEL_DNS_ADDRESS = '10.99.0.2';
export const TUNNEL_DNS_PORT = 1053;
export async function startTunnelDnsStub({ forwarder, address = TUNNEL_DNS_ADDRESS, port = TUNNEL_DNS_PORT,
  maxInflight = 16, maxTcpConnections = 16, tcpLifetimeMs = 10000 } = {}) {
  assert.ok(forwarder && typeof forwarder.resolve === 'function' && typeof forwarder.close === 'function');
  // Loopback is a JS test option, not a CLI override of the installed bind.
  assert.ok(address === TUNNEL_DNS_ADDRESS || address === '127.0.0.1');
  assert.ok(Number.isInteger(port) && (port === 0 || port >= 1024 && port <= 65535));
  for (const value of [maxInflight, maxTcpConnections]) assert.ok(Number.isInteger(value) && value >= 1 && value <= 64);
  assert.ok(Number.isInteger(tcpLifetimeMs) && tcpLifetimeMs >= 50 && tcpLifetimeMs <= 30000);
  const sockets = new Set(), jobs = new Set(), timers = new Set();
  let closing = false, closePromise, udpBound = false;
  const counts = { received: 0, rejected: 0, failed: 0, answered: 0 };
  const udp = dgram.createSocket('udp4'); udp.on('error', () => {});
  const run = (query, tcp, reply, signal) => {
    counts.received++;
    let parsed;
    try { parsed = parseDnsQuery(query); } catch { counts.rejected++; reply(null); return; }
    if (closing) { reply(null); return; }
    if (parsed.edns?.version > 0) { counts.rejected++; reply(dnsFailure(query, 16)); return; }
    if (jobs.size >= maxInflight) { counts.rejected++; reply(dnsFailure(query)); return; }
    const job = (async () => {
      let response;
      try {
        response = await forwarder.resolve(query, { tcp, signal }); validateDnsResponse(response, query);
        if (!tcp && response.length > parsed.udpSize) response = truncateDnsResponse(query, response);
      } catch { counts.failed++; response = dnsFailure(query); }
      if (!closing && !signal?.aborted) { counts.answered++; reply(response); }
    })().finally(() => jobs.delete(job));
    jobs.add(job); job.catch(() => {});
  };
  udp.on('message', (query, peer) => {
    if (query.length > DNS_UDP_MAX_BYTES) { counts.rejected++; return; }
    run(query, false, (response) => { if (response && !closing) udp.send(response, peer.port, peer.address, () => {}); });
  });
  const tcp = net.createServer({ allowHalfOpen: true }, (socket) => {
    socket.on('error', () => {});
    if (closing || sockets.size >= maxTcpConnections) { socket.destroy(); return; }
    sockets.add(socket);
    const controller = new AbortController();
    const timer = setTimeout(() => socket.destroy(), tcpLifetimeMs); timers.add(timer);
    socket.once('close', () => { sockets.delete(socket); controller.abort(); clearTimeout(timer); timers.delete(timer); });
    const pending = Buffer.alloc(2 * (DNS_MAX_BYTES + 2)); let size = 0, busy = false;
    const pump = () => {
      if (busy || socket.destroyed || closing) return;
      if (size < 2) { if (socket.readableEnded) socket.end(); return; }
      const length = pending.readUInt16BE(0);
      if (length < 12 || length > DNS_MAX_BYTES) { counts.rejected++; socket.destroy(); return; }
      if (size < length + 2) { if (socket.readableEnded) socket.destroy(); return; }
      const query = Buffer.from(pending.subarray(2, length + 2));
      pending.copyWithin(0, length + 2, size); size -= length + 2; busy = true;
      run(query, true, (response) => {
        if (!response) { socket.destroy(); return; }
        if (socket.destroyed) return;
        const frame = Buffer.alloc(response.length + 2); frame.writeUInt16BE(response.length); response.copy(frame, 2);
        socket.write(frame, () => { busy = false; pump(); });
      }, controller.signal);
    };
    socket.on('data', (part) => {
      if (size + part.length > pending.length) { counts.rejected++; socket.destroy(); return; }
      part.copy(pending, size); size += part.length; pump();
    });
    socket.on('end', pump);
  });
  const close = () => {
    if (closePromise) return closePromise;
    closing = true;
    closePromise = (async () => {
      const tcpClosed = new Promise((resolve) => tcp.listening ? tcp.close(resolve) : resolve());
      const udpClosed = new Promise((resolve) => udpBound ? udp.close(resolve) : resolve());
      const socketClosed = [...sockets].map((socket) => new Promise((resolve) => {
        socket.once('close', resolve); socket.destroy();
      }));
      await forwarder.close();
      await Promise.allSettled([...jobs, tcpClosed, udpClosed, ...socketClosed]);
      for (const timer of timers) clearTimeout(timer); timers.clear();
    })();
    return closePromise;
  };
  try {
    tcp.listen(port, address); await once(tcp, 'listening');
    udp.bind(tcp.address().port, address); await once(udp, 'listening'); udpBound = true;
  } catch (error) { await close(); try { udp.close(); } catch {} throw error; }
  return { address, port: tcp.address().port, close,
    stats: () => ({ ...counts, inflight: jobs.size, tcpSockets: sockets.size, timers: timers.size, closing }) };
}
