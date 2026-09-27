/** Ordinary DNS exchanges for the existing IP tunnel. No DoH, TLS or OS DNS
 * setters. Binding a source address is NOT a routing/leak guard: the caller
 * must install and retain the TUN policy/guard for both resolver destinations. */
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import { randomInt } from 'node:crypto';
import { DNS_MAX_BYTES, DNS_UDP_MAX_BYTES, dnsError, parseDnsQuery, validateDnsResponse } from './lab-dns-wire.mjs';
import { isPublicRelayAddress } from './transparent-tls-destination.mjs';

export const DEFAULT_TUNNEL_DNS_SERVERS = Object.freeze(['1.1.1.1', '8.8.8.8']);
export function tunnelDnsServers(primary) {
  if (primary === undefined) return [...DEFAULT_TUNNEL_DNS_SERVERS];
  assert.ok(typeof primary === 'string' && net.isIPv4(primary) && isPublicRelayAddress(primary), '--dns-server requires a public IPv4 address');
  // An explicit primary changes that choice, not the promised backup. Do not
  // send the same request twice to 8.8.8.8 when it is selected as the primary.
  return [...new Set([primary, DEFAULT_TUNNEL_DNS_SERVERS[1]])];
}

/** Bounded socket primitive. Tests may use loopback peers; operator arguments
 * are checked separately by tunnelDnsServers. No hostname lookup is possible. */
export async function exchangePlainDns({ server, localAddress, port = 53, query, tcp = false, timeoutMs = 1200, signal }) {
  assert.ok(net.isIPv4(server) && net.isIPv4(localAddress));
  assert.ok(Number.isInteger(port) && port > 0 && port <= 65535);
  assert.ok(typeof tcp === 'boolean' && Number.isInteger(timeoutMs) && timeoutMs >= 10 && timeoutMs <= 5000);
  parseDnsQuery(query);
  if (!tcp && query.length > DNS_UDP_MAX_BYTES) throw dnsError('DNS_SIZE');
  signal?.throwIfAborted();
  const socket = tcp ? new net.Socket() : dgram.createSocket('udp4');
  const closed = new Promise((resolve) => socket.once('close', resolve));
  let timer, aborted;
  try {
    return await new Promise((resolve, reject) => {
      let done = false;
      const finish = (error, bytes) => {
        if (done) return; done = true;
        clearTimeout(timer); signal?.removeEventListener('abort', aborted);
        if (error) reject(error); else resolve(bytes);
      };
      const reply = (bytes) => {
        try { validateDnsResponse(bytes, query); finish(null, Buffer.from(bytes)); }
        catch { finish(dnsError('DNS_RESPONSE')); }
      };
      aborted = () => finish(dnsError('DNS_ABORTED'));
      timer = setTimeout(() => finish(dnsError('DNS_TIMEOUT')), timeoutMs);
      signal?.addEventListener('abort', aborted, { once: true });
      socket.on('error', () => finish(dnsError('DNS_UPSTREAM')));
      if (signal?.aborted) { aborted(); return; }
      if (tcp) {
        const frame = Buffer.alloc(DNS_MAX_BYTES + 2); let size = 0;
        socket.on('data', (part) => {
          if (done) return;
          if (size + part.length > frame.length) return finish(dnsError('DNS_SIZE'));
          part.copy(frame, size); size += part.length;
          if (size < 2) return;
          const length = frame.readUInt16BE(0);
          if (length < 12 || size > length + 2) return finish(dnsError('DNS_RESPONSE'));
          if (size === length + 2) reply(frame.subarray(2, size));
        });
        socket.once('end', () => finish(dnsError('DNS_UPSTREAM')));
        socket.once('connect', () => {
          if (done) return;
          const prefix = Buffer.alloc(2); prefix.writeUInt16BE(query.length);
          socket.write(Buffer.concat([prefix, query]));
        });
        socket.connect({ host: server, port, localAddress, family: 4, autoSelectFamily: false,
          lookup: () => { throw dnsError('DNS_BOOTSTRAP_FORBIDDEN'); } });
      } else {
        socket.on('message', reply);
        socket.bind(0, localAddress, () => {
          if (done) return;
          socket.connect(port, server, (error) => {
            if (done) return;
            if (error) return finish(dnsError('DNS_UPSTREAM'));
            try { socket.send(query, (e) => { if (e) finish(dnsError('DNS_UPSTREAM')); }); }
            catch { finish(dnsError('DNS_UPSTREAM')); }
          });
        });
      }
    });
  } finally {
    clearTimeout(timer); signal?.removeEventListener('abort', aborted);
    let waitForClose = true;
    if (tcp) socket.destroy(); else {
      try { socket.close(); } catch (e) { if (e.code !== 'ERR_SOCKET_DGRAM_NOT_RUNNING') throw e; waitForClose = false; }
    }
    if (waitForClose) await closed;
  }
}

export function createTunnelDnsForwarder({ primary, localAddress = '10.99.0.2', timeoutMs = 1200, maxInflight = 16,
  exchange = exchangePlainDns } = {}) {
  const servers = tunnelDnsServers(primary);
  assert.equal(localAddress, '10.99.0.2'); assert.equal(typeof exchange, 'function');
  assert.ok(Number.isInteger(timeoutMs) && timeoutMs >= 10 && timeoutMs <= 5000);
  assert.ok(Number.isInteger(maxInflight) && maxInflight >= 1 && maxInflight <= 64);
  const jobs = new Set(), controllers = new Set(); let closing = false, closePromise;
  const counts = { primary: 0, backup: 0, succeeded: 0, failed: 0, refused: 0 };
  const resolve = (query, { tcp = false, signal } = {}) => {
    parseDnsQuery(query); assert.equal(typeof tcp, 'boolean');
    if (closing || jobs.size >= maxInflight) { counts.refused++; return Promise.reject(dnsError('DNS_BUSY')); }
    const wire = Buffer.from(query), originalId = wire.readUInt16BE(0); wire.writeUInt16BE(randomInt(65536));
    const controller = new AbortController(); controllers.add(controller);
    const cancel = () => controller.abort(); signal?.addEventListener('abort', cancel, { once: true });
    if (signal?.aborted) cancel();
    const job = (async () => {
      let failure;
      for (const [index, server] of servers.entries()) {
        controller.signal.throwIfAborted(); counts[index === 0 ? 'primary' : 'backup']++;
        try {
          const response = Buffer.from(await exchange({ server, localAddress, query: wire, tcp, timeoutMs, signal: controller.signal }));
          const answer = validateDnsResponse(response, wire);
          if (answer.rcode === 2) throw dnsError('DNS_SERVFAIL');
          response.writeUInt16BE(originalId); counts.succeeded++; return response;
        } catch (error) { failure = error; if (controller.signal.aborted) throw error; }
      }
      throw failure ?? dnsError('DNS_UPSTREAM');
    })().catch((e) => { counts.failed++; throw e; }).finally(() => {
      signal?.removeEventListener('abort', cancel); controllers.delete(controller); jobs.delete(job);
    });
    jobs.add(job); return job;
  };
  return { servers: [...servers], resolve,
    stats: () => ({ ...counts, inflight: jobs.size, closing }),
    close() {
      closing = true;
      closePromise ??= (async () => { for (const c of controllers) c.abort(); await Promise.allSettled([...jobs]); })();
      return closePromise;
    } };
}
