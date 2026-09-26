/** Bounded localhost readiness through the owned exit adapter; no OS resolver or direct upstream. */
import assert from 'node:assert/strict';
import net from 'node:net';
import dgram from 'node:dgram';
import { randomInt } from 'node:crypto';
import { makeDnsQuery, parseDnsQuery, validateDnsResponse, DNS_MAX_BYTES } from './lab-dns-wire.mjs';
import { compileDnsDomainPolicy } from './dns-domain-policy.mjs';

const failure = () => Object.assign(new Error('DNS_ADAPTER_NOT_READY'), { code: 'DNS_ADAPTER_NOT_READY' });
export function validateDnsReadyName(name, domainPolicy) {
  try {
    assert.ok(typeof name === 'string' && name.length <= 253 && name.includes('.') && !net.isIP(name));
    assert.ok(name.split('.').every((l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(l)));
    assert.ok(!/(?:^|\.)(?:localhost|local|internal|home\.arpa)$/i.test(name));
    const normalized = name.toLowerCase();
    if (domainPolicy) assert.equal(compileDnsDomainPolicy(domainPolicy).denies(parseDnsQuery(makeDnsQuery(normalized))), false);
    return normalized;
  } catch { throw failure(); }
}

export async function queryDnsReadiness(port, packet, { tcp = false, timeoutMs = 2000, signal } = {}) {
  try {
    assert.ok(Number.isInteger(port) && port >= 1024 && port <= 65535);
    assert.ok(Number.isInteger(timeoutMs) && timeoutMs >= 10 && timeoutMs <= 10000);
    assert.ok(Buffer.isBuffer(packet) && packet.length <= 4096); parseDnsQuery(packet);
    assert.ok(!signal?.aborted);
  } catch { throw failure(); }
  const socket = tcp ? new net.Socket() : dgram.createSocket('udp4');
  let timer, closed = false, settled = false, abort, resolveClosed;
  const closure = new Promise((resolve) => { resolveClosed = resolve; });
  socket.once('close', () => { closed = true; resolveClosed(); });
  // Keep an error listener until close, including errors arriving after cancellation.
  socket.on('error', () => {});
  try {
    return await new Promise((resolve, reject) => {
      const finish = (error, bytes) => {
        if (settled) return; settled = true;
        error ? reject(failure()) : resolve(bytes);
      };
      abort = () => finish(failure());
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) { abort(); return; }
      timer = setTimeout(abort, timeoutMs);
      socket.once('error', abort); socket.once('close', () => finish(failure()));
      if (tcp) {
        const buffer = Buffer.alloc(DNS_MAX_BYTES + 2); let used = 0;
        socket.on('data', (chunk) => {
          if (used + chunk.length > buffer.length) { finish(failure()); return; }
          chunk.copy(buffer, used); used += chunk.length;
          if (used < 2) return;
          const size = buffer.readUInt16BE(0);
          if (size < 12 || used > size + 2) finish(failure());
          else if (used === size + 2) finish(null, Buffer.from(buffer.subarray(2, used)));
        });
        socket.once('end', () => finish(failure()));
        socket.connect({ host: '127.0.0.1', port, family: 4, lookup: () => { throw failure(); } }, () => {
          if (settled) return;
          const frame = Buffer.alloc(packet.length + 2); frame.writeUInt16BE(packet.length); packet.copy(frame, 2);
          socket.end(frame);
        });
      } else {
        socket.once('message', (bytes) => bytes.length <= 4096 ? finish(null, bytes) : finish(failure()));
        socket.connect(port, '127.0.0.1', () => { if (!settled) socket.send(packet, (error) => { if (error) finish(error); }); });
      }
    });
  } catch { throw failure(); }
  finally {
    clearTimeout(timer); if (abort) signal?.removeEventListener('abort', abort);
    if (tcp) socket.destroy();
    else if (!closed) { try { socket.close(); } catch { resolveClosed(); } }
    await closure;
  }
}

export async function probeDnsAdapterReady(adapter, { name, signal, timeoutMs = 2000 } = {}) {
  try {
    name = validateDnsReadyName(name); assert.ok(!signal?.aborted);
    const before = adapter.stats(); assert.equal(before.transport.closing, false);
    for (const tcp of [false, true]) for (const type of [1, 28]) {
      assert.ok(!signal?.aborted);
      const query = makeDnsQuery(name, type, randomInt(65536), 1232);
      const r = validateDnsResponse(await queryDnsReadiness(adapter.port, query, { tcp, signal, timeoutMs }), query);
      assert.equal(r.rcode, 0); assert.equal(r.flags & 0x200, 0);
      assert.ok(r.records.some((rr) => rr.section === 0 && rr.klass === 1 && rr.type === type), 'positive A/AAAA required');
    }
    assert.ok(!signal?.aborted);
    const after = adapter.stats(); assert.equal(after.transport.closing, false);
    assert.ok(after.stub.succeeded - before.stub.succeeded >= 4 && after.stub.forwarded - before.stub.forwarded >= 4
      && after.transport.connections - before.transport.connections >= 4, 'owned adapter must forward each readiness query');
    return { status: 'ready', protocols: ['udp', 'tcp'], types: ['A', 'AAAA'], queries: 4, systemDnsChanged: false };
  } catch { throw failure(); }
}
