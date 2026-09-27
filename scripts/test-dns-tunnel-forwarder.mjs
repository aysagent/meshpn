import assert from 'node:assert/strict';
import test from 'node:test';
import dgram from 'node:dgram';
import net from 'node:net';
import { once } from 'node:events';
import { createTunnelDnsForwarder, exchangePlainDns, tunnelDnsServers } from './lib/dns-tunnel-forwarder.mjs';
import { makeDnsQuery, fixtureDnsAnswer, dnsFailure, validateDnsResponse } from './lib/lab-dns-wire.mjs';

const query = () => makeDnsQuery('example.test', 1, 1234);
const answer = (q) => fixtureDnsAnswer(q, { rdata: Buffer.from([192, 0, 2, 8]) });
test('numeric default primary/backup and explicit primary; no hostname or local upstream', () => {
  assert.deepEqual(tunnelDnsServers(), ['1.1.1.1', '8.8.8.8']);
  assert.deepEqual(tunnelDnsServers('9.9.9.9'), ['9.9.9.9', '8.8.8.8']);
  assert.deepEqual(tunnelDnsServers('8.8.8.8'), ['8.8.8.8']);
  for (const v of ['', null, 'localhost', '::1', '127.0.0.1', '192.168.1.1', '10.0.0.2', '224.0.0.1', '1.1.1.1:53'])
    assert.throws(() => tunnelDnsServers(v));
});
test('valid primary answer and NXDOMAIN are returned without asking backup', async () => {
  for (const negative of [false, true]) {
    const seen = [];
    const f = createTunnelDnsForwarder({ exchange: async (input) => {
      seen.push(input.server); assert.equal(input.localAddress, '10.99.0.2');
      return negative ? dnsFailure(input.query, 3) : answer(input.query);
    } });
    const q = query(), r = await f.resolve(q);
    assert.equal(validateDnsResponse(r, q).rcode, negative ? 3 : 0);
    assert.deepEqual(seen, ['1.1.1.1']); assert.equal(q.readUInt16BE(0), 1234);
    await f.close(); assert.equal(f.stats().inflight, 0);
  }
});
for (const failure of ['timeout', 'servfail', 'wrong-id']) test(`backup handles ${failure}, keeping transport/source and original ID`, async () => {
  const seen = [];
  const f = createTunnelDnsForwarder({ primary: '9.9.9.9', exchange: async (input) => {
    seen.push({ server: input.server, tcp: input.tcp, source: input.localAddress });
    if (seen.length > 1) return answer(input.query);
    if (failure === 'timeout') throw new Error('timeout');
    if (failure === 'servfail') return dnsFailure(input.query, 2);
    const r = answer(input.query); r.writeUInt16BE((input.query.readUInt16BE(0) + 1) & 65535); return r;
  } });
  const q = query(), r = await f.resolve(q, { tcp: true }); validateDnsResponse(r, q);
  assert.deepEqual(seen, [
    { server: '9.9.9.9', tcp: true, source: '10.99.0.2' },
    { server: '8.8.8.8', tcp: true, source: '10.99.0.2' },
  ]);
  assert.equal(f.stats().backup, 1); await f.close();
});
test('both failed resolvers terminate; no third resolver or OS lookup', async () => {
  const seen = [], f = createTunnelDnsForwarder({ exchange: async ({ server }) => { seen.push(server); throw new Error('offline'); } });
  await assert.rejects(f.resolve(query())); assert.deepEqual(seen, ['1.1.1.1', '8.8.8.8']);
  assert.equal(f.stats().failed, 1); await f.close();
});
test('inflight limit and close cancel pending request without attempting backup', async () => {
  const seen = [], f = createTunnelDnsForwarder({ maxInflight: 1, exchange: ({ server, signal }) => {
    seen.push(server); return new Promise((_, reject) => signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true }));
  } });
  const first = assert.rejects(f.resolve(query()));
  await assert.rejects(f.resolve(query()), { code: 'DNS_BUSY' });
  await f.close(); await first; await f.close();
  assert.equal(f.stats().inflight, 0); assert.deepEqual(seen, ['1.1.1.1']);
  await assert.rejects(f.resolve(query()), { code: 'DNS_BUSY' });
});
test('already aborted request never contacts a resolver', async () => {
  const f = createTunnelDnsForwarder({ exchange: () => { throw new Error('unexpected exchange'); } });
  const c = new AbortController(); c.abort();
  await assert.rejects(f.resolve(query(), { signal: c.signal }));
  assert.equal(f.stats().primary, 0); await f.close();
});
for (const tcp of [false, true]) test(`real ${tcp ? 'TCP' : 'UDP'} loopback wire exchange, timeout and abort clean up`, async (t) => {
  let silent = false; const sockets = new Set();
  const server = tcp ? net.createServer((socket) => {
    sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket));
    let pending = Buffer.alloc(0);
    socket.on('data', (b) => {
      pending = Buffer.concat([pending, b]);
      if (silent || pending.length < 2 || pending.length !== pending.readUInt16BE(0) + 2) return;
      const reply = answer(pending.subarray(2)), prefix = Buffer.alloc(2); prefix.writeUInt16BE(reply.length);
      socket.write(prefix.subarray(0, 1)); socket.write(Buffer.concat([prefix.subarray(1), reply]));
    });
  }) : dgram.createSocket('udp4');
  if (!tcp) server.on('message', (q, peer) => { if (!silent) server.send(answer(q), peer.port, peer.address); });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  if (tcp) server.listen(0, '127.0.0.1'); else server.bind(0, '127.0.0.1');
  await once(server, 'listening');
  const options = { server: '127.0.0.1', localAddress: '127.0.0.1', port: server.address().port, query: query(), tcp, timeoutMs: 1000 };
  validateDnsResponse(await exchangePlainDns(options), options.query);
  silent = true;
  await assert.rejects(exchangePlainDns({ ...options, timeoutMs: 30 }), { code: 'DNS_TIMEOUT' });
  const c = new AbortController(), result = assert.rejects(exchangePlainDns({ ...options, signal: c.signal }), { code: 'DNS_ABORTED' });
  setImmediate(() => c.abort()); await result;
});
