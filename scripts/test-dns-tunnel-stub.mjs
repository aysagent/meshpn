import assert from 'node:assert/strict';
import test from 'node:test';
import net from 'node:net';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { startTunnelDnsStub } from './lib/dns-tunnel-stub.mjs';
import { createTunnelDnsForwarder, exchangePlainDns } from './lib/dns-tunnel-forwarder.mjs';
import { makeDnsQuery, fixtureDnsAnswer, validateDnsResponse } from './lib/lab-dns-wire.mjs';

const answer = (q) => fixtureDnsAnswer(q, { rdata: Buffer.from([192, 0, 2, 9]) });
const query = (id = 15) => makeDnsQuery('listener.test', 1, id);
async function open(t, options = {}) {
  const seen = [], forwarder = createTunnelDnsForwarder({ exchange: async (v) => { seen.push(v); return answer(v.query); } });
  const stub = await startTunnelDnsStub({ address: '127.0.0.1', port: 0, forwarder, ...options });
  t.after(() => stub.close()); return { stub, seen, forwarder };
}
const exchange = (stub, tcp, q = query()) => exchangePlainDns({ server: '127.0.0.1', localAddress: '127.0.0.1',
  port: stub.port, tcp, query: q, timeoutMs: 1000 });
test('listener accepts UDP/TCP DNS, preserves protocol and ID, releases all resources', async (t) => {
  const { stub, seen } = await open(t);
  for (const tcp of [false, true]) validateDnsResponse(await exchange(stub, tcp), query());
  assert.deepEqual(seen.map((v) => v.tcp), [false, true]);
  assert.ok(seen.every((v) => v.localAddress === '10.99.0.2' && v.server === '1.1.1.1'));
  await stub.close(); await stub.close();
  assert.deepEqual(stub.stats(), { received: 2, rejected: 0, failed: 0, answered: 2, inflight: 0, tcpSockets: 0, timers: 0, closing: true });
});
test('TCP fragmented pipeline and half-close return both complete replies', async (t) => {
  const { stub } = await open(t), first = query(1), second = query(2);
  const frame = (q) => { const p = Buffer.alloc(2); p.writeUInt16BE(q.length); return Buffer.concat([p, q]); };
  const socket = net.connect(stub.port, '127.0.0.1'); t.after(() => socket.destroy());
  socket.setTimeout(1000, () => socket.destroy(new Error('test timeout')));
  const parts = []; socket.on('data', (v) => parts.push(v));
  const ended = once(socket, 'end'); await once(socket, 'connect');
  const input = Buffer.concat([frame(first), frame(second)]);
  socket.write(input.subarray(0, 1)); socket.end(input.subarray(1)); await ended;
  const output = Buffer.concat(parts), n = output.readUInt16BE(0);
  validateDnsResponse(output.subarray(2, n + 2), first);
  const m = output.readUInt16BE(n + 2); assert.equal(output.length, n + m + 4);
  validateDnsResponse(output.subarray(n + 4), second);
});
test('both upstreams failed returns SERVFAIL rather than switching to OS DNS', async (t) => {
  const seen = [], forwarder = createTunnelDnsForwarder({ exchange: async ({ server }) => { seen.push(server); throw new Error('offline'); } });
  const { stub } = await open(t, { forwarder });
  assert.equal(validateDnsResponse(await exchange(stub, false), query()).rcode, 2);
  assert.deepEqual(seen, ['1.1.1.1', '8.8.8.8']); assert.equal(stub.stats().failed, 1);
});
test('closing listener cancels pending TCP upstream and closes idle clients', async (t) => {
  let started;
  const began = new Promise((resolve) => { started = resolve; });
  const forwarder = createTunnelDnsForwarder({ exchange: ({ signal }) => new Promise((_, reject) => {
    signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true }); started();
  }) });
  const { stub } = await open(t, { forwarder });
  const pending = assert.rejects(exchange(stub, true)); await began;
  const idle = net.connect(stub.port, '127.0.0.1'); idle.on('error', () => {}); t.after(() => idle.destroy());
  await once(idle, 'connect'); await stub.close(); await pending;
  assert.equal(stub.stats().inflight, 0); assert.equal(stub.stats().tcpSockets, 0); assert.equal(stub.stats().timers, 0);
  assert.equal(forwarder.stats().inflight, 0); assert.equal(forwarder.stats().backup, 0);
});
test('UDP bind failure rolls back TCP listener and closes forwarder', async (t) => {
  const occupied = dgram.createSocket('udp4'); occupied.bind(0, '127.0.0.1'); await once(occupied, 'listening');
  t.after(() => new Promise((resolve) => occupied.close(resolve)));
  let closed = 0;
  await assert.rejects(startTunnelDnsStub({ address: '127.0.0.1', port: occupied.address().port,
    forwarder: { resolve: async (q) => answer(q), close: async () => { closed++; } } }), { code: 'EADDRINUSE' });
  assert.equal(closed, 1);
  const server = net.createServer(); t.after(() => new Promise((resolve) => server.close(resolve)));
  server.listen(occupied.address().port, '127.0.0.1'); await once(server, 'listening');
});
test('configuration cannot expose wildcard/public listeners or unlimited resources', async () => {
  const forwarder = { resolve: async (q) => answer(q), close: async () => {} };
  for (const override of [{ address: '0.0.0.0' }, { address: '1.1.1.1' }, { port: 53 }, { maxInflight: 0 },
    { maxTcpConnections: 100 }, { tcpLifetimeMs: 0 }]) await assert.rejects(startTunnelDnsStub({ forwarder, ...override }));
});
