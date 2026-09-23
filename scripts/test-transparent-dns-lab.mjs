import assert from 'node:assert/strict';
import test from 'node:test';
import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';
import net from 'node:net';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { makeDnsQuery, parseDns, parseDnsQuery, validateDnsResponse, fixtureDnsAnswer, dnsFailure, DNS_MAX_BYTES } from './lib/lab-dns-wire.mjs';
import { startTransparentDnsLab, queryLabDns } from './lib/transparent-dns-lab.mjs';
import { startLabDohStub } from './lib/lab-doh-stub.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

const query = (type = 1, id = 123, udpSize) => makeDnsQuery('private-query.dns-lab.test', type, id, udpSize);
const frame = (packet) => { const b = Buffer.alloc(packet.length + 2); b.writeUInt16BE(packet.length); packet.copy(b, 2); return b; };
async function eventually(predicate, ms = 2000) {
  const end = performance.now() + ms;
  while (!predicate()) { if (performance.now() > end) assert.fail('DNS test deadline'); await delay(5); }
}
async function fixture(t, options) {
  const lab = await startTransparentDnsLab(options);
  t.after(async () => {
    await lab.close();
    const { stub, resolverSockets } = lab.stats();
    for (const key of ['inflight', 'tcpSockets', 'tlsSockets', 'requests', 'jobs', 'timers']) assert.equal(stub[key], 0, key);
    assert.equal(resolverSockets, 0); assert.equal(lab.relay.stats().sockets, 0);
  }); return lab;
}

test('wire A/AAAA, compressed RR names, ID, TTL and EDNS payload size roundtrip', () => {
  for (const type of [1, 28]) for (const udpSize of [undefined, 1232, 65535]) {
    const q = query(type, 0xfefe, udpSize), r = fixtureDnsAnswer(q, { ttl: 0 });
    const parsed = validateDnsResponse(r, q);
    assert.equal(parsed.records[0].ttl, 0); assert.equal(parsed.records[0].length, type === 1 ? 4 : 16);
    assert.equal(parsed.id, 0xfefe); assert.equal(parsed.udpSize, Math.min(udpSize ?? 512, 4096));
  }
});
for (const [name, mutate] of [
  ['short', () => Buffer.alloc(11)], ['too large', () => Buffer.alloc(DNS_MAX_BYTES + 1)],
  ['QR', (b) => { b[2] |= 128; return b; }], ['opcode', (b) => { b[2] |= 8; return b; }],
  ['multi-question', (b) => { b[5] = 2; return b; }], ['trailing bytes', (b) => Buffer.concat([b, Buffer.from([0])])],
  ['compression loop', (b) => { b[12] = 0xc0; b[13] = 12; return b; }],
  ['pointer outside packet', (b) => { b[12] = 0xff; b[13] = 255; return b; }],
  ['unsupported qtype', (b) => { b.writeUInt16BE(255, b.length - 4); return b; }],
  ['nonzero query EDNS RCODE', () => { const b = query(1, 123, 1232); b[b.length - 6] = 1; return b; }],
]) test(`wire rejects ${name}`, () => assert.throws(() => parseDnsQuery(mutate(query())), { code: 'DNS_WIRE' }));
test('response mismatch, malformed RR length and wrong QR are rejected', () => {
  for (const mutate of [
    (b) => { b[1] ^= 1; }, (b) => { b[13] ^= 1; }, (b) => { b[2] &= 127; },
    (b) => { b.writeUInt16BE(500, b.length - 6); },
  ]) { const reply = fixtureDnsAnswer(query()); mutate(reply); assert.throws(() => validateDnsResponse(reply, query())); }
});
test('SERVFAIL/truncation retains question and ID, clears answers, never copies invalid query', () => {
  for (const edns of [undefined, 1232]) {
    const q = query(28, 0xabcd, edns), parsed = validateDnsResponse(dnsFailure(q, 0, true), q);
    assert.equal(parsed.flags & 0x200, 0x200); assert.equal(parsed.id, 0xabcd); assert.equal(parsed.counts[0], 0);
  }
  assert.throws(() => dnsFailure(Buffer.alloc(12)));
});

for (const tcp of [false, true]) for (const type of [1, 28]) test(`${tcp ? 'TCP fragmented/half-close' : 'UDP'} query type ${type} crosses verified TLS relay`, async (t) => {
  const lab = await fixture(t);
  const q = query(type, 0x1234), reply = await queryLabDns(lab.stub.port, q, { tcp, fragment: true });
  const parsed = validateDnsResponse(reply, q);
  assert.equal(parsed.flags & 15, 0); assert.equal(parsed.counts[0], 1); assert.equal(parsed.records[0].ttl, 30);
  assert.equal(lab.stats().resolverRequests, 1); assert.equal(lab.relay.stats().originConnections, 1);
  assert.equal(lab.stub.stats().succeeded, 1);
});
test('NXDOMAIN and zero TTL survive transport; repeated queries are not cached', async (t) => {
  const lab = await fixture(t, { mode: 'nxdomain' });
  assert.equal(parseDns(await queryLabDns(lab.stub.port, query())).flags & 15, 3);
  lab.setMode('ttl-zero');
  for (let i = 0; i < 2; i++) assert.equal(parseDns(await queryLabDns(lab.stub.port, query())).records[0].ttl, 0);
  assert.equal(lab.stats().resolverRequests, 3);
});
test('UDP 512-byte truncation and explicit TCP retry use DoH, with EDNS permitting larger UDP', async (t) => {
  const lab = await fixture(t, { mode: 'large' });
  const small = await queryLabDns(lab.stub.port, query());
  assert.ok(small.length <= 512); assert.equal(parseDns(small).flags & 0x200, 0x200);
  for (const options of [{ tcp: true }, { tcp: false }]) {
    const q = query(1, 123, options.tcp ? undefined : 1232);
    const reply = await queryLabDns(lab.stub.port, q, options);
    assert.ok(reply.length > 512); assert.equal(validateDnsResponse(reply, q).counts[0], 40);
  }
  assert.equal(lab.stats().resolverRequests, 3);
});
for (const mode of ['hold', 'reset', 'redirect', 'bad-type', 'encoding', 'oversize', 'chunked-oversize', 'bad-id', 'bad-question', 'bad-body', 'partial']) {
  test(`DoH ${mode} returns SERVFAIL without alternative resolution`, async (t) => {
    const lab = await fixture(t, { mode, timeoutMs: 80 });
    const q = query(), reply = await queryLabDns(lab.stub.port, q);
    assert.equal(validateDnsResponse(reply, q).flags & 15, 2);
    assert.equal(lab.stats().resolverRequests, 1); assert.equal(lab.stub.stats().failed, 1);
    assert.equal(lab.stub.stats().forwarded, 1); assert.equal(lab.stub.stats().succeeded, 0);
  });
}
for (const options of [{ ca: [] }, { servername: 'wrong-name.test' }]) test(`TLS certificate rejection ${options.servername ?? 'untrusted CA'} sends no DNS body`, async (t) => {
  const lab = await fixture(t, options);
  assert.equal(parseDns(await queryLabDns(lab.stub.port, query())).flags & 15, 2);
  assert.equal(lab.stats().resolverRequests, 0); assert.equal(lab.stub.stats().errors.DNS_UPSTREAM, 1);
});
test('actual resolver downtime fails closed, restart recovers without changing resolver', async (t) => {
  const lab = await fixture(t);
  await lab.stopOrigin();
  assert.equal(parseDns(await queryLabDns(lab.stub.port, query())).flags & 15, 2);
  await lab.restartOrigin();
  assert.equal(parseDns(await queryLabDns(lab.stub.port, query())).flags & 15, 0);
  assert.equal(lab.stats().resolverRequests, 1);
});
test('in-flight cap rejects excess work with SERVFAIL and no unbounded DoH queue', async (t) => {
  const lab = await fixture(t, { mode: 'hold', maxInflight: 1, timeoutMs: 200 });
  const first = queryLabDns(lab.stub.port, query());
  await eventually(() => lab.stats().resolverRequests === 1);
  assert.equal(parseDns(await queryLabDns(lab.stub.port, query(28))).flags & 15, 2);
  assert.equal(lab.stats().resolverRequests, 1); assert.equal(lab.stub.stats().peakInflight, 1);
  assert.equal(parseDns(await first).flags & 15, 2);
});
test('invalid UDP query is dropped before any TLS connection', async (t) => {
  const lab = await fixture(t);
  await assert.rejects(queryLabDns(lab.stub.port, Buffer.alloc(4), { timeoutMs: 50 }), { code: 'DNS_CLIENT_TIMEOUT' });
  assert.equal(lab.stub.stats().forwarded, 0); assert.equal(lab.relay.stats().originConnections, 0);
});
for (const kind of ['incomplete-max-frame', 'partial-frame', 'overflow-buffer']) test(`TCP ${kind} closes within bound without DNS`, async (t) => {
  const lab = await fixture(t, { tcpLifetimeMs: 70 });
  const socket = net.connect(lab.stub.port, '127.0.0.1'); socket.on('error', () => {}); t.after(() => socket.destroy());
  await once(socket, 'connect'); const closed = new Promise((resolve) => socket.once('close', resolve));
  if (kind === 'incomplete-max-frame') socket.write(Buffer.from([0xff, 0xff]));
  if (kind === 'partial-frame') socket.write(Buffer.from([0]));
  if (kind === 'overflow-buffer') socket.write(Buffer.alloc(2 * (DNS_MAX_BYTES + 2) + 1));
  await closed; assert.equal(lab.stub.stats().forwarded, 0);
});
test('two pipelined TCP frames get matching IDs and preserve order', async (t) => {
  const lab = await fixture(t);
  const socket = net.connect(lab.stub.port, '127.0.0.1'); t.after(() => socket.destroy());
  await once(socket, 'connect'); const chunks = []; socket.on('data', (chunk) => chunks.push(chunk));
  const ended = once(socket, 'end'); socket.end(Buffer.concat([frame(query(1, 100)), frame(query(28, 101))])); await ended;
  const bytes = Buffer.concat(chunks), n = bytes.readUInt16BE(0);
  assert.equal(parseDns(bytes.subarray(2, 2 + n)).id, 100);
  assert.equal(parseDns(bytes.subarray(4 + n)).id, 101); assert.equal(lab.stats().resolverRequests, 2);
});
test('TCP connection budget and absolute lifetime bound idle clients', async (t) => {
  const lab = await fixture(t, { maxTcpConnections: 1, tcpLifetimeMs: 100 });
  const a = net.connect(lab.stub.port, '127.0.0.1'); await once(a, 'connect');
  t.after(() => a.destroy()); const aClosed = once(a, 'close');
  const b = net.connect(lab.stub.port, '127.0.0.1'); t.after(() => b.destroy()); await once(b, 'close');
  assert.ok(lab.stub.stats().tcpSockets <= 1); await aClosed;
  assert.equal(lab.stub.stats().forwarded, 0);
});
test('client close cancels an active DoH exchange; close is idempotent with work in flight', async (t) => {
  const lab = await fixture(t, { mode: 'hold' });
  const socket = net.connect(lab.stub.port, '127.0.0.1'); t.after(() => socket.destroy()); await once(socket, 'connect');
  socket.write(frame(query())); await eventually(() => lab.stats().resolverRequests === 1); socket.resetAndDestroy();
  await eventually(() => lab.stub.stats().inflight === 0);
  assert.equal(lab.stub.stats().errors.DNS_ABORTED, 1);
  const pending = queryLabDns(lab.stub.port, query(), { timeoutMs: 100 });
  const expected = assert.rejects(pending, { code: 'DNS_CLIENT_TIMEOUT' });
  await eventually(() => lab.stub.stats().inflight === 1);
  await Promise.all([lab.close(), lab.close(), expected]);
});

test('observed TLS wire hides real QNAME; resolver receives it; OS DNS and unexpected UDP are forbidden', async (t) => {
  const marker = `secret-${randomBytes(12).toString('hex')}`;
  const q = makeDnsQuery(`${marker}.dns-lab.test`);
  const captures = new Map();
  const lab = await fixture(t, { observeWire(stage, chunk, { peerPort }) {
    const key = `${stage}:${peerPort}`, bytes = Buffer.concat([captures.get(key) ?? Buffer.alloc(0), chunk]);
    assert.ok(bytes.length < 256 * 1024); captures.set(key, bytes);
  } });
  let lookups = 0;
  for (const api of [dns, dnsPromises]) for (const name of ['lookup', 'resolve', 'resolve4', 'resolve6']) {
    const original = api[name];
    t.mock.method(api, name, (...args) => {
      // Node dgram calls dns.lookup even for numeric bind/send addresses; these
      // short-circuit without a DNS query. Forbid actual name resolution.
      if (name === 'lookup' && net.isIP(args[0])) return original.apply(api, args);
      lookups++; throw new Error('unexpected OS DNS');
    });
  }
  const sends = [], send = dgram.Socket.prototype.send;
  const connects = [], connect = net.Socket.prototype.connect;
  t.mock.method(net.Socket.prototype, 'connect', function (...args) {
    const options = Array.isArray(args[0]) ? args[0][0] : args[0];
    connects.push({ address: options.host, port: options.port }); return connect.apply(this, args);
  });
  t.mock.method(dgram.Socket.prototype, 'send', function (...args) {
    let remote; try { remote = this.remoteAddress(); } catch { remote = { address: args[2], port: args[1] }; }
    sends.push(remote); return send.apply(this, args);
  });
  assert.equal(validateDnsResponse(await queryLabDns(lab.stub.port, q), q).flags & 15, 0);
  assert.equal(lab.stats().resolverRequests, 1);
  for (const stage of ['exit', 'origin']) {
    const streams = [...captures].filter(([key]) => key.startsWith(`${stage}:`)); assert.equal(streams.length, 1);
    assert.ok(streams[0][1].length > q.length); assert.ok(!streams[0][1].includes(Buffer.from(marker)));
    assert.ok(!streams[0][1].includes(q.subarray(12, q.length - 4)));
  }
  lab.setMode('redirect'); assert.equal(parseDns(await queryLabDns(lab.stub.port, q)).flags & 15, 2);
  lab.setMode('reset'); assert.equal(parseDns(await queryLabDns(lab.stub.port, q)).flags & 15, 2);
  assert.equal(lookups, 0); assert.equal(sends.length, 6);
  assert.ok(sends.every((peer) => peer.address === '127.0.0.1' && peer.port !== 53));
  assert.equal(sends.filter((peer) => peer.port === lab.stub.port).length, 3);
  const allowed = new Set([lab.relay.clientPort, lab.relay.exitPort, lab.relay.originPort, lab.resolverPort]);
  assert.ok(connects.length > 0);
  assert.ok(connects.every((peer) => peer.address === '127.0.0.1' && allowed.has(peer.port)), JSON.stringify(connects));
});
test('unsafe endpoints and disabled/unbounded resource settings are rejected before listeners', async () => {
  const base = { upstream: { address: '127.0.0.1', port: 12345, servername: 'localhost', authority: 'localhost:12345' } };
  for (const options of [{}, { ...base, upstream: { ...base.upstream, address: '8.8.8.8' } }, { ...base, port: 53 },
    { ...base, timeoutMs: 0 }, { ...base, maxInflight: 65 }, { ...base, maxTcpConnections: 0 }, { ...base, tcpLifetimeMs: Infinity }]) {
    await assert.rejects(startLabDohStub(options), { code: 'DNS_CONFIG' });
  }
});
test('bounded DNS CLI checks real queries and reports zero resources after cleanup', async () => {
  const result = await runCommand(process.execPath, ['scripts/transparent-dns-lab.mjs'], { env: cleanEnvironment(process.env), timeoutMs: 20000 });
  assert.equal(result.code, 0, result.stderr); assert.equal(result.reason, null);
  const rows = result.stdout.split('\n').filter((line) => line.startsWith('DNS_LAB_RESULT ')); assert.equal(rows.length, 1);
  const report = JSON.parse(rows[0].slice('DNS_LAB_RESULT '.length));
  assert.equal(report.status, 'passed'); assert.equal(report.exposed, false); assert.equal(report.stats.stub.succeeded, 5);
  assert.equal(report.stats.stub.failed, 3); assert.equal(report.stats.resolverSockets, 0);
  assert.ok(report.wireBytes.exit > 0 && report.wireBytes.origin > 0);
});
test('DNS CLI refuses deployment-style flags instead of changing OS DNS', async () => {
  const result = await runCommand(process.execPath, ['scripts/transparent-dns-lab.mjs', '--serve'], { timeoutMs: 3000 });
  assert.equal(result.code, 1); assert.ok(!result.stdout.includes('DNS_LAB_RESULT'));
});
test('UDP bind failure rolls back the already-opened TCP listener', async (t) => {
  const occupied = dgram.createSocket('udp4'); occupied.bind(0, '127.0.0.1'); await once(occupied, 'listening');
  t.after(() => occupied.close()); const port = occupied.address().port;
  await assert.rejects(startLabDohStub({ port, upstream: { address: '127.0.0.1', port: 12345,
    servername: 'localhost', authority: 'localhost:12345' } }), { code: 'EADDRINUSE' });
  const probe = net.createServer(); probe.listen(port, '127.0.0.1'); await once(probe, 'listening');
  await new Promise((resolve) => probe.close(resolve));
});
