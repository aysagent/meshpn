import assert from 'node:assert/strict';
import test from 'node:test';
import net from 'node:net';
import https from 'node:https';
import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';
import { once } from 'node:events';
import { readFile, mkdtemp, writeFile, chmod, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { compileDnsUpstream, compileLabDnsUpstream } from './lib/dns-upstream-config.mjs';
import { createDnsExitTransport, createLabDnsExitTransport, dnsExitTransportTarget } from './lib/dns-exit-transport.mjs';
import { startLabDohStub } from './lib/lab-doh-stub.mjs';
import { queryLabDns } from './lib/transparent-dns-lab.mjs';
import { wireTransparentTlsEncSniSession } from './lib/transparent-tls-runtime.mjs';
import { ExitDestinationPolicy } from './lib/transparent-tls-destination.mjs';
import { EncSniReplayGuard } from './lib/transparent-tls-replay.mjs';
import { makeDnsQuery, fixtureDnsAnswer, validateDnsResponse, parseDns, DNS_MAX_BYTES, DNS_UDP_MAX_BYTES } from './lib/lab-dns-wire.mjs';
import { sizedTxtAnswer, paddedDnsQuery, negativeSoaAnswer } from './lib/dns-wire-fixtures.mjs';
import { parseDnsExitArgs, readDnsExitSecret } from './dns-exit-adapter.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';
import { child } from './lib/browser-lab-driver.mjs';
import { startDnsExitAdapter } from './lib/dns-exit-adapter.mjs';

const cert = await readFile(new URL('./fixtures/boring-tls-local.cert.pem', import.meta.url), 'utf8');
const key = await readFile(new URL('./fixtures/boring-tls-local.key.pem', import.meta.url));
const input = { schema: 1, transport: 'doh', hostname: 'resolver.test', port: 443, path: '/custom/dns',
  bootstrap: { addresses: ['93.184.216.34'] }, trust: { mode: 'custom', certificates: [cert] } };
const publicOptions = () => ({ profile: compileDnsUpstream(input), exitAddress: '93.184.216.35', exitPort: 443,
  publicName: 'relay.test', secret: randomBytes(32) });

for (const [label, patch] of [
  ['hostname exit', { exitAddress: 'exit.test' }], ['loopback exit', { exitAddress: '127.0.0.1' }],
  ['private exit', { exitAddress: '10.1.2.3' }], ['multicast', { exitAddress: 'ff02::1' }],
  ['port zero', { exitPort: 0 }], ['port string', { exitPort: '443' }], ['invalid port', { exitPort: 65536 }],
  ['short PSK', { secret: Buffer.alloc(31) }], ['hex PSK', { secret: 'a'.repeat(64) }],
  ['suffix URL', { publicName: 'https://relay.test' }], ['suffix wildcard', { publicName: '*.relay.test' }],
  ['suffix empty label', { publicName: 'relay..test' }], ['trailing dot', { publicName: 'relay.test.' }],
  ['suffix too long for enc-SNI', { publicName: `${'x'.repeat(63)}.${'x'.repeat(63)}.${'x'.repeat(63)}.test` }],
  ['cloned profile', { profile: { ...compileDnsUpstream(input) } }],
  ['lab profile', { profile: compileLabDnsUpstream({ ...input, hostname: 'localhost', bootstrap: { addresses: ['127.0.0.1'] } }) }],
  ['lookup override', { lookup() {} }], ['direct socket override', { connectExit() {} }],
]) test(`exit transport preflight rejects ${label}`, () => assert.throws(() => createDnsExitTransport({ ...publicOptions(), ...patch }), { code: 'DNS_EXIT_CONFIG' }));

test('public IPv4/IPv6 transport creation is offline, branded, and close is idempotent', async () => {
  for (const exitAddress of ['93.184.216.35', '2606:4700::1111']) {
    const transport = createDnsExitTransport({ ...publicOptions(), exitAddress });
    assert.equal(transport.stats().connections, 0);
    assert.throws(() => dnsExitTransportTarget({ ...transport }), { code: 'DNS_EXIT_CONFIG' });
    const first = transport.close(); assert.equal(transport.close(), first); await first;
    assert.throws(() => dnsExitTransportTarget(transport), { code: 'DNS_EXIT_CONFIG' });
    assert.equal(transport.stats().sockets, 0);
  }
});

async function fixture(t, { badCa = false, wrongName = false, wrongSecret = false, mode = 'normal', timeoutMs = 300,
  answer = fixtureDnsAnswer, responseHeaders = {}, chunkBytes = 0, bodyDelayMs = 0, onQuery = () => {}, domainPolicy } = {}) {
  let bodies = 0, attempts = 0;
  const wire = [];
  const sockets = new Set(), sessions = [];
  const track = (s) => { sockets.add(s); s.on('error', () => {}); s.once('close', () => sockets.delete(s)); };
  const origin = https.createServer({ key, cert, minVersion: 'TLSv1.3' }, (req, res) => {
    req.on('error', () => {}); res.on('error', () => {});
    const chunks = []; req.on('data', (b) => chunks.push(b));
    req.on('end', () => {
      bodies++;
      assert.equal(req.url, '/custom/dns'); assert.equal(req.headers.host, `localhost:${origin.address().port}`);
      assert.equal(req.socket.servername, 'localhost');
      assert.equal(req.headers['cache-control'], 'no-cache, no-store');
      onQuery(Buffer.concat(chunks));
      if (mode === 'hold') return;
      if (mode === 'reset') { req.socket.destroy(); return; }
      if (mode === 'redirect') { res.writeHead(302, { location: 'http://resolver.test:53' }).end(); return; }
      const body = answer(Buffer.concat(chunks));
      res.writeHead(200, { 'content-type': 'application/dns-message', ...responseHeaders });
      const send = () => {
        if (chunkBytes) for (let at = 0; at < body.length; at += chunkBytes) res.write(body.subarray(at, at + chunkBytes));
        else res.write(body);
        res.end();
      };
      if (bodyDelayMs) {
        res.flushHeaders(); const timer = setTimeout(send, bodyDelayMs); res.once('close', () => clearTimeout(timer));
      } else send();
    });
  });
  origin.on('connection', track); origin.on('tlsClientError', () => {});
  origin.listen(0, '127.0.0.1'); await once(origin, 'listening');
  const secret = randomBytes(32), publicName = 'relay.test';
  const profile = compileLabDnsUpstream({ ...input, hostname: wrongName ? 'wrong.test' : 'localhost', port: origin.address().port,
    bootstrap: { addresses: ['127.0.0.1'] }, trust: badCa ? { mode: 'bundled' } : input.trust });
  const destinationPolicy = new ExitDestinationPolicy({ loopback: { hostname: profile.hostname, port: profile.port } });
  const replayGuard = new EncSniReplayGuard();
  const exit = net.createServer((socket) => {
    track(socket);
    socket.on('data', (bytes) => wire.push(Buffer.from(bytes)));
    sessions.push(wireTransparentTlsEncSniSession(socket, { vpnSecretBuf: secret, publicName, replayGuard, destinationPolicy,
      connectOrigin(address, port) { attempts++; return net.connect({ host: address, port }); } }));
  });
  exit.listen(0, '127.0.0.1'); await once(exit, 'listening');
  const options = { profile, exitAddress: '127.0.0.1', exitPort: exit.address().port, publicName,
    secret: wrongSecret ? randomBytes(32) : Buffer.from(secret) };
  const transport = createLabDnsExitTransport(options);
  // Transport owns snapshots, not the caller's mutable key/options.
  options.secret.fill(0); options.exitAddress = 'resolver.test'; options.exitPort = 1;
  const stub = await startLabDohStub({ exitTransport: transport, timeoutMs, maxInflight: 2, domainPolicy });
  t.after(async () => {
    await stub.close(); await transport.close();
    for (const socket of sockets) socket.destroy();
    await Promise.all(sessions.filter(Boolean).map((session) => session.closed));
    await Promise.all([origin, exit].map((server) => new Promise((resolve) => server.close(resolve))));
    await delay(10);
    for (const field of ['sockets', 'jobs']) assert.equal(transport.stats()[field], 0, field);
    for (const field of ['inflight', 'tcpSockets', 'tlsSockets', 'requests', 'jobs', 'timers']) assert.equal(stub.stats()[field], 0, field);
    for (const session of sessions.filter(Boolean)) assert.equal(session.timers.size, 0);
    assert.equal(sockets.size, 0);
  });
  return { stub, transport, wire, exitPort: exit.address().port, originPort: origin.address().port,
    counts: () => ({ bodies, attempts }), stopExit: () => new Promise((resolve) => exit.close(resolve)) };
}
test('QNAME policy refuses ordinary query types locally before exit TLS/DoH, UDP and TCP', async (t) => {
  const domainPolicy = { schema: 1, denySuffixes: ['auto.internal'] };
  const lab = await fixture(t, { domainPolicy });
  domainPolicy.denySuffixes[0] = 'changed.test'; // The running policy is a snapshot.
  let denied = 0;
  for (const tcp of [false, true]) for (const type of [1, 28, 5, 12, 16, 33, 64, 65, 65280]) {
    const q = makeDnsQuery('Case.AUTO.internal.', type, 456, 1232);
    const r = validateDnsResponse(await queryLabDns(lab.stub.port, q, { tcp }), q);
    assert.equal(r.rcode, 5); assert.deepEqual(r.counts, [0, 0, 1]); assert.equal(r.flags & 0x20, 0); denied++;
  }
  assert.equal(lab.stub.stats().policyDenied, denied); assert.equal(lab.stub.stats().forwarded, 0);
  assert.equal(lab.transport.stats().connections, 0); assert.deepEqual(lab.counts(), { bodies: 0, attempts: 0 });
  for (const tcp of [false, true]) {
    const q = makeDnsQuery('notauto.internal');
    assert.equal(validateDnsResponse(await queryLabDns(lab.stub.port, q, { tcp }), q).rcode, 0);
  }
  assert.equal(lab.counts().bodies, 2);
});

for (const tcp of [false, true]) for (const type of [1, 28, 12, 16, 33, 64, 65, 65280]) test(`in-memory relay ${tcp ? 'TCP' : 'UDP'} type ${type}: verified TLS, identity/path, snapshot, no listener`, async (t) => {
  const lab = await fixture(t);
  const packet = makeDnsQuery('private-adapter.dns-lab.test', type, 4321);
  const reply = await queryLabDns(lab.stub.port, packet, { tcp, fragment: true });
  assert.equal(validateDnsResponse(reply, packet).counts[0], 1);
  assert.deepEqual(reply, fixtureDnsAnswer(packet));
  assert.deepEqual(lab.counts(), { bodies: 1, attempts: 1 });
  assert.equal(lab.transport.stats().connections, 1);
});
for (const size of [4096, 4097, 65535]) test(`large TXT ${size} bytes: UDP cap and full fragmented TCP via exit`, async (t) => {
  const lab = await fixture(t, { answer: (q) => sizedTxtAnswer(q, size), chunkBytes: 127, timeoutMs: 1500 });
  const q = makeDnsQuery('large-adapter.test', 16, 4123, 65535);
  const udp = await queryLabDns(lab.stub.port, q), small = validateDnsResponse(udp, q);
  if (size > DNS_UDP_MAX_BYTES) { assert.equal(small.flags & 0x200, 0x200); assert.ok(udp.length <= DNS_UDP_MAX_BYTES); }
  else assert.deepEqual(udp, sizedTxtAnswer(q, size));
  const tcp = await queryLabDns(lab.stub.port, q, { tcp: true, fragment: true });
  assert.deepEqual(tcp, sizedTxtAnswer(q, size));
  assert.equal(lab.stub.stats().peakDohBodyBytes, size);
  assert.ok(lab.stub.stats().peakTcpPendingBytes <= 2 * (DNS_MAX_BYTES + 2));
});
test('maximum padded TCP query reaches resolver intact except ID; oversized UDP never dials exit', async (t) => {
  const base = makeDnsQuery('padded-adapter.test', 16, 4123, 65535);
  const q = paddedDnsQuery(base, DNS_MAX_BYTES), normalized = Buffer.from(q); normalized.writeUInt16BE(0);
  const lab = await fixture(t, { timeoutMs: 1500, onQuery: (packet) => assert.deepEqual(packet, normalized) });
  const r = await queryLabDns(lab.stub.port, q, { tcp: true, fragment: true });
  assert.deepEqual(r, fixtureDnsAnswer(q));
  await assert.rejects(queryLabDns(lab.stub.port, paddedDnsQuery(base, 4097), { timeoutMs: 50 }), { code: 'DNS_CLIENT_TIMEOUT' });
  assert.equal(lab.transport.stats().connections, 1);
  assert.equal(lab.stub.stats().rejected, 1);
});
for (const tcp of [false, true]) test(`EDNS BADVERS is local with no exit dial (${tcp ? 'TCP' : 'UDP'})`, async (t) => {
  const lab = await fixture(t, { mode: 'hold' });
  for (const version of [1, 255]) {
    const q = makeDnsQuery('version.test', 65, 42, 1232); q.writeUInt32BE(version * 65536 + 0x8000, q.length - 6);
    const r = validateDnsResponse(await queryLabDns(lab.stub.port, q, { tcp }), q);
    assert.equal(r.rcode, 16); assert.equal(r.edns.version, 0); assert.equal(r.edns.flags, 0x8000);
  }
  assert.deepEqual(lab.counts(), { attempts: 0, bodies: 0 }); assert.equal(lab.transport.stats().connections, 0);
});
for (const responseHeaders of [{ age: '250' }, { age: '999999999999999999999' }]) {
  test(`HTTP Age ${responseHeaders.age} reduces DNS TTL through exit`, async (t) => {
    const lab = await fixture(t, { responseHeaders, answer: (q) => fixtureDnsAnswer(q, { ttl: 600 }) });
    const q = makeDnsQuery('age.test', 1);
    const r = validateDnsResponse(await queryLabDns(lab.stub.port, q), q);
    assert.equal(r.records[0].ttl, responseHeaders.age === '250' ? 350 : 0);
  });
}
test('negative cached NXDOMAIN accounts for SOA MINIMUM before HTTP Age', async (t) => {
  const lab = await fixture(t, { responseHeaders: { age: '30' }, answer: negativeSoaAnswer });
  const q = makeDnsQuery('missing.test');
  const r = validateDnsResponse(await queryLabDns(lab.stub.port, q), q);
  assert.equal(r.rcode, 3); assert.equal(r.records[0].ttl, 30);
});
test('malformed negative SOA fails closed instead of forwarding an unchecked lifetime', async (t) => {
  const lab = await fixture(t, { answer: (q) => {
    const r = negativeSoaAnswer(q); r.writeUInt16BE(0xffff, parseDns(r).records[0].offset); return r;
  } });
  const q = makeDnsQuery('broken-soa.test');
  assert.equal(validateDnsResponse(await queryLabDns(lab.stub.port, q), q).rcode, 2);
  assert.equal(lab.stub.stats().errors.DNS_RESPONSE, 1); assert.equal(lab.transport.stats().connections, 1);
});
for (const age of ['-1', '1, 2', ['1', '1']]) test(`invalid/duplicate Age fails closed: ${age}`, async (t) => {
  const lab = await fixture(t, { responseHeaders: { age } });
  const q = makeDnsQuery('age.test');
  assert.equal(validateDnsResponse(await queryLabDns(lab.stub.port, q), q).rcode, 2);
  assert.equal(lab.stub.stats().errors.DNS_HTTP_AGE, 1); assert.equal(lab.transport.stats().connections, 1);
});
test('slow HTTP body transfer cannot extend TTL', async (t) => {
  const lab = await fixture(t, { timeoutMs: 2500, responseHeaders: { age: '10' }, bodyDelayMs: 1100 });
  const q = makeDnsQuery('slow-age.test');
  const r = validateDnsResponse(await queryLabDns(lab.stub.port, q), q);
  assert.ok(r.records[0].ttl <= 19 && r.records[0].ttl >= 18);
});
for (const declared of [false, true]) test(`65536-byte HTTP body rejected (${declared ? 'content-length' : 'chunked'})`, async (t) => {
  const lab = await fixture(t, { answer: () => Buffer.alloc(DNS_MAX_BYTES + 1),
    responseHeaders: declared ? { 'content-length': String(DNS_MAX_BYTES + 1) } : {}, timeoutMs: 1500 });
  const q = makeDnsQuery('oversize.test');
  assert.equal(validateDnsResponse(await queryLabDns(lab.stub.port, q), q).rcode, 2);
  assert.equal(lab.stub.stats().failed, 1); assert.ok(lab.stub.stats().peakDohBodyBytes <= DNS_MAX_BYTES);
});
test('TCP pending buffer overflow cancels a held query and releases capacity', async (t) => {
  const lab = await fixture(t, { mode: 'hold', timeoutMs: 1500 });
  const socket = net.connect(lab.stub.port, '127.0.0.1'); socket.on('error', () => {}); t.after(() => socket.destroy());
  await once(socket, 'connect');
  const q = makeDnsQuery('buffer.test'), frame = Buffer.alloc(q.length + 2); frame.writeUInt16BE(q.length); q.copy(frame, 2);
  socket.write(frame);
  const deadline = Date.now() + 1000;
  while (!lab.counts().bodies) { assert.ok(Date.now() < deadline); await delay(5); }
  const closed = new Promise((resolve) => socket.once('close', resolve));
  socket.write(Buffer.alloc(2 * (DNS_MAX_BYTES + 2) + 1)); await closed;
  assert.ok(lab.stub.stats().peakTcpPendingBytes <= 2 * (DNS_MAX_BYTES + 2));
  assert.equal(lab.stub.stats().rejected, 1); assert.equal(lab.transport.stats().connections, 1);
});
test('HTTPS UDP truncation then TCP retry preserves complete opaque answer and extended RCODE', async (t) => {
  const answer = (q) => {
    const r = fixtureDnsAnswer(q, { count: 40 });
    r.writeUInt32BE(0x01008000, r.length - 6); // extended RCODE 16 + DO
    return r;
  };
  const lab = await fixture(t, { answer });
  const q = makeDnsQuery('service.test', 65, 0xabcd, 512);
  const udp = await queryLabDns(lab.stub.port, q);
  const small = validateDnsResponse(udp, q);
  assert.ok(udp.length <= 512); assert.equal(small.rcode, 16);
  assert.equal(small.flags & 0x200, 0x200); assert.equal(small.counts[0], 0);
  const tcp = await queryLabDns(lab.stub.port, q, { tcp: true, fragment: true });
  assert.deepEqual(tcp, answer(q)); assert.equal(validateDnsResponse(tcp, q).counts[0], 40);
  assert.deepEqual(lab.counts(), { bodies: 2, attempts: 2 });
});
for (const options of [{ badCa: true }, { wrongName: true }, { wrongSecret: true }, { mode: 'hold' }, { mode: 'reset' }, { mode: 'redirect' }]) {
  test(`in-memory relay fails closed: ${JSON.stringify(options)}`, async (t) => {
    const lab = await fixture(t, options), packet = makeDnsQuery('private-adapter.dns-lab.test', 1, 77);
    const reply = await queryLabDns(lab.stub.port, packet);
    assert.equal(validateDnsResponse(reply, packet).flags & 15, 2);
    assert.equal(lab.counts().bodies, options.mode ? 1 : 0);
    assert.equal(lab.transport.stats().connections, 1);
    assert.equal(lab.counts().attempts, options.wrongSecret ? 0 : 1);
  });
}
test('numeric exit unavailable: SERVFAIL, no origin attempt', async (t) => {
  const lab = await fixture(t); await lab.stopExit();
  const packet = makeDnsQuery('private-adapter.dns-lab.test', 1);
  assert.equal(validateDnsResponse(await queryLabDns(lab.stub.port, packet), packet).flags & 15, 2);
  assert.deepEqual(lab.counts(), { bodies: 0, attempts: 0 });
});
test('shutdown aborts a held TLS request and drains resources', async (t) => {
  const lab = await fixture(t, { mode: 'hold', timeoutMs: 1000 });
  const request = queryLabDns(lab.stub.port, makeDnsQuery('private-adapter.dns-lab.test', 1), { tcp: true }).catch(() => {});
  const deadline = Date.now() + 2000;
  while (!lab.counts().bodies) { assert.ok(Date.now() < deadline); await delay(5); }
  await lab.transport.close(); await request; await lab.stub.close();
  assert.equal(lab.transport.stats().jobs, 0);
});
test('no system lookup, direct resolver or plaintext QNAME on client-exit wire', async (t) => {
  const lab = await fixture(t);
  let lookups = 0;
  for (const api of [dns, dnsPromises]) for (const name of ['lookup', 'resolve', 'resolve4', 'resolve6']) {
    const original = api[name];
    t.mock.method(api, name, (...args) => {
      // dgram invokes lookup for numeric bind/send, without an actual DNS query.
      if (name === 'lookup' && net.isIP(args[0])) return original.apply(api, args);
      lookups++; throw new Error('lookup forbidden');
    });
  }
  const connects = [], connect = net.Socket.prototype.connect;
  t.mock.method(net.Socket.prototype, 'connect', function (...args) {
    const options = Array.isArray(args[0]) ? args[0][0] : args[0];
    connects.push({ address: options.host, port: options.port }); return connect.apply(this, args);
  });
  const packet = makeDnsQuery('private-adapter.dns-lab.test', 28);
  assert.equal(validateDnsResponse(await queryLabDns(lab.stub.port, packet), packet).counts[0], 1);
  assert.equal(lookups, 0); assert.equal(lab.transport.stats().connections, 1);
  const wire = Buffer.concat(lab.wire); assert.ok(wire.length > 100);
  assert.equal(wire.includes(Buffer.from('private-adapter')), false);
  assert.equal(wire.includes(packet.subarray(12)), false);
  assert.equal(lab.counts().bodies, 1);
  assert.deepEqual(connects, [{ address: '127.0.0.1', port: lab.exitPort }, { address: '127.0.0.1', port: lab.originPort }]);
});
test('invalid limits and occupied listen port roll back adapter startup without connecting', async () => {
  await assert.rejects(startDnsExitAdapter({ ...publicOptions(), maxInflight: 0 }), { code: 'DNS_CONFIG' });
  const server = net.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try { await assert.rejects(startDnsExitAdapter({ ...publicOptions(), port: server.address().port }), { code: 'EADDRINUSE' }); }
  finally { await new Promise((resolve) => server.close(resolve)); }
});

const argv = ['--config=/private/config.json', '--exit-ip=93.184.216.35', '--exit-port=443', '--public-name=relay.test',
  '--shared-hmac-key=/private/key', '--listen-port=1053'];
for (const args of [[], argv.slice(1), [...argv, argv[0]], [...argv, '--direct=true'], [...argv, '--help'],
  argv.map((x) => x === '--listen-port=1053' ? '--listen-port=53' : x),
  argv.map((x) => x === '--exit-port=443' ? '--exit-port=443junk' : x)]) {
  test(`CLI rejects invalid arguments ${JSON.stringify(args)}`, () => assert.throws(() => parseDnsExitArgs(args), /DNS_EXIT_ADAPTER_INVALID/));
}
test('CLI help is offline; errors are redacted', async () => {
  assert.equal(parseDnsExitArgs(argv)['listen-port'], 1053);
  for (const [args, code] of [[['--help'], 0], [argv, 1]]) {
    const result = await runCommand(process.execPath, ['scripts/dns-exit-adapter.mjs', ...args], { env: cleanEnvironment(process.env) });
    assert.equal(result.code, code); assert.equal(result.reason, null);
    if (code) { assert.equal(result.stderr.trim(), 'DNS_EXIT_ADAPTER_INVALID'); assert.equal(result.stdout, ''); }
  }
});
test('PSK reader requires exactly 32 binary bytes, private regular file, no symlink', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-dns-exit-key-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'key'), secret = randomBytes(32);
  await writeFile(path, secret, { mode: 0o600 }); assert.deepEqual(await readDnsExitSecret(path), secret);
  await symlink(path, join(dir, 'link')); await assert.rejects(readDnsExitSecret(join(dir, 'link')), /DNS_EXIT_ADAPTER_INVALID/);
  await assert.rejects(readDnsExitSecret(dir), /DNS_EXIT_ADAPTER_INVALID/);
  await chmod(path, 0o644); await assert.rejects(readDnsExitSecret(path), /DNS_EXIT_ADAPTER_INVALID/);
  await chmod(path, 0o600);
  for (const size of [0, 31, 33, 65536]) { await writeFile(path, Buffer.alloc(size)); await assert.rejects(readDnsExitSecret(path), /DNS_EXIT_ADAPTER_INVALID/); }
});
for (const signal of ['SIGINT', 'SIGTERM']) test(`CLI explicit bind then ${signal} releases listener without resolver traffic`, { timeout: 10000 }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-dns-exit-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const config = join(dir, 'upstream.json'), secret = join(dir, 'key');
  await writeFile(config, JSON.stringify(input), { mode: 0o600 }); await writeFile(secret, randomBytes(32), { mode: 0o600 });
  const portProbe = net.createServer(); portProbe.listen(0, '127.0.0.1'); await once(portProbe, 'listening');
  const port = portProbe.address().port; await new Promise((resolve) => portProbe.close(resolve));
  const proc = child(process.execPath, ['scripts/dns-exit-adapter.mjs', `--config=${config}`, '--exit-ip=93.184.216.35',
    '--exit-port=443', '--public-name=relay.test', `--shared-hmac-key=${secret}`, `--listen-port=${port}`], { env: cleanEnvironment(process.env) });
  t.after(() => proc.stop());
  const ready = await proc.waitFor(/DNS_EXIT_ADAPTER (\{[^\n]+\})/, 5000);
  assert.deepEqual(JSON.parse(ready[1]), { status: 'listening', address: '127.0.0.1', port, systemDnsChanged: false, domainPolicyEnabled: false });
  await proc.stop(signal); assert.equal(proc.proc.exitCode, 0);
  portProbe.listen(port, '127.0.0.1'); await once(portProbe, 'listening'); await new Promise((resolve) => portProbe.close(resolve));
});
test('CLI loads domain policy before listening; rejects invalid file and answers denied queries locally', { timeout: 10000 }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-dns-policy-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const config = join(dir, 'upstream.json'), secret = join(dir, 'key'), policy = join(dir, 'policy.json');
  await writeFile(config, JSON.stringify(input)); await writeFile(secret, randomBytes(32), { mode: 0o600 });
  const probe = net.createServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
  const port = probe.address().port; await new Promise((resolve) => probe.close(resolve));
  const args = ['scripts/dns-exit-adapter.mjs', `--config=${config}`, '--exit-ip=93.184.216.35',
    '--exit-port=443', '--public-name=relay.test', `--shared-hmac-key=${secret}`, `--listen-port=${port}`, `--domain-policy=${policy}`];
  await writeFile(policy, '{}');
  const bad = await runCommand(process.execPath, args, { env: cleanEnvironment(process.env) });
  assert.equal(bad.code, 1); assert.equal(bad.stdout, ''); assert.equal(bad.stderr.trim(), 'DNS_EXIT_ADAPTER_INVALID');
  await writeFile(policy, JSON.stringify({ schema: 1, denySuffixes: ['auto.internal'] }));
  const proc = child(process.execPath, args, { env: cleanEnvironment(process.env) }); t.after(() => proc.stop());
  const ready = JSON.parse((await proc.waitFor(/DNS_EXIT_ADAPTER (\{[^\n]+\})/, 5000))[1]);
  assert.equal(ready.domainPolicyEnabled, true);
  for (const tcp of [false, true]) {
    const q = makeDnsQuery('vm.auto.internal');
    assert.equal(validateDnsResponse(await queryLabDns(port, q, { tcp }), q).rcode, 5);
  }
  await proc.stop(); assert.equal(proc.proc.exitCode, 0);
});
