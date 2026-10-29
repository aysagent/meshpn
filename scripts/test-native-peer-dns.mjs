import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import dgram from 'node:dgram';
import net from 'node:net';
import { once } from 'node:events';
import { spawnSync } from 'node:child_process';
import { peerDnsSnapshot, readPeerDnsRegistry, peerDnsAnswer, startPeerDns, peerDnsUnit, PEER_DNS_LIMITS } from './lib/native-peer-dns.mjs';
import { makeDnsQuery, parseDns, validateDnsResponse } from './lib/lab-dns-wire.mjs';

const registry = (clients = [{ name: 'laptop', ipv4: '10.99.0.3', revoked: false }], revision = 1) => ({ version: 1, revision, clients });
const state = () => peerDnsSnapshot(registry());
function temporary(t) {
  const directory = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'cvpn-peer-dns-')); fs.chmodSync(directory, 0o700);
  const filename = path.join(directory, 'registry.json');
  const publish = object => { const next = filename + '.next'; fs.writeFileSync(next, typeof object === 'string' ? object : JSON.stringify(object), { mode: 0o600 }); fs.renameSync(next, filename); };
  publish(registry()); t.after(() => fs.rmSync(directory, { recursive: true, force: true })); return { filename, publish, directory };
}
function udpQuery(port, query) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4'); const timer = setTimeout(() => { socket.close(); reject(new Error('udp_timeout')); }, 2000);
    socket.once('message', data => { clearTimeout(timer); socket.close(); resolve(data); });
    socket.once('error', error => { clearTimeout(timer); socket.close(); reject(error); }); socket.send(query, port, '127.0.0.1');
  });
}
async function tcpQuery(port, queries, fragmented = false) {
  const socket = net.connect(port, '127.0.0.1'); await once(socket, 'connect');
  return new Promise((resolve, reject) => {
    let buffered = Buffer.alloc(0); const replies = [];
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('tcp_timeout')); }, 2000);
    socket.on('error', reject); socket.on('data', data => {
      buffered = Buffer.concat([buffered, data]);
      while (buffered.length >= 2 && buffered.length >= buffered.readUInt16BE(0) + 2) {
        const n = buffered.readUInt16BE(0); replies.push(buffered.subarray(2, n + 2)); buffered = buffered.subarray(n + 2);
      }
      if (replies.length === queries.length) { clearTimeout(timer); socket.destroy(); resolve(replies); }
    });
    const data = Buffer.concat(queries.map(query => { const size = Buffer.alloc(2); size.writeUInt16BE(query.length); return Buffer.concat([size, query]); }));
    if (fragmented) { socket.write(data.subarray(0, 1)); setTimeout(() => socket.write(data.subarray(1)), 5); }
    else socket.write(data);
  });
}

test('private records use stable names and exclude revoked identities', () => {
  const s = peerDnsSnapshot(registry([{ name: 'laptop', ipv4: '10.99.0.3', revoked: false }, { name: 'phone', ipv4: '10.99.0.4', revoked: true }]));
  assert.equal(s.forward.size, 1); assert.equal(s.reverse.size, 1);
  assert.equal(parseDns(peerDnsAnswer(makeDnsQuery('phone.mpn'), s)).rcode, 3);
});
test('registry rejects invalid names, addresses, duplicates and ambiguous revocation', () => {
  for (const changes of [{ name: '../root' }, { name: 'Laptop' }, { name: 'laptop.mpn' }, { name: '-laptop' }, { name: 'laptop-' }, { ipv4: '10.99.0.1' }, { ipv4: '10.99.1.3' }, { ipv4: '10.99.0.03' }, { revoked: undefined }])
    assert.throws(() => peerDnsSnapshot(registry([{ name: 'laptop', ipv4: '10.99.0.3', revoked: false, ...changes }])));
  assert.throws(() => peerDnsSnapshot(registry([{ name: 'a', ipv4: '10.99.0.3', revoked: false }, { name: 'b', ipv4: '10.99.0.3', revoked: true }])));
  assert.throws(() => peerDnsSnapshot(registry([{ name: 'a', ipv4: '10.99.0.3', revoked: false }, { name: 'a', ipv4: '10.99.0.4', revoked: false }])));
  assert.throws(() => peerDnsSnapshot(registry([], -1)));
});
test('A answers are authoritative, case-insensitive and bounded to five seconds', () => {
  const q = makeDnsQuery('LaPtOp.MPN', 1, 1542), r = peerDnsAnswer(q, state()), parsed = validateDnsResponse(r, q);
  assert.equal(parsed.rcode, 0); assert.equal(parsed.counts[0], 1); assert.ok(parsed.flags & 0x400); assert.equal(parsed.flags & 0x80, 0);
  const rr = parsed.records[0]; assert.equal(rr.ttl, 5); assert.deepEqual([...r.subarray(rr.offset, rr.offset + rr.length)], [10, 99, 0, 3]);
});
test('PTR maps only allocated active addresses', () => {
  const r = peerDnsAnswer(makeDnsQuery('3.0.99.10.in-addr.arpa', 12), state()), parsed = parseDns(r), rr = parsed.records[0];
  assert.equal(parsed.rcode, 0); assert.equal(rr.type, 12); assert.deepEqual(r.subarray(rr.offset, rr.offset + rr.length), Buffer.from([6, ...Buffer.from('laptop'), 3, ...Buffer.from('mpn'), 0]));
  assert.equal(parseDns(peerDnsAnswer(makeDnsQuery('4.0.99.10.in-addr.arpa', 12), state())).rcode, 3);
});
test('unknown zone names return authoritative NXDOMAIN with bounded SOA', () => {
  for (const name of ['absent.mpn', 'www.laptop.mpn', 'mpn.mpn']) {
    const r = parseDns(peerDnsAnswer(makeDnsQuery(name), state())); assert.equal(r.rcode, 3); assert.deepEqual(r.counts, [0, 1, 0]); assert.equal(r.records[0].type, 6); assert.equal(r.records[0].ttl, 5);
  }
});
test('known names have no AAAA HTTPS SVCB or unexpected type hints', () => {
  for (const type of [28, 64, 65, 16, 2]) {
    const r = parseDns(peerDnsAnswer(makeDnsQuery('laptop.mpn', type), state())); assert.equal(r.rcode, 0); assert.deepEqual(r.counts, [0, 1, 0]);
  }
  assert.equal(parseDns(peerDnsAnswer(makeDnsQuery('mpn', 6), state())).records[0].type, 6);
});
test('outside names are refused even when registry is unavailable; never recursion', () => {
  for (const name of ['example.com', 'mpn.example', 'notmpn', '3.0.99.11.in-addr.arpa']) {
    const r = parseDns(peerDnsAnswer(makeDnsQuery(name), null)); assert.equal(r.rcode, 5); assert.equal(r.flags & 0x480, 0);
  }
});
test('embedded dot in one binary label cannot impersonate laptop.mpn', () => {
  const h = makeDnsQuery('laptop.mpn').subarray(0, 12);
  const q = Buffer.concat([h, Buffer.from([10]), Buffer.from('laptop.mpn'), Buffer.from([0, 0, 1, 0, 1])]);
  assert.equal(parseDns(peerDnsAnswer(q, state())).rcode, 5);
});
test('bad registry is SERVFAIL, malformed queries are bounded, response packets ignored', () => {
  assert.equal(parseDns(peerDnsAnswer(makeDnsQuery('laptop.mpn'), null)).rcode, 2);
  assert.equal(peerDnsAnswer(Buffer.alloc(3), state()), null);
  assert.equal(peerDnsAnswer(Buffer.alloc(4097), state()), null);
  const q = makeDnsQuery('laptop.mpn'); q[2] |= 128; assert.equal(peerDnsAnswer(q, state()), null);
  const bad = makeDnsQuery('laptop.mpn'); bad[12] = 0xc0; bad[13] = 12;
  const r = peerDnsAnswer(bad, state()); assert.equal(r.length, 12); assert.equal(r[3] & 15, 1);
});
test('EDNS version zero preserved and nonzero BADVERS has no RA', () => {
  const q = makeDnsQuery('laptop.mpn', 1, 1, 1232), r = parseDns(peerDnsAnswer(q, state()));
  assert.deepEqual(r.counts, [1, 0, 1]); assert.equal(r.edns.version, 0);
  const opt = parseDns(q).records[0]; q[opt.offset - 5] = 1;
  const badvers = parseDns(peerDnsAnswer(q, state())); assert.equal(badvers.rcode, 16); assert.equal(badvers.flags & 0x80, 0);
});
test('registry reads reject symlinks, permissive modes and oversize contents', t => {
  const tmp = temporary(t); assert.equal(readPeerDnsRegistry(tmp.filename).forward.size, 1);
  fs.chmodSync(tmp.filename, 0o644); assert.throws(() => readPeerDnsRegistry(tmp.filename)); fs.chmodSync(tmp.filename, 0o600);
  fs.symlinkSync(tmp.filename, path.join(tmp.directory, 'linked')); assert.throws(() => readPeerDnsRegistry(path.join(tmp.directory, 'linked')));
  tmp.publish('x'.repeat(PEER_DNS_LIMITS.registryBytes + 1)); assert.throws(() => readPeerDnsRegistry(tmp.filename));
});
test('unfinished manager transaction fails closed including a dangling marker symlink', t => {
  const tmp = temporary(t), marker = path.join(tmp.directory, 'transaction.json');
  fs.writeFileSync(marker, '{}', { mode: 0o600 }); assert.throws(() => readPeerDnsRegistry(tmp.filename), /peer_dns_transaction_pending/);
  fs.unlinkSync(marker); fs.symlinkSync(path.join(tmp.directory, 'absent'), marker); assert.throws(() => readPeerDnsRegistry(tmp.filename), /peer_dns_transaction_pending/);
  fs.unlinkSync(marker); assert.equal(readPeerDnsRegistry(tmp.filename).forward.size, 1);
});
test('UDP and fragmented/pipelined TCP serve same live registry and fail closed after corruption', async t => {
  const tmp = temporary(t), server = await startPeerDns({ registry: tmp.filename, port: 0 }); t.after(() => server.close());
  const q = makeDnsQuery('laptop.mpn'); assert.equal(parseDns(await udpQuery(server.port, q)).counts[0], 1);
  const replies = await tcpQuery(server.port, [q, makeDnsQuery('3.0.99.10.in-addr.arpa', 12)], true); assert.deepEqual(replies.map(r => parseDns(r).counts[0]), [1, 1]);
  tmp.publish(registry([{ name: 'laptop', ipv4: '10.99.0.3', revoked: true }], 2)); assert.equal(parseDns(await udpQuery(server.port, q)).rcode, 3);
  tmp.publish('{'); assert.equal(parseDns(await udpQuery(server.port, q)).rcode, 2);
  tmp.publish(registry([{ name: 'newname', ipv4: '10.99.0.3', revoked: false }], 3));
  assert.equal(parseDns(await udpQuery(server.port, q)).rcode, 3); assert.equal(parseDns(await udpQuery(server.port, makeDnsQuery('newname.mpn'))).counts[0], 1);
});
test('TCP rejects oversized frame and stop releases both protocol ports', async t => {
  const tmp = temporary(t), server = await startPeerDns({ registry: tmp.filename, port: 0 }); t.after(() => server.close());
  const socket = net.connect(server.port, '127.0.0.1'); await once(socket, 'connect'); socket.write(Buffer.from([0xff, 0xff])); await once(socket, 'close');
  const port = server.port; await server.close(); const replacement = await startPeerDns({ registry: tmp.filename, port }); await replacement.close();
});
test('server forbids public bind and startup fails without valid registry', async t => {
  const tmp = temporary(t); await assert.rejects(startPeerDns({ registry: tmp.filename, address: '0.0.0.0' })); tmp.publish('{}'); await assert.rejects(startPeerDns({ registry: tmp.filename }));
});
test('TCP connection cap rejects excess clients while an admitted client still works', async t => {
  const tmp = temporary(t), server = await startPeerDns({ registry: tmp.filename, port: 0 }); t.after(() => server.close());
  const sockets = [];
  for (let i = 0; i < PEER_DNS_LIMITS.tcpConnections; i++) {
    const s = net.connect(server.port, '127.0.0.1'); sockets.push(s); await once(s, 'connect');
  }
  t.after(() => sockets.forEach(s => s.destroy()));
  const overflow = net.connect(server.port, '127.0.0.1'); const closed = once(overflow, 'close'); await closed;
  const first = sockets[0], q = makeDnsQuery('laptop.mpn'), length = Buffer.alloc(2); length.writeUInt16BE(q.length);
  const received = once(first, 'data'); first.write(Buffer.concat([length, q]));
  const [data] = await received; assert.equal(parseDns(data.subarray(2)).counts[0], 1);
});
test('TCP absolute per-connection query budget closes persistent pipelining', async t => {
  const tmp = temporary(t), server = await startPeerDns({ registry: tmp.filename, port: 0 }); t.after(() => server.close());
  const socket = net.connect(server.port, '127.0.0.1'); await once(socket, 'connect'); socket.resume();
  const q = makeDnsQuery('laptop.mpn'), length = Buffer.alloc(2); length.writeUInt16BE(q.length);
  const closed = once(socket, 'close'); socket.write(Buffer.concat(Array.from({ length: PEER_DNS_LIMITS.tcpQueries + 1 }, () => Buffer.concat([length, q]))));
  await closed; assert.ok(server.counters.answered <= PEER_DNS_LIMITS.tcpQueries);
});
test('TCP bind failure rolls back UDP bind', async t => {
  const tmp = temporary(t), occupied = net.createServer(); occupied.listen(0, '127.0.0.1'); await once(occupied, 'listening'); t.after(() => occupied.close());
  const port = occupied.address().port; await assert.rejects(startPeerDns({ registry: tmp.filename, port }));
  const udp = dgram.createSocket('udp4'); udp.bind(port, '127.0.0.1'); await once(udp, 'listening'); udp.close();
});
test('unit is opt-in and uses high port with no privileged network capability', () => {
  const unit = peerDnsUnit({ node: '/usr/bin/node', script: '/opt/project/scripts/clean-vpn-native-peer-dns.mjs', registry: '/var/lib/clean-vpn/clients/registry.json' });
  assert.match(unit, /CapabilityBoundingSet=\n/); assert.match(unit, /--port=1055/); assert.doesNotMatch(unit, /ExecStartPre|iptables|resolvectl|CAP_NET_ADMIN/);
  assert.throws(() => peerDnsUnit({ node: '/usr/bin/node', script: '/tmp/a%name', registry: '/tmp/registry' }));
});
test('CLI checks counts without disclosing credential fields', t => {
  const tmp = temporary(t); tmp.publish(registry([{ name: 'laptop', ipv4: '10.99.0.3', revoked: false, secret_path: '/secret/never-display' }]));
  const r = spawnSync(process.execPath, ['scripts/clean-vpn-native-peer-dns.mjs', 'check', '--registry=' + tmp.filename], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).clients, 1); assert.doesNotMatch(r.stdout, /secret/);
});
