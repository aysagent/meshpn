import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectPcap } from './clean-vpn-pcap-fingerprints.mjs';

const destination = '154.62.226.216', options = { destination };
const body = Buffer.concat([Buffer.from('0303', 'hex'), Buffer.alloc(32),
  Buffer.from('000002130101000007002b0003020304', 'hex')]);
const handshake = Buffer.alloc(4); handshake[0] = 1; handshake.writeUIntBE(body.length, 1, 3);
const record = b => { const h = Buffer.from('1603010000', 'hex'); h.writeUInt16BE(b.length, 3); return Buffer.concat([h, b]); };
const hello = record(Buffer.concat([handshake, body]));
function packet(seq, payload = Buffer.alloc(0), flags = 0x18) {
  const b = Buffer.alloc(54 + payload.length); b.writeUInt16BE(0x0800, 12);
  b[14] = 0x45; b.writeUInt16BE(40 + payload.length, 16); b[23] = 6;
  Buffer.from([192, 0, 2, 1, 154, 62, 226, 216]).copy(b, 26);
  b.writeUInt16BE(45678, 34); b.writeUInt16BE(443, 36); b.writeUInt32BE(seq >>> 0, 38);
  b[46] = 0x50; b[47] = flags; payload.copy(b, 54); return b;
}
function pcap(packets, le = true) {
  const u32 = (b, v, o) => le ? b.writeUInt32LE(v, o) : b.writeUInt32BE(v, o);
  const header = Buffer.alloc(24); Buffer.from(le ? 'd4c3b2a1' : 'a1b2c3d4', 'hex').copy(header);
  if (le) { header.writeUInt16LE(2, 4); header.writeUInt16LE(4, 6); }
  else { header.writeUInt16BE(2, 4); header.writeUInt16BE(4, 6); }
  u32(header, 65535, 16); u32(header, 1, 20);
  return Buffer.concat([header, ...packets.flatMap(p => {
    const h = Buffer.alloc(16); u32(h, p.length, 8); u32(h, p.length, 12); return [h, p];
  })]);
}
for (const le of [true, false]) test(`observed JA4 from classic pcap endian=${le}`, () => {
  const r = inspectPcap(pcap([packet(100, undefined, 2), packet(101, hello)], le), options);
  assert.equal(r.connections[0].status, 'observed');
  assert.equal(r.connections[0].ja4, 't13i010100_0f2cb44170f4_b9a491fefe05');
  assert.equal(r.connections[0].ja3String, '771,4865,43,,');
});
test('reassembles reordered segments, duplicate SYN, overlap and sequence wrap', () => {
  const syn = 0xfffffff0, base = (syn + 1) >>> 0;
  const r = inspectPcap(pcap([packet(syn, undefined, 2), packet(syn, undefined, 2),
    packet(base + 20, hello.subarray(20)), packet(base, hello.subarray(0, 35)),
    packet(base, hello.subarray(0, 35))]), options);
  assert.equal(r.connections.length, 1); assert.equal(r.connections[0].status, 'observed');
});
test('ClientHello fragmented across TLS records', () => {
  const h = Buffer.concat([handshake, body]);
  const wire = Buffer.concat([record(h.subarray(0, 2)), record(h.subarray(2, 20)), record(h.subarray(20))]);
  assert.equal(inspectPcap(pcap([packet(0, undefined, 2), packet(1, wire)]), options).connections[0].status, 'observed');
});
test('conflicting TCP overlap never produces a fingerprint', () => {
  const r = inspectPcap(pcap([packet(0, undefined, 2), packet(1, hello), packet(10, Buffer.from([255]))]), options);
  assert.equal(r.connections[0].status, 'conflicting_tcp_overlap'); assert.equal(r.connections[0].ja4, undefined);
});
test('capture without SYN and capture with a gap do not guess a ClientHello', () => {
  assert.equal(inspectPcap(pcap([packet(1, hello)]), options).connections.length, 0);
  assert.equal(inspectPcap(pcap([packet(0, undefined, 2), packet(2, hello.subarray(1))]), options).connections[0].status, 'incomplete_clienthello');
});
test('new connection on reused tuple does not concatenate old bytes', () => {
  const r = inspectPcap(pcap([packet(0, undefined, 2), packet(1, hello), packet(80, undefined, 1),
    packet(200, undefined, 2), packet(201, hello)]), options);
  assert.equal(r.connections.length, 2); assert.ok(r.connections.every(c => c.status === 'observed'));
});
test('malformed record lengths and unsupported capture format fail closed', () => {
  const b = pcap([packet(0, undefined, 2)]);
  assert.throws(() => inspectPcap(b.subarray(0, b.length - 1), options), /incomplete_pcap_packet/);
  const other = Buffer.from(b); other.writeUInt32LE(113, 20);
  assert.throws(() => inspectPcap(other, options), /ethernet_pcap/);
  assert.throws(() => inspectPcap(Buffer.alloc(24), options), /classic_pcap/);
});
test('truncated captured frame is counted and never accepted', () => {
  const b = pcap([packet(0, undefined, 2), packet(1, hello)]);
  b.writeUInt32LE(b.readUInt32LE(24 + 16 + 54 + 12) + 10, 24 + 16 + 54 + 12);
  const r = inspectPcap(b, options);
  assert.equal(r.counts.truncated, 1); assert.equal(r.connections[0].status, 'incomplete_clienthello');
});
test('bounded stream admission', () => {
  const packets = Array.from({ length: 129 }, (_, i) => packet(i, undefined, 2));
  assert.throws(() => inspectPcap(pcap(packets), options), /stream_limit/);
});
