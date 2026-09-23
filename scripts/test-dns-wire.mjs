import assert from 'node:assert/strict';
import test from 'node:test';
import { makeDnsQuery, parseDnsQuery, parseDns, validateDnsResponse, fixtureDnsAnswer,
  dnsFailure, truncateDnsResponse, DNS_MAX_BYTES, DNS_UDP_MAX_BYTES, ageDnsResponse } from './lib/lab-dns-wire.mjs';
import { dnsHttpAge } from './lib/dns-http-age.mjs';
import { sizedTxtAnswer, paddedDnsQuery, negativeSoaAnswer } from './lib/dns-wire-fixtures.mjs';

const query = (type = 65, size = 1232) => makeDnsQuery('_svc.Example.test', type, 0xabcd, size);
const rejected = (fn) => assert.throws(fn, { code: 'DNS_WIRE' });
function options(packet, data) {
  const opt = parseDns(packet).records.find((rr) => rr.type === 41);
  assert.equal(opt.offset, packet.length);
  const copy = Buffer.from(packet); copy.writeUInt16BE(data.length, opt.offset - 2);
  return Buffer.concat([copy, data]);
}
function rawQuestion(labels) {
  const header = Buffer.from('abcd01000001000000000000', 'hex');
  return Buffer.concat([header, ...labels.flatMap((label) => [Buffer.from([label.length]), label]), Buffer.from('0000100001', 'hex')]);
}

for (const type of [1, 2, 5, 6, 12, 15, 16, 28, 33, 39, 43, 46, 47, 48, 50, 51, 52, 64, 65, 257, 65280]) {
  test(`ordinary IN type ${type}: envelope and opaque RDATA round trip`, () => {
    const q = query(type), reply = fixtureDnsAnswer(q);
    const before = Buffer.from(reply), parsed = validateDnsResponse(reply, q);
    assert.equal(parsed.type, type); assert.equal(parsed.counts[0], 1);
    assert.deepEqual(reply, before);
  });
}
for (const type of [0, 41, 249, 250, 251, 252, 253, 254, 255, 65535]) {
  test(`pilot excludes meta/transfer/reserved type ${type}`, () => rejected(() => makeDnsQuery('example.test', type)));
}
test('root question, trailing dot, ASCII case folding and binary label boundaries', () => {
  assert.equal(parseDnsQuery(makeDnsQuery('.', 2)).nameKey, '');
  assert.deepEqual(makeDnsQuery('example.test.'), makeDnsQuery('example.test'));
  const q = rawQuestion([Buffer.from([65, 0, 192, 255]), Buffer.from('test')]);
  const r = dnsFailure(q); r[13] = 97; validateDnsResponse(r, q);
  r[16] = 223; rejected(() => validateDnsResponse(r, q)); // no Unicode case folding
  const one = rawQuestion([Buffer.from('a.b')]), two = rawQuestion([Buffer.from('a'), Buffer.from('b')]);
  assert.equal(parseDnsQuery(one).name, parseDnsQuery(two).name);
  rejected(() => validateDnsResponse(dnsFailure(one), two));
});
test('EDNS options and DO/CD/AD pass unchanged; local errors omit request options and AD', () => {
  const q = options(query(), Buffer.from('fde8000500ff41c000000c0003000000', 'hex'));
  q.writeUInt16BE(0x0130, 2);
  const opt = parseDns(q).records[0]; q.writeUInt32BE(0x8000, opt.offset - 6);
  const reply = fixtureDnsAnswer(q); reply.writeUInt16BE(reply.readUInt16BE(2) | 0x20, 2);
  const withOptions = options(reply, Buffer.from('fde8000300ff41', 'hex'));
  assert.equal(validateDnsResponse(withOptions, q).edns.flags, 0x8000);
  const failure = dnsFailure(q), parsed = validateDnsResponse(failure, q);
  assert.equal(parsed.flags & 0x30, 0x10); assert.equal(parsed.edns.flags, 0x8000);
  assert.equal(parsed.records[0].length, 0);
});
test('extended RCODE, including BADVERS and 4095, survives safe UDP truncation', () => {
  for (const rcode of [0, 3, 16, 23, 4095]) {
    const q = query(), r = dnsFailure(q, rcode); r.writeUInt16BE(r.readUInt16BE(2) | 0x420, 2);
    const small = truncateDnsResponse(q, r), parsed = validateDnsResponse(small, q);
    assert.equal(parsed.rcode, rcode); assert.equal(parsed.flags & 0x200, 0x200);
    assert.equal(parsed.flags & 0x420, 0); assert.equal(parsed.id, 0xabcd);
    assert.deepEqual(parsed.counts, [0, 0, 1]); assert.ok(small.length <= 512);
  }
  const plain = makeDnsQuery('example.test');
  rejected(() => dnsFailure(plain, 16));
  for (const code of [-1, 4096, 1.5]) rejected(() => dnsFailure(query(), code));
});
test('truncation preserves upstream RA/RD/CD, not fabricated recursion capability', () => {
  const q = query(), r = fixtureDnsAnswer(q); r.writeUInt16BE(0x8010, 2);
  assert.equal(parseDns(truncateDnsResponse(q, r)).flags, 0x8210);
});
test('EDNS envelope rejects duplicate/wrong-section/nonroot OPT and broken option lengths', () => {
  const q = query(), opt = q.subarray(parseDns(q).questionEnd);
  const duplicate = Buffer.concat([q, opt]); duplicate.writeUInt16BE(2, 10);
  rejected(() => parseDnsQuery(duplicate));
  const wrongSection = Buffer.from(q); wrongSection.writeUInt16BE(1, 6); wrongSection.writeUInt16BE(0, 10);
  rejected(() => parseDns(wrongSection));
  const nonroot = Buffer.concat([q.subarray(0, q.length - 11), Buffer.from([1, 97]), opt]);
  rejected(() => parseDnsQuery(nonroot));
  for (const bytes of ['00', '000100', '0001000400']) rejected(() => parseDnsQuery(options(q, Buffer.from(bytes, 'hex'))));
});
test('query extended RCODE and unsolicited response OPT are rejected', () => {
  for (const ttl of [0x1000000, 0xff000000]) {
    const q = query(); q.writeUInt32BE(ttl, q.length - 6); rejected(() => parseDnsQuery(q));
  }
  rejected(() => validateDnsResponse(dnsFailure(query()), makeDnsQuery('_svc.Example.test', 65, 0xabcd)));
  const q = query(), r = dnsFailure(q); r.writeUInt32BE(0x10000, r.length - 6);
  rejected(() => validateDnsResponse(r, q));
});
test('new EDNS versions get a version-zero BADVERS envelope without copying options', () => {
  for (const version of [1, 2, 255]) {
    const q = options(query(), Buffer.from('fde8000200ff', 'hex'));
    const opt = parseDns(q).records[0]; q.writeUInt32BE(version * 65536 + 0x8000, opt.offset - 6);
    assert.equal(parseDnsQuery(q).edns.version, version);
    const r = validateDnsResponse(dnsFailure(q, 16), q);
    assert.equal(r.rcode, 16); assert.equal(r.edns.version, 0); assert.equal(r.edns.flags, 0x8000);
    assert.deepEqual(r.counts, [0, 0, 1]); assert.equal(r.records[0].length, 0);
  }
});
test('65535-byte DNS messages are accepted, UDP cap stays independent', () => {
  const q = query(16, 65535), r = sizedTxtAnswer(q, DNS_MAX_BYTES);
  assert.equal(validateDnsResponse(r, q).udpSize, DNS_UDP_MAX_BYTES);
  assert.equal(parseDnsQuery(paddedDnsQuery(q, DNS_MAX_BYTES)).type, 16);
  assert.ok(truncateDnsResponse(q, r).length <= 512);
  rejected(() => parseDns(Buffer.concat([r, Buffer.from([0])])));
});
for (const [headers, expected] of [
  [[], 0], [['Age', '0'], 0], [['aGe', ' 000250 '], 250],
  [['Age', '2147483647'], 2147483647], [['Age', '2147483648'], 2147483648],
  [['Age', '9'.repeat(400)], 2147483648],
]) test(`HTTP Age parses/saturates ${String(headers).slice(0, 60)}`, () => assert.equal(dnsHttpAge(headers), expected));
for (const headers of [
  ['Age', '-1'], ['Age', '+1'], ['Age', '1.5'], ['Age', '1e3'], ['Age', ''], ['Age', '1, 2'],
  ['Age', 'NaN'], ['Age', '0x10'], ['Age', '1', 'age', '1'], ['Age', '\u00a01'], ['Age', '\v1'],
]) test(`HTTP Age rejects ambiguous/malformed ${headers}`, () => assert.throws(() => dnsHttpAge(headers), { code: 'DNS_HTTP_AGE' }));
test('Age changes TTL headers only in all three sections; OPT/RDATA/AD stay intact', () => {
  const q = query(65280), r = fixtureDnsAnswer(q, { count: 3, ttl: 600 });
  r.writeUInt16BE(r.readUInt16BE(2) | 0x20, 2); r.writeUInt16BE(1, 6); r.writeUInt16BE(1, 8); r.writeUInt16BE(2, 10);
  const original = Buffer.from(r), parsed = parseDns(r);
  ageDnsResponse(r, 250);
  for (const rr of parsed.records) {
    assert.deepEqual(r.subarray(rr.offset, rr.offset + rr.length), original.subarray(rr.offset, rr.offset + rr.length));
    if (rr.type !== 41) original.writeUInt32BE(350, rr.offset - 6);
  }
  assert.deepEqual(r, original);
});
test('TTL age saturates at zero and high-bit TTL is zero even without Age', () => {
  for (const [ttl, age, expected] of [[30, 30, 0], [30, 100, 0], [0, 0, 0], [0x80000000, 0, 0], [0x7fffffff, 1, 0x7ffffffe]]) {
    const r = fixtureDnsAnswer(query(), { ttl }); ageDnsResponse(r, age);
    assert.equal(parseDns(r).records[0].ttl, expected);
  }
  for (const age of [-1, 1.5, Infinity]) rejected(() => ageDnsResponse(fixtureDnsAnswer(query()), age));
});
test('negative SOA uses min(TTL, MINIMUM) minus Age; SOA RDATA is not rewritten', () => {
  for (const rcode of [0, 3]) for (const [ttl, minimum, age, expected] of [[600, 60, 30, 30], [600, 60, 90, 0], [20, 60, 5, 15], [600, 0, 0, 0]]) {
    const r = negativeSoaAnswer(query(), { ttl, minimum, rcode }), original = Buffer.from(r);
    const rr = parseDns(r).records[0]; ageDnsResponse(r, age);
    original.writeUInt32BE(expected, rr.offset - 6); assert.deepEqual(r, original);
  }
  for (const rcode of [0, 3]) {
    const q = query(), r = negativeSoaAnswer(q, { rcode }), end = parseDns(q).questionEnd;
    const cname = Buffer.from('c00c00050001000002580002c00c', 'hex');
    const chained = Buffer.concat([r.subarray(0, end), cname, r.subarray(end)]); chained.writeUInt16BE(1, 6);
    ageDnsResponse(chained, 90);
    assert.equal(parseDns(chained).records[1].ttl, 0, 'CNAME Answer does not bypass SOA MINIMUM');
  }
});
test('malformed negative SOA fails instead of guessing MINIMUM from arbitrary RDATA', () => {
  for (const mutate of [(r, rr) => r.writeUInt16BE(0xffff, rr.offset), (r, rr) => { r[rr.offset] = 0; },
    (r, rr) => r.writeUInt16BE(0xc000 | rr.offset, rr.offset)]) {
    const r = negativeSoaAnswer(query()); mutate(r, parseDns(r).records[0]); rejected(() => ageDnsResponse(r, 10));
  }
});
test('upstream TC remains valid only with complete record framing; response matching stays strict', () => {
  const q = query(), r = fixtureDnsAnswer(q); r[2] |= 2;
  validateDnsResponse(r, q);
  rejected(() => validateDnsResponse(r.subarray(0, r.length - 1), q));
  for (const at of [0, 13, parseDns(q).questionEnd - 3, parseDns(q).questionEnd - 1]) {
    const copy = Buffer.from(r); copy[at] ^= 1; rejected(() => validateDnsResponse(copy, q));
  }
});
test('name, RR and message limits remain bounded', () => {
  rejected(() => makeDnsQuery(Array(4).fill('a'.repeat(63)).join('.'), 65));
  rejected(() => parseDns(Buffer.alloc(DNS_MAX_BYTES + 1)));
  const q = query(), r = fixtureDnsAnswer(q); r.writeUInt16BE(129, 6);
  rejected(() => validateDnsResponse(r, q));
  const loop = fixtureDnsAnswer(q); loop.writeUInt16BE(0xc000 | parseDns(q).questionEnd, parseDns(q).questionEnd);
  rejected(() => validateDnsResponse(loop, q));
});
