/**
 * Unit tests: enc-SNI v2 (base62) + ClientHello rebuild.
 * node scripts/test-transparent-tls-enc-sni.mjs
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import { createHmac, randomBytes } from 'node:crypto';
import {
  base62Decode,
  base62Encode,
  buildRelayHostname,
  decodeRelayFromHostname,
  decodeRelaySniLabel,
  encodeRelaySniLabel,
  parseRelayEncLabels,
} from './lib/transparent-tls-enc-sni.mjs';
import {
  replaceFirstSniInTcpBuffer,
  restoreFirstSniInTcpBuffer,
} from './lib/transparent-tls-ch-rebuild.mjs';
import { parseFirstTlsClientHelloFromTcpBuf } from './lib/tls-clienthello-ja3.mjs';

const PSK = createHmac('sha256', Buffer.from('test-psk')).update('k').digest();
const PUBLIC = 'vpn.example.com';
const BASE62 =
  '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

function clientHelloBodyWithSni(hostname) {
  const hostB = Buffer.from(hostname, 'utf8');
  const sniPayload = Buffer.concat([
    Buffer.from([0x00, hostB.length + 3]),
    Buffer.from([0x00]),
    Buffer.from([0x00, hostB.length]),
    hostB,
  ]);
  const ext0 = Buffer.concat([
    Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, sniPayload.length]),
    sniPayload,
  ]);
  const ext43 = Buffer.from([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
  const extBlock = Buffer.concat([ext0, ext43]);
  const extLen = Buffer.alloc(2);
  extLen.writeUInt16BE(extBlock.length, 0);
  const legacy = Buffer.from([0x03, 0x03]);
  const random = Buffer.alloc(32, 0xab);
  const sid = Buffer.from([0]);
  const ciphers = Buffer.from([0x00, 0x02, 0x13, 0x01]);
  const comp = Buffer.from([1, 0]);
  return Buffer.concat([legacy, random, sid, ciphers, comp, extLen, extBlock]);
}

function clientHelloBodyWithSniAndEch(hostname) {
  const hostB = Buffer.from(hostname, 'utf8');
  const sniPayload = Buffer.concat([
    Buffer.from([0x00, hostB.length + 3]),
    Buffer.from([0x00]),
    Buffer.from([0x00, hostB.length]),
    hostB,
  ]);
  const ext0 = Buffer.concat([
    Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, sniPayload.length]),
    sniPayload,
  ]);
  // ECH (0xfe0d) как GREASE ECH: произвольная начинка, сервер игнорирует.
  const echPayload = Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
  const echLen = Buffer.alloc(2);
  echLen.writeUInt16BE(echPayload.length, 0);
  const extEch = Buffer.concat([Buffer.from([0xfe, 0x0d]), echLen, echPayload]);
  const ext43 = Buffer.from([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
  const extBlock = Buffer.concat([ext0, extEch, ext43]);
  const extLen = Buffer.alloc(2);
  extLen.writeUInt16BE(extBlock.length, 0);
  const legacy = Buffer.from([0x03, 0x03]);
  const random = Buffer.alloc(32, 0xab);
  const sid = Buffer.from([0]);
  const ciphers = Buffer.from([0x00, 0x02, 0x13, 0x01]);
  const comp = Buffer.from([1, 0]);
  return Buffer.concat([legacy, random, sid, ciphers, comp, extLen, extBlock]);
}

function tlsTcpFromClientHelloBody(chBody) {
  const inner = Buffer.alloc(4 + chBody.length);
  inner[0] = 1;
  inner.writeUIntBE(chBody.length, 1, 3);
  chBody.copy(inner, 4);
  const rec = Buffer.alloc(5 + inner.length);
  rec[0] = 0x16;
  rec.writeUInt16BE(0x0301, 1);
  rec.writeUInt16BE(inner.length, 3);
  inner.copy(rec, 5);
  return rec;
}

test('base62 roundtrip random buffers including leading zeros', () => {
  for (let t = 0; t < 32; t++) {
    const buf = randomBytes(1 + (t % 48));
    const enc = base62Encode(buf);
    assert.match(enc, /^[0-9a-zA-Z]*$/);
    const dec = base62Decode(enc);
    assert.deepEqual(dec, buf);
  }
});

test('base62 alphabet maps all 62 symbols', () => {
  for (let i = 0; i < 62; i++) {
    const enc = base62Encode(Buffer.from([i % 256]));
    assert.ok(enc.length >= 1);
    assert.ok(BASE62.includes(enc[enc.length - 1]));
  }
});

test('encode/decode roundtrip short hostname', () => {
  const labels = encodeRelaySniLabel(PSK, { hostname: 'example.com', port: 443 });
  assert.ok(labels.length >= 1);
  for (const l of labels) {
    assert.match(l, /^[0-9a-zA-Z]+$/);
  }
  const host = buildRelayHostname(labels, PUBLIC);
  assert.ok(host.endsWith(`.${PUBLIC}`));
  const dec = decodeRelayFromHostname(host, PUBLIC, PSK);
  assert.equal(dec.ok, true);
  assert.equal(dec.hostname, 'example.com');
  assert.equal(dec.port, 443);
});

test('example.com enc blob shorter than base32-era (~76 sym), v2 base62', () => {
  const labels = encodeRelaySniLabel(PSK, { hostname: 'example.com', port: 443 });
  const blobLen = labels.join('').length;
  assert.ok(blobLen < 76, `blob length ${blobLen} expected < 76 (base32 v1)`);
  assert.ok(labels.length <= 2, `labels=${labels.length}`);
});

test('parseRelayEncLabels preserves case in enc prefix', () => {
  const mixed = 'Ab9ZxY.vpn.example.com';
  const parsed = parseRelayEncLabels(mixed, PUBLIC);
  assert.deepEqual(parsed, ['Ab9ZxY']);
  const parsedLowerSuffix = parseRelayEncLabels('Ab9ZxY.VPN.EXAMPLE.COM', PUBLIC);
  assert.deepEqual(parsedLowerSuffix, ['Ab9ZxY']);
});

test('case-sensitive base62 survives parseRelayEncLabels roundtrip', () => {
  let labels = null;
  let host = null;
  for (let i = 0; i < 24; i++) {
    const lb = encodeRelaySniLabel(PSK, { hostname: `case-test-${i}.example.com`, port: 443 });
    const blob = lb.join('');
    if (!/[A-Z]/.test(blob)) continue;
    labels = lb;
    host = buildRelayHostname(lb, PUBLIC);
    break;
  }
  assert.ok(labels && host, 'need enc blob with uppercase base62 letter');
  const reparsed = parseRelayEncLabels(host, PUBLIC);
  assert.deepEqual(reparsed, labels);
  decodeRelaySniLabel(PSK, /** @type {string[]} */ (reparsed));
});

test('encode/decode long hostname via multi-label', () => {
  const longHost = `${'a'.repeat(80)}.example.org`;
  const labels = encodeRelaySniLabel(PSK, { hostname: longHost, port: 8443 });
  assert.ok(labels.some((l) => l.length <= 63));
  const host = buildRelayHostname(labels, PUBLIC);
  assert.ok(Buffer.byteLength(host, 'utf8') <= 253);
  const parsed = parseRelayEncLabels(host, PUBLIC);
  assert.ok(parsed && parsed.length >= 1);
  const plain = decodeRelaySniLabel(PSK, parsed);
  assert.equal(plain.hostname, longHost);
  assert.equal(plain.port, 8443);
});

test('replaceFirstSniInTcpBuffer: variable length rebuild', () => {
  const origin = 'short.example.com';
  const tcp = tlsTcpFromClientHelloBody(clientHelloBodyWithSni(origin));
  const labels = encodeRelaySniLabel(PSK, { hostname: origin, port: 443 });
  const relayHost = buildRelayHostname(labels, PUBLIC);

  const wr = replaceFirstSniInTcpBuffer(Buffer.from(tcp), relayHost);
  assert.equal(wr.ok, true);
  if (!wr.ok) return;

  const p = parseFirstTlsClientHelloFromTcpBuf(wr.prefixBuf);
  assert.equal('ok' in p && p.ok, true);
  assert.equal(p.sni?.[0], relayHost);

  const rr = restoreFirstSniInTcpBuffer(wr.prefixBuf, relayHost, origin);
  assert.equal(rr.ok, true);
  if (!rr.ok) return;
  const p2 = parseFirstTlsClientHelloFromTcpBuf(rr.prefixBuf);
  assert.equal('ok' in p2 && p2.ok, true);
  assert.equal(p2.sni?.[0], origin);
});

test('replaceFirstSniInTcpBuffer: longer relay SNI than origin', () => {
  const origin = 'x.co';
  const tcp = tlsTcpFromClientHelloBody(clientHelloBodyWithSni(origin));
  const relayHost = buildRelayHostname(
    encodeRelaySniLabel(PSK, { hostname: 'much-longer-origin-name.example.net', port: 443 }),
    PUBLIC,
  );
  const wr = replaceFirstSniInTcpBuffer(Buffer.from(tcp), relayHost);
  assert.equal(wr.ok, true);
  if (!wr.ok) return;
  assert.notEqual(wr.prefixBuf.length, tcp.length);
});

test('enc-SNI пропускает GREASE ECH (0xfe0d) и восстанавливает ClientHello байт-в-байт', () => {
  const origin = 'sync.browser.yandex.net';
  const tcp = tlsTcpFromClientHelloBody(clientHelloBodyWithSniAndEch(origin));
  const relayHost = buildRelayHostname(
    encodeRelaySniLabel(PSK, { hostname: origin, port: 443 }),
    PUBLIC,
  );

  const wr = replaceFirstSniInTcpBuffer(Buffer.from(tcp), relayHost);
  assert.equal(wr.ok, true, `rewrite не должен отклонять ECH: ${!wr.ok ? wr.reason : ''}`);
  if (!wr.ok) return;

  const pMid = parseFirstTlsClientHelloFromTcpBuf(wr.prefixBuf);
  assert.equal('ok' in pMid && pMid.ok, true);
  assert.equal(pMid.sni?.[0], relayHost);

  // Exit восстанавливает исходный ClientHello — должен совпасть с оригиналом браузера
  // байт-в-байт (SNI назад + ECH-расширение нетронуто).
  const rr = restoreFirstSniInTcpBuffer(wr.prefixBuf, relayHost, origin);
  assert.equal(rr.ok, true);
  if (!rr.ok) return;
  assert.deepEqual(rr.prefixBuf, tcp, 'restored ClientHello должен быть равен оригиналу (ECH не тронут)');
});

test('decodeRelayFromHostname rejects wrong public suffix', () => {
  const labels = encodeRelaySniLabel(PSK, { hostname: 'a.test', port: 443 });
  const host = buildRelayHostname(labels, PUBLIC);
  const bad = decodeRelayFromHostname(host, 'other.example.com', PSK);
  assert.equal(bad.ok, false);
});

console.log('test-transparent-tls-enc-sni: all assertions passed');
