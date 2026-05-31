/**
 * Unit tests: enc-SNI label + ClientHello rebuild (variable-length SNI).
 * node scripts/test-transparent-tls-enc-sni.mjs
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import { createHmac } from 'node:crypto';
import {
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

test('encode/decode roundtrip short hostname', () => {
  const labels = encodeRelaySniLabel(PSK, { hostname: 'example.com', port: 443 });
  assert.ok(labels.length >= 1);
  const host = buildRelayHostname(labels, PUBLIC);
  assert.ok(host.endsWith(`.${PUBLIC}`));
  const dec = decodeRelayFromHostname(host, PUBLIC, PSK);
  assert.equal(dec.ok, true);
  assert.equal(dec.hostname, 'example.com');
  assert.equal(dec.port, 443);
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

test('decodeRelayFromHostname rejects wrong public suffix', () => {
  const labels = encodeRelaySniLabel(PSK, { hostname: 'a.test', port: 443 });
  const host = buildRelayHostname(labels, PUBLIC);
  const bad = decodeRelayFromHostname(host, 'other.example.com', PSK);
  assert.equal(bad.ok, false);
});

console.log('test-transparent-tls-enc-sni: all assertions passed');
