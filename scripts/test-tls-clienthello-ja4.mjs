/**
 * Юнит-тесты JA4 (FoxIO). Запуск: node scripts/test-tls-clienthello-ja4.mjs
 */
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ja4AlpnFingerprintPair,
  ja4FromClientHelloBody,
  tlsClientHandshakeProfileWithJa4FromTcpBuf,
} from './lib/tls-clienthello-ja4.mjs';
import { TLS_GREASE_VALUES } from './lib/tls-clienthello-ja3.mjs';

test('JA4.md: усечённые SHA256 для JA4_b и JA4_c (примеры из спецификации)', () => {
  const cipherSorted =
    '002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9';
  const extAndSig =
    '0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601';
  assert.strictEqual(
    crypto.createHash('sha256').update(cipherSorted, 'utf8').digest('hex').slice(0, 12),
    '8daaf6152771',
  );
  assert.strictEqual(
    crypto.createHash('sha256').update(extAndSig, 'utf8').digest('hex').slice(0, 12),
    'e5627efa2ab1',
  );
});

test('ja4AlpnFingerprintPair: h2, http/1.1, пусто, hex fallback', () => {
  assert.strictEqual(ja4AlpnFingerprintPair('h2'), 'h2');
  assert.strictEqual(ja4AlpnFingerprintPair('http/1.1'), 'h1');
  assert.strictEqual(ja4AlpnFingerprintPair(''), '00');
  assert.strictEqual(ja4AlpnFingerprintPair(undefined), '00');
  assert.strictEqual(ja4AlpnFingerprintPair('x'), 'xx');
});

/** Минимальный ClientHello: TLS 1.3 через supported_versions, один cipher, без SNI/ALPN */
function minimalTls13ClientHelloBody() {
  const legacy = Buffer.from([0x03, 0x03]);
  const random = Buffer.alloc(32, 0);
  const sid = Buffer.from([0]);
  const ciphers = Buffer.from([0x00, 0x02, 0x13, 0x01]);
  const comp = Buffer.from([1, 0]);
  const ext43 = Buffer.from([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
  const extLen = Buffer.alloc(2);
  extLen.writeUInt16BE(ext43.length, 0);
  return Buffer.concat([legacy, random, sid, ciphers, comp, extLen, ext43]);
}

test('ja4FromClientHelloBody: минимальный TLS 1.3 hello', () => {
  const j = ja4FromClientHelloBody(minimalTls13ClientHelloBody());
  assert.strictEqual(j.ja4_a, 't13i010100');
  assert.strictEqual(j.ja4_b, '0f2cb44170f4');
  assert.strictEqual(j.ja4_c, 'b9a491fefe05');
  assert.strictEqual(j.fingerprint, 't13i010100_0f2cb44170f4_b9a491fefe05');
  assert.strictEqual(j.fingerprint_alt_sni_alpn_in_j4c, j.fingerprint);
  assert.strictEqual(j.ja4_c_alt_sni_alpn_in_hash, j.ja4_c);
  assert.strictEqual(j.raw_r, 't13i010100_1301_002b');
  assert.strictEqual(j.raw_o, 't13i010100_1301_002b');
  assert.strictEqual(j.raw_r_alt_sni_alpn_in_segment, j.raw_r);
});

/** ClientHello с SNI + ALPN + supported_versions — JA4.md исключает 0000/0010 из JA4_c; alt включает их в хеш JA4_c */
function clientHelloBodyWithSniAlpnSupportedVersions() {
  const legacy = Buffer.from([0x03, 0x03]);
  const random = Buffer.alloc(32, 0);
  const sid = Buffer.from([0]);
  const ciphers = Buffer.from([0x00, 0x02, 0x13, 0x01]);
  const comp = Buffer.from([1, 0]);
  const sniPayload = Buffer.concat([
    Buffer.from([0x00, 0x06]),
    Buffer.from([0x00]),
    Buffer.from([0x00, 0x03]),
    Buffer.from('abc'),
  ]);
  const ext0 = Buffer.concat([
    Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, sniPayload.length]),
    sniPayload,
  ]);
  const alpnPayload = Buffer.from([0x00, 0x03, 0x02, 0x68, 0x32]);
  const ext16 = Buffer.concat([
    Buffer.from([0x00, 0x10]),
    Buffer.from([0x00, alpnPayload.length]),
    alpnPayload,
  ]);
  const ext43 = Buffer.from([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
  const extBlock = Buffer.concat([ext0, ext16, ext43]);
  const extLen = Buffer.alloc(2);
  extLen.writeUInt16BE(extBlock.length, 0);
  return Buffer.concat([legacy, random, sid, ciphers, comp, extLen, extBlock]);
}

test('ja4FromClientHelloBody: fingerprint_alt при наличии SNI и ALPN на wire', () => {
  const j = ja4FromClientHelloBody(clientHelloBodyWithSniAlpnSupportedVersions());
  assert.strictEqual(j.ja4_a, 't13d0103h2');
  assert.strictEqual(j.fingerprint, 't13d0103h2_0f2cb44170f4_b9a491fefe05');
  assert.strictEqual(j.fingerprint_alt_sni_alpn_in_j4c, 't13d0103h2_0f2cb44170f4_76ae7f21e19f');
  assert.notStrictEqual(j.ja4_c, j.ja4_c_alt_sni_alpn_in_hash);
  assert.strictEqual(j.raw_r_alt_sni_alpn_in_segment.split('_')[2]?.startsWith('0000'), true);
});

test('GREASE cipher не входит в счётчик JA4_a и в JA4_b', () => {
  const legacy = Buffer.from([0x03, 0x03]);
  const random = Buffer.alloc(32, 0);
  const sid = Buffer.from([0]);
  const greaseCipher = [...TLS_GREASE_VALUES][0];
  const ciphers = Buffer.alloc(2 + 2 + 2);
  ciphers.writeUInt16BE(2 + 2, 0);
  ciphers.writeUInt16BE(greaseCipher, 2);
  ciphers.writeUInt16BE(0x1301, 4);
  const comp = Buffer.from([1, 0]);
  const ext43 = Buffer.from([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
  const extLen = Buffer.alloc(2);
  extLen.writeUInt16BE(ext43.length, 0);
  const body = Buffer.concat([legacy, random, sid, ciphers, comp, extLen, ext43]);
  const j = ja4FromClientHelloBody(body);
  assert.strictEqual(j.ja4_a.slice(4, 8), '0101');
});

function tlsRecordsFromHandshakePlaintexts(tlsPlainChunks) {
  /** @type {Buffer[]} */
  const parts = [];
  for (const chunk of tlsPlainChunks) {
    const rec = Buffer.alloc(5 + chunk.length);
    rec[0] = 0x16;
    rec.writeUInt16BE(0x0301, 1);
    rec.writeUInt16BE(chunk.length, 3);
    chunk.copy(rec, 5);
    parts.push(rec);
  }
  return Buffer.concat(parts);
}

test('tlsClientHandshakeProfileWithJa4FromTcpBuf: JA4 при валидном TCP с одним record', () => {
  const chBody = minimalTls13ClientHelloBody();
  const inner = Buffer.alloc(4 + chBody.length);
  inner[0] = 1;
  inner.writeUIntBE(chBody.length, 1, 3);
  chBody.copy(inner, 4);
  const tlsPlain = inner;
  const rec = Buffer.alloc(5 + tlsPlain.length);
  rec[0] = 0x16;
  rec.writeUInt16BE(0x0301, 1);
  rec.writeUInt16BE(tlsPlain.length, 3);
  tlsPlain.copy(rec, 5);
  const p = tlsClientHandshakeProfileWithJa4FromTcpBuf(rec, {});
  assert.strictEqual(p.ok, true);
  assert.ok(p.ja4 && 'fingerprint' in p.ja4 && typeof p.ja4.fingerprint === 'string');
  assert.match(
    p.ja4.fingerprint,
    /^t.{9}_[a-f0-9]{12}_[a-f0-9]{12}$/,
  );
  assert.ok(p.ja4.raw_r && p.ja4.raw_o);
  assert.strictEqual(
    p.ja4.raw_r,
    `${p.ja4.ja4_a}_1301_002b`,
    'JA4_r: без sig — только sorted cipher и ext (без 0000/0010)',
  );
  assert.strictEqual(p.ja4.raw_o, `${p.ja4.ja4_a}_1301_002b`);
});

test('JA4 тот же при ClientHello, разбитом на два TLS record (mux)', () => {
  const chBody = minimalTls13ClientHelloBody();
  const innerFull = Buffer.alloc(4 + chBody.length);
  innerFull[0] = 1;
  innerFull.writeUIntBE(chBody.length, 1, 3);
  chBody.copy(innerFull, 4);
  const cut = 12;
  const frag1 = innerFull.subarray(0, cut);
  const frag2 = innerFull.subarray(cut);
  const splitTcp = tlsRecordsFromHandshakePlaintexts([frag1, frag2]);
  const singleTcp = tlsRecordsFromHandshakePlaintexts([innerFull]);
  const pSplit = tlsClientHandshakeProfileWithJa4FromTcpBuf(splitTcp, {});
  const pOne = tlsClientHandshakeProfileWithJa4FromTcpBuf(singleTcp, {});
  assert.strictEqual(pSplit.ok, true);
  assert.strictEqual(pOne.ok, true);
  assert.strictEqual(pSplit.ja4.fingerprint, pOne.ja4.fingerprint);
  assert.strictEqual(pSplit.ja4.raw_r, pOne.ja4.raw_r);
  assert.strictEqual(pSplit.ja4.raw_o, pOne.ja4.raw_o);
  assert.strictEqual(
    pSplit.ja4.raw_r_alt_sni_alpn_in_segment,
    pOne.ja4.raw_r_alt_sni_alpn_in_segment,
  );
});

test('JA4.md Raw: JA4_r для типового Chrome-подобного набора (совпадает с примером в спецификации)', () => {
  const expectedR =
    't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601';
  const cipherSorted =
    '002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9';
  const extSortedNoSniAlpn =
    '0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01';
  const sigWire = '0403,0804,0401,0503,0805,0501,0806,0601';
  assert.strictEqual(
    `t13d1516h2_${cipherSorted}_${extSortedNoSniAlpn}_${sigWire}`,
    expectedR,
  );
});
