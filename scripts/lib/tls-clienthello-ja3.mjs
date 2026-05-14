/**
 * JA3 по сырым байтам первого ClientHello (алгоритм Salesforce JA3, GREASE из RFC 8701).
 * @see https://github.com/salesforce/ja3
 */
import crypto from 'node:crypto';

/** @type {ReadonlySet<number>} */
const GREASE = new Set([
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
  0xcaca, 0xdada, 0xeaea, 0xfafa,
]);

/** @param {Buffer} buf @param {number} o */
function u24(buf, o) {
  return (buf[o] << 16) | (buf[o + 1] << 8) | buf[o + 2];
}

/**
 * Из буфера TCP (накопленного с начала соединения) вытаскивает тело ClientHello
 * (после legacy_version … до конца расширений).
 * @param {Buffer} buf
 * @returns {Buffer | null}
 */
export function extractFirstClientHelloBody(buf) {
  let off = 0;
  while (off + 5 <= buf.length) {
    const typ = buf[off];
    const reclen = buf.readUInt16BE(off + 3);
    if (off + 5 + reclen > buf.length) return null;
    const inner = buf.subarray(off + 5, off + 5 + reclen);
    off += 5 + reclen;
    if (typ !== 22 || inner.length < 4 || inner[0] !== 1) continue;
    const hsLen = u24(inner, 1);
    if (inner.length < 4 + hsLen) return null;
    return inner.subarray(4, 4 + hsLen);
  }
  return null;
}

/**
 * @param {Buffer} body — тело ClientHello (RFC 8446)
 * @returns {{ ja3String: string, ja3Digest: string }}
 */
export function ja3FromClientHelloBody(body) {
  let o = 0;
  const legacyVersion = body.readUInt16BE(o);
  o += 2 + 32;
  const sidLen = body[o];
  o += 1 + sidLen;
  const cipherLen = body.readUInt16BE(o);
  o += 2;
  const cipherEnd = o + cipherLen;
  /** @type {number[]} */
  const ciphers = [];
  while (o < cipherEnd) {
    const cs = body.readUInt16BE(o);
    o += 2;
    if (!GREASE.has(cs)) ciphers.push(cs);
  }
  const compLen = body[o];
  o += 1 + compLen;
  if (o + 2 > body.length) {
    throw new Error('ja3: нет блока расширений');
  }
  const extTotal = body.readUInt16BE(o);
  o += 2;
  const extEnd = o + extTotal;

  /** @type {number[]} */
  const extTypes = [];
  let ellipticCurve = '';
  let ecPointFmt = '';

  while (o + 4 <= extEnd && o + 4 <= body.length) {
    const et = body.readUInt16BE(o);
    const elen = body.readUInt16BE(o + 2);
    o += 4;
    if (o + elen > body.length || o + elen > extEnd) {
      throw new Error('ja3: обрезанное расширение');
    }
    const edata = body.subarray(o, o + elen);
    o += elen;
    if (GREASE.has(et)) continue;
    extTypes.push(et);
    if (et === 0x000a && edata.length >= 2) {
      const glen = edata.readUInt16BE(0);
      /** @type {number[]} */
      const gs = [];
      for (let i = 2; i < 2 + glen && i + 2 <= edata.length; i += 2) {
        const g = edata.readUInt16BE(i);
        if (!GREASE.has(g)) gs.push(g);
      }
      ellipticCurve = gs.join('-');
    } else if (et === 0x000b && edata.length >= 1) {
      const flen = edata[0];
      /** @type {number[]} */
      const fs = [];
      for (let i = 1; i < 1 + flen && i < edata.length; i++) fs.push(edata[i]);
      ecPointFmt = fs.join('-');
    }
  }

  const ja3String = [
    legacyVersion,
    ciphers.join('-'),
    extTypes.join('-'),
    ellipticCurve,
    ecPointFmt,
  ].join(',');

  return {
    ja3String,
    ja3Digest: crypto.createHash('md5').update(ja3String, 'utf8').digest('hex'),
  };
}

/**
 * @param {Buffer} tcpBuf
 */
export function ja3FromTcpBuf(tcpBuf) {
  const ch = extractFirstClientHelloBody(tcpBuf);
  if (!ch) return null;
  return ja3FromClientHelloBody(ch);
}
