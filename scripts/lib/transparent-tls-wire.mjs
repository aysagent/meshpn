/** Фреймы transparent-tls поверх простого TCP (без второго TLS). Версия 1. */

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';

export const TTL_FRAME_MAGIC_PREFIX = Buffer.from('CVPTX1\r\n', 'ascii');
export const OP_OPEN = 0x01;
export const OP_DATA = 0x02;

const TTL_MAX_FIRST_INNER = 4096;
const OPEN_CTX = Buffer.from('transparent-tls-open-v1\0');

/**
 * @param {{ address: string, port: number }} dst
 */
export function encodeOpenFrame(secretBuf, nonce16, dst, originHostAscii, fakeHostAscii) {
  const o = Buffer.from(originHostAscii, 'utf8');
  const f = Buffer.from(fakeHostAscii, 'utf8');
  if (o.length !== f.length || o.length < 1 || o.length > 253) {
    throw new Error('transparent-tls OPEN: имена — одной UTF-8 длины 1..253');
  }
  const ipv4Parts = dst.address.trim().split('.');
  if (ipv4Parts.length !== 4) throw new Error('transparent-tls OPEN: ожидался IPv4');
  /** @type {number[]} */
  const octets = ipv4Parts.map((p) => {
    const n = parseInt(p, 10);
    if (!Number.isInteger(n) || n < 0 || n > 255) {
      throw new Error('transparent-tls OPEN: некорректный IPv4');
    }
    return n;
  });
  const port = dst.port;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error('transparent-tls OPEN: некорректный порт');
  }
  const ipBuf = Buffer.from(octets);
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(port, 0);
  const hl = Buffer.alloc(2);
  hl.writeUInt16BE(o.length, 0);
  const beforeMac = Buffer.concat([nonce16, ipBuf, portBuf, hl, o, f]);
  const mac = createHmac('sha256', secretBuf).update(Buffer.concat([OPEN_CTX, beforeMac])).digest();
  const innerPayload = Buffer.concat([Buffer.from([OP_OPEN]), beforeMac, mac]);
  const out = Buffer.allocUnsafe(TTL_FRAME_MAGIC_PREFIX.length + 4 + innerPayload.length);
  TTL_FRAME_MAGIC_PREFIX.copy(out, 0);
  out.writeUInt32BE(innerPayload.length, TTL_FRAME_MAGIC_PREFIX.length);
  innerPayload.copy(out, TTL_FRAME_MAGIC_PREFIX.length + 4);
  return out;
}

/** @param {Buffer} innerBlob — [OP_OPEN|payload|MAC] */
export function decodeVerifyOpen(secretBuf, innerBlob) {
  if (innerBlob.length < 25) throw new Error('transparent-tls OPEN: кадр слишком короткий');
  if (innerBlob[0] !== OP_OPEN) throw new Error('transparent-tls: ожидался OP_OPEN');
  let q = 1;
  const nonce = innerBlob.subarray(q, q + 16);
  q += 16;
  const ipv4Oct = innerBlob.subarray(q, q + 4);
  q += 4;
  const ipv4Host = [...ipv4Oct].join('.');
  const port = innerBlob.readUInt16BE(q);
  q += 2;
  const hnLen = innerBlob.readUInt16BE(q);
  q += 2;
  if (hnLen < 1 || hnLen > 253) throw new Error('transparent-tls OPEN: hnLen');
  if (innerBlob.length !== q + hnLen + hnLen + 32) throw new Error('transparent-tls OPEN: bad length');
  const orig = innerBlob.subarray(q, q + hnLen).toString('utf8');
  q += hnLen;
  const fake = innerBlob.subarray(q, q + hnLen).toString('utf8');
  q += hnLen;
  const macProvided = innerBlob.subarray(q, q + 32);

  const beforeMac = innerBlob.subarray(1, innerBlob.length - 32);
  const macExp = createHmac('sha256', secretBuf).update(Buffer.concat([OPEN_CTX, beforeMac])).digest();

  if (macExp.length !== macProvided.length || !timingSafeEqual(macExp, macProvided)) {
    throw new Error('transparent-tls OPEN: HMAC mismatch');
  }
  return { nonce, ipv4Host, port, originHostAscii: orig, fakeHostAscii: fake };
}

export function encodeDataFrame(chunk) {
  const innerPayload = Buffer.concat([Buffer.from([OP_DATA]), chunk]);
  const out = Buffer.allocUnsafe(TTL_FRAME_MAGIC_PREFIX.length + 4 + innerPayload.length);
  TTL_FRAME_MAGIC_PREFIX.copy(out, 0);
  out.writeUInt32BE(innerPayload.length, TTL_FRAME_MAGIC_PREFIX.length);
  innerPayload.copy(out, TTL_FRAME_MAGIC_PREFIX.length + 4);
  return out;
}

export class TransparentTlsStreamDecoder {
  /**
   * @param {{ maxInnerData?: number }} [opts]
   */
  constructor(opts = {}) {
    this.buf = Buffer.alloc(0);
    this.maxInnerData = opts.maxInnerData ?? 512 * 1024;
    this.gotOpen = false;
  }

  /** @returns {Buffer[]}
   */
  push(chunk) {
    /** @type {Buffer[]} */
    const out = [];
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;

    for (;;) {
      if (this.buf.length < TTL_FRAME_MAGIC_PREFIX.length + 4) return out;

      const head = this.buf.subarray(0, TTL_FRAME_MAGIC_PREFIX.length);
      if (head.compare(TTL_FRAME_MAGIC_PREFIX) !== 0) {
        throw new Error('transparent-tls wire: неверный magic кадра');
      }
      const innerLen = this.buf.readUInt32BE(TTL_FRAME_MAGIC_PREFIX.length);
      const maxAllowed = !this.gotOpen ? TTL_MAX_FIRST_INNER : 1 + this.maxInnerData;
      if (innerLen < 2 || innerLen > maxAllowed) {
        throw new Error(`transparent-tls wire: innerLen=${innerLen} недопустим`);
      }

      const total = TTL_FRAME_MAGIC_PREFIX.length + 4 + innerLen;
      if (this.buf.length < total) return out;

      const inner = this.buf.subarray(TTL_FRAME_MAGIC_PREFIX.length + 4, total);
      this.buf = this.buf.subarray(total);

      if (!this.gotOpen) {
        if (inner[0] !== OP_OPEN) throw new Error('transparent-tls wire: первый кадр не OPEN');
        this.gotOpen = true;
      } else if (inner[0] !== OP_DATA) {
        throw new Error(`transparent-tls wire: неизвестный op=${inner[0]}`);
      }
      out.push(inner);
    }
  }
}

export function randomNonce16() {
  return randomBytes(16);
}
