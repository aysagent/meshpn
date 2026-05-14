/**
 * JA3 по сырым байтам первого ClientHello (алгоритм Salesforce JA3, GREASE из RFC 8701).
 * В строку JA3 входят только типы расширений (числа), не содержимое ALPN/SNI и т.п.
 * @see https://github.com/salesforce/ja3
 */
import crypto from 'node:crypto';

/** @type {ReadonlySet<number>} */
const GREASE = new Set([
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
  0xcaca, 0xdada, 0xeaea, 0xfafa,
]);

/** Дефолт длины hex-превью входного TCP-буфера для --ja3-verbose */
export const JA3_HEX_PREVIEW_DEFAULT = 96;

/** Макс. буфер при сборке ClientHello из нескольких TLS records (защита от DOS). */
export const TLS_MUX_MAX_CLIENT_BUF = 512 * 1024;

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
 * Разбор полей ClientHello для JA3 и отладки.
 * @param {Buffer} body — тело ClientHello (RFC 8446), без handshake type/len
 * @returns {{
 *   legacyVersion: number,
 *   ciphers: number[],
 *   extTypes: number[],
 *   curves: number[],
 *   ecPointFormats: number[],
 *   ja3String: string,
 *   ja3Digest: string,
 * }}
 */
export function ja3ComponentsFromClientHelloBody(body) {
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
  /** @type {number[]} */
  const curves = [];
  /** @type {number[]} */
  const ecPointFormats = [];

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
      for (let i = 2; i < 2 + glen && i + 2 <= edata.length; i += 2) {
        const g = edata.readUInt16BE(i);
        if (!GREASE.has(g)) curves.push(g);
      }
    } else if (et === 0x000b && edata.length >= 1) {
      const flen = edata[0];
      for (let i = 1; i < 1 + flen && i < edata.length; i++) ecPointFormats.push(edata[i]);
    }
  }

  const ellipticCurve = curves.join('-');
  const ecPointFmt = ecPointFormats.join('-');

  const ja3String = [
    legacyVersion,
    ciphers.join('-'),
    extTypes.join('-'),
    ellipticCurve,
    ecPointFmt,
  ].join(',');

  return {
    legacyVersion,
    ciphers,
    extTypes,
    curves,
    ecPointFormats,
    ja3String,
    ja3Digest: crypto.createHash('md5').update(ja3String, 'utf8').digest('hex'),
  };
}

/**
 * @param {Buffer} body — тело ClientHello (RFC 8446)
 * @returns {{ ja3String: string, ja3Digest: string }}
 */
export function ja3FromClientHelloBody(body) {
  const c = ja3ComponentsFromClientHelloBody(body);
  return { ja3String: c.ja3String, ja3Digest: c.ja3Digest };
}

/**
 * @param {Buffer} tcpBuf
 */
export function ja3FromTcpBuf(tcpBuf) {
  const ch = extractFirstClientHelloBody(tcpBuf);
  if (!ch) return null;
  return ja3FromClientHelloBody(ch);
}

/**
 * Полный разбор для логов (--ja3-verbose).
 * @param {Buffer} tcpBuf — TCP payload от начала соединения
 * @param {{ hexPreviewLen?: number }} [opts]
 * @returns {{
 *   ja3Digest: string,
 *   ja3String: string,
 *   legacyVersion: number,
 *   ciphers: number[],
 *   extTypes: number[],
 *   curves: number[],
 *   ecPointFormats: number[],
 *   hexPreview: string,
 * } | null}
 */
export function ja3DebugFromTcpBuf(tcpBuf, opts = {}) {
  const ch = extractFirstClientHelloBody(tcpBuf);
  if (!ch) return null;
  const c = ja3ComponentsFromClientHelloBody(ch);
  const maxHex = opts.hexPreviewLen ?? JA3_HEX_PREVIEW_DEFAULT;
  const hexPreview = Buffer.from(tcpBuf.subarray(0, Math.min(maxHex, tcpBuf.length))).toString(
    'hex',
  );
  return {
    ja3Digest: c.ja3Digest,
    ja3String: c.ja3String,
    legacyVersion: c.legacyVersion,
    ciphers: c.ciphers,
    extTypes: c.extTypes,
    curves: c.curves,
    ecPointFormats: c.ecPointFormats,
    hexPreview,
  };
}

/**
 * SNI / ALPN / supported_versions (43) из тела ClientHello (как в Wireshark).
 * @param {Buffer} ch — тело ClientHello без handshake type/len
 * @returns {{ ok: true, sni: string[], alpn: string[], supportedVersions: number[] } | { ok: false, reason: string }}
 */
export function parseTlsClientHelloReadableExtensions(ch) {
  let o = 0;
  if (ch.length < 34) return { ok: false, reason: 'short_ch' };
  o += 34;
  const sidLen = ch[o];
  o += 1;
  if (ch.length < o + sidLen + 2) return { ok: false, reason: 'short_ch2' };
  o += sidLen;
  const csLen = ch.readUInt16BE(o);
  o += 2;
  if (ch.length < o + csLen + 1) return { ok: false, reason: 'short_ch3' };
  o += csLen;
  const compLen = ch[o];
  o += 1;
  if (ch.length < o + compLen + 2) return { ok: false, reason: 'short_ch4' };
  o += compLen;
  const extLen = ch.readUInt16BE(o);
  o += 2;
  if (ch.length < o + extLen) return { ok: false, reason: 'short_ext' };
  const extBlock = ch.subarray(o, o + extLen);
  /** @type {string[]} */
  const sni = [];
  /** @type {string[]} */
  const alpn = [];
  /** @type {number[]} */
  const supportedVersions = [];
  let eo = 0;
  while (eo + 4 <= extBlock.length) {
    const et = extBlock.readUInt16BE(eo);
    const el = extBlock.readUInt16BE(eo + 2);
    eo += 4;
    if (eo + el > extBlock.length) break;
    const ed = extBlock.subarray(eo, eo + el);
    if (et === 0 && ed.length >= 2) {
      let listLen = ed.readUInt16BE(0);
      let so = 2;
      while (so + 3 <= ed.length && listLen >= 3) {
        const nt = ed[so];
        const nl = ed.readUInt16BE(so + 1);
        so += 3;
        if (so + nl > ed.length) break;
        if (nt === 0) sni.push(ed.subarray(so, so + nl).toString('utf8'));
        so += nl;
        listLen -= 3 + nl;
      }
    } else if (et === 16 && ed.length >= 2) {
      let listLen = ed.readUInt16BE(0);
      let ao = 2;
      while (ao + 1 <= ed.length && listLen > 0) {
        const pl = ed[ao];
        ao += 1;
        if (ao + pl > ed.length) break;
        alpn.push(ed.subarray(ao, ao + pl).toString('utf8'));
        ao += pl;
        listLen -= 1 + pl;
      }
    } else if (et === 43 && ed.length >= 1) {
      const slen = ed[0];
      const end = Math.min(ed.length, 1 + slen);
      for (let pos = 1; pos + 1 < end; pos += 2) {
        supportedVersions.push(ed.readUInt16BE(pos));
      }
    }
    eo += el;
  }
  return { ok: true, sni, alpn, supportedVersions };
}

/**
 * Накопленный TCP от начала соединения до полного первого ClientHello (несколько TLS records).
 * @returns {{ needMore: true, minTotal: number } | { ok: false, reason: string } | { ok: true, sni: string[], alpn: string[], supportedVersions: number[], bytesConsumed: number }}
 */
export function parseFirstTlsClientHelloFromTcpBuf(buf) {
  if (buf.length > TLS_MUX_MAX_CLIENT_BUF) {
    return { ok: false, reason: 'buffer_max' };
  }
  if (buf.length < 5) return { needMore: true, minTotal: 5 };
  if (buf[0] !== 0x16) return { ok: false, reason: 'not_tls_handshake' };

  /** @type {Buffer[]} */
  const payloads = [];
  let offset = 0;
  for (;;) {
    if (buf.length - offset < 5) {
      return { needMore: true, minTotal: offset + 5 };
    }
    if (buf[offset] !== 0x16) {
      return offset === 0
        ? { ok: false, reason: 'not_tls_handshake' }
        : { ok: false, reason: 'non_handshake_record' };
    }
    const recLen = buf.readUInt16BE(offset + 3);
    const recordEnd = offset + 5 + recLen;
    if (recLen < 1 || recordEnd > TLS_MUX_MAX_CLIENT_BUF) {
      return { ok: false, reason: 'record_oversize' };
    }
    if (recordEnd > buf.length) {
      return { needMore: true, minTotal: recordEnd };
    }
    payloads.push(buf.subarray(offset + 5, recordEnd));
    offset = recordEnd;
    const combined = Buffer.concat(payloads);
    if (combined.length < 4) continue;
    if (combined[0] !== 1) return { ok: false, reason: 'not_client_hello' };
    const hsLen = combined.readUIntBE(1, 3);
    const totalHs = 4 + hsLen;
    if (combined.length < totalHs) continue;
    const ch = combined.subarray(4, totalHs);
    const ext = parseTlsClientHelloReadableExtensions(ch);
    if (!ext.ok) return ext;
    return {
      ok: true,
      sni: ext.sni,
      alpn: ext.alpn,
      supportedVersions: ext.supportedVersions,
      bytesConsumed: offset,
    };
  }
}

/**
 * Единый объект профиля TLS ClientHello + JA3 для снифферов и отладки (без HTTP).
 * @param {Buffer} tcpBuf
 * @param {{ hexPreviewLen?: number }} [opts]
 */
export function tlsClientHandshakeProfileFromTcpBuf(tcpBuf, opts = {}) {
  const parsed = parseFirstTlsClientHelloFromTcpBuf(tcpBuf);
  if ('needMore' in parsed && parsed.needMore) {
    return { ok: false, reason: 'incomplete_client_hello', minTotal: parsed.minTotal };
  }
  if (!parsed.ok) {
    return { ok: false, reason: parsed.reason };
  }
  const ja3d = ja3DebugFromTcpBuf(tcpBuf, opts);
  if (!ja3d) {
    return { ok: false, reason: 'ja3_extract_failed' };
  }
  /** @type {number | null} */
  let tlsRecordLegacyVersion = null;
  if (tcpBuf.length >= 3 && tcpBuf[0] === 0x16) {
    tlsRecordLegacyVersion = tcpBuf.readUInt16BE(1);
  }
  return {
    ok: true,
    tls: {
      tls_record_legacy_version: tlsRecordLegacyVersion,
      tls_record_legacy_hex:
        tlsRecordLegacyVersion != null ? `0x${tlsRecordLegacyVersion.toString(16)}` : null,
      clienthello_legacy_version: ja3d.legacyVersion,
      clienthello_legacy_hex: `0x${ja3d.legacyVersion.toString(16)}`,
      sni_hostnames: parsed.sni,
      offered_alpn_protocols: parsed.alpn,
      supported_versions_extension: parsed.supportedVersions,
    },
    ja3: {
      md5: ja3d.ja3Digest,
      string_before_md5: ja3d.ja3String,
      components: {
        legacy_version_decimal: ja3d.legacyVersion,
        cipher_suites_decimal_grease_filtered: ja3d.ciphers,
        extension_types_decimal_grease_filtered: ja3d.extTypes,
        supported_groups_decimal_grease_filtered: ja3d.curves,
        ec_point_formats_decimal: ja3d.ecPointFormats,
      },
      note:
        'salesforce JA3: в строку до MD5 входят только типы расширений (без имён ALPN/SNI). GREASE из типов/шифров убран.',
    },
    wire: {
      hex_preview_first_tcp_bytes: ja3d.hexPreview,
    },
  };
}
