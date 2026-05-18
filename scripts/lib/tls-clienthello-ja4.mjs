/**
 * JA4 TLS Client fingerprint (FoxIO).
 * @see https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
 */
import crypto from 'node:crypto';
import {
  TLS_GREASE_VALUES,
  extractFirstClientHelloBody,
  parseFirstTlsClientHelloFromTcpBuf,
  tlsClientHandshakeProfileFromSuccessfulParse,
} from './tls-clienthello-ja3.mjs';

/** @param {number} n */
function hex4(n) {
  return n.toString(16).padStart(4, '0');
}

/** @param {number} n */
function count99(n) {
  const c = Math.min(Math.max(0, n), 99);
  return c < 10 ? `0${c}` : String(c);
}

/** @param {number} v TLS legacy / negotiated version uint16 */
function ja4VersionTwoChars(v) {
  switch (v) {
    case 0x0304:
      return '13';
    case 0x0303:
      return '12';
    case 0x0302:
      return '11';
    case 0x0301:
      return '10';
    case 0x0300:
      return 's3';
    case 0x0002:
      return 's2';
    case 0xfeff:
      return 'd1';
    case 0xfefd:
      return 'd2';
    case 0xfefc:
      return 'd3';
    default:
      return '00';
  }
}

/**
 * @param {number[]} supportedVersions from ext 43 (may include GREASE)
 * @param {number} legacyVersion first 2 bytes ClientHello
 */
function ja4ResolvedTlsVersion(supportedVersions, legacyVersion) {
  const clean = supportedVersions.filter((x) => !TLS_GREASE_VALUES.has(x));
  if (clean.length > 0) {
    return ja4VersionTwoChars(Math.max(...clean));
  }
  return ja4VersionTwoChars(legacyVersion);
}

/** @param {number} b */
function isAsciiAlnumByte(b) {
  return (
    (b >= 0x30 && b <= 0x39) ||
    (b >= 0x41 && b <= 0x5a) ||
    (b >= 0x61 && b <= 0x7a)
  );
}

/**
 * Два символа JA4_a из байтов первого протокола ALPN (как на wire).
 * @param {Buffer | null | undefined} proto
 */
export function ja4AlpnFingerprintPairFromBytes(proto) {
  if (proto == null || proto.length === 0) return '00';
  const fb = proto[0];
  const lb = proto[proto.length - 1];
  if (isAsciiAlnumByte(fb) && isAsciiAlnumByte(lb)) {
    return String.fromCharCode(fb) + String.fromCharCode(lb);
  }
  let hex = '';
  for (let i = 0; i < proto.length; i++) {
    hex += proto[i].toString(16).padStart(2, '0');
  }
  return hex[0] + hex[hex.length - 1];
}

/**
 * Два символа JA4_a из UTF-8 строки протокола (совместимость с текстовым ALPN).
 * @param {string|null|undefined} firstProto
 */
export function ja4AlpnFingerprintPair(firstProto) {
  if (firstProto == null || firstProto === '') return '00';
  return ja4AlpnFingerprintPairFromBytes(Buffer.from(firstProto, 'utf8'));
}

/** @param {string} s */
function sha256Trunc12(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 12);
}

/**
 * @param {Buffer} body — тело ClientHello (RFC 8446), без handshake type/len
 * @returns {{
 *   fingerprint: string,
 *   fingerprint_alt_sni_alpn_in_j4c: string,
 *   ja4_a: string,
 *   ja4_b: string,
 *   ja4_c: string,
 *   ja4_c_alt_sni_alpn_in_hash: string,
 *   raw_r: string,
 *   raw_r_alt_sni_alpn_in_segment: string,
 *   raw_o: string,
 * }}
 */
export function ja4FromClientHelloBody(body) {
  const grease = TLS_GREASE_VALUES;
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
    if (!grease.has(cs)) ciphers.push(cs);
  }
  const compLen = body[o];
  o += 1 + compLen;
  if (o + 2 > body.length) {
    throw new Error('ja4: нет блока расширений');
  }
  const extTotal = body.readUInt16BE(o);
  o += 2;
  const extEnd = o + extTotal;

  let hasSniExtension = false;
  /** @type {Buffer | null} */
  let firstAlpnBytes = null;
  /** @type {number[]} */
  const supportedVersions = [];
  /** @type {number[]} */
  const signatureAlgorithms = [];
  /** @type {number[]} */
  const extTypes = [];

  while (o + 4 <= extEnd && o + 4 <= body.length) {
    const et = body.readUInt16BE(o);
    const elen = body.readUInt16BE(o + 2);
    o += 4;
    if (o + elen > body.length || o + elen > extEnd) {
      throw new Error('ja4: обрезанное расширение');
    }
    const edata = body.subarray(o, o + elen);
    o += elen;
    if (grease.has(et)) continue;
    extTypes.push(et);
    if (et === 0) {
      hasSniExtension = true;
    } else if (et === 16 && edata.length >= 2) {
      let listLen = edata.readUInt16BE(0);
      let ao = 2;
      while (ao + 1 <= edata.length && listLen > 0) {
        const pl = edata[ao];
        ao += 1;
        if (ao + pl > edata.length) break;
        if (firstAlpnBytes === null) {
          firstAlpnBytes = Buffer.from(edata.subarray(ao, ao + pl));
        }
        ao += pl;
        listLen -= 1 + pl;
      }
    } else if (et === 43 && edata.length >= 1) {
      const slen = edata[0];
      const end = Math.min(edata.length, 1 + slen);
      for (let pos = 1; pos + 1 < end; pos += 2) {
        supportedVersions.push(edata.readUInt16BE(pos));
      }
    } else if (et === 13 && edata.length >= 2) {
      const algLen = edata.readUInt16BE(0);
      for (let i = 2; i < 2 + algLen && i + 2 <= edata.length; i += 2) {
        const sid = edata.readUInt16BE(i);
        if (!grease.has(sid)) signatureAlgorithms.push(sid);
      }
    } else if (et === 50 && edata.length >= 2) {
      // signature_algorithms_cert — та же форма списка uint16, что у расширения 13 (RFC 8446).
      const algLen = edata.readUInt16BE(0);
      for (let i = 2; i < 2 + algLen && i + 2 <= edata.length; i += 2) {
        const sid = edata.readUInt16BE(i);
        if (!grease.has(sid)) signatureAlgorithms.push(sid);
      }
    }
  }

  if (o !== extEnd) {
    throw new Error(
      'ja4: длина блока расширений не сходится с разбором (возможен обрезанный ClientHello или ошибка разбора)',
    );
  }

  const ver = ja4ResolvedTlsVersion(supportedVersions, legacyVersion);
  const sniMark = hasSniExtension ? 'd' : 'i';
  const alpnPair = ja4AlpnFingerprintPairFromBytes(firstAlpnBytes);

  const ja4_a = `t${ver}${sniMark}${count99(ciphers.length)}${count99(extTypes.length)}${alpnPair}`;

  /** JA4_b */
  let ja4_b;
  const sortedCipherHex = ciphers.length
    ? [...ciphers].map(hex4).sort().join(',')
    : '';
  if (ciphers.length === 0) {
    ja4_b = '000000000000';
  } else {
    ja4_b = sha256Trunc12(sortedCipherHex);
  }

  /** JA4_c (FoxIO JA4.md): типы расширений без SNI 0000 и ALPN 0010, sorted */
  const extForC = extTypes
    .filter((t) => t !== 0 && t !== 16)
    .map(hex4)
    .sort();
  let ja4_c;
  if (extForC.length === 0) {
    ja4_c = '000000000000';
  } else {
    const extPart = extForC.join(',');
    const sigPart = signatureAlgorithms.map(hex4).join(',');
    const payload =
      signatureAlgorithms.length > 0 ? `${extPart}_${sigPart}` : extPart;
    ja4_c = sha256Trunc12(payload);
  }

  /** Не JA4.md: JA4_c от всех типов расширений (кроме GREASE на уровне типа), sorted — часть сайтов/калькуляторов так включает 0000/0010 в хеш */
  const extForAltC = extTypes.map(hex4).sort();
  let ja4_c_alt_sni_alpn_in_hash;
  if (extForAltC.length === 0) {
    ja4_c_alt_sni_alpn_in_hash = '000000000000';
  } else {
    const extPartAlt = extForAltC.join(',');
    const sigPart = signatureAlgorithms.map(hex4).join(',');
    const payloadAlt =
      signatureAlgorithms.length > 0 ? `${extPartAlt}_${sigPart}` : extPartAlt;
    ja4_c_alt_sni_alpn_in_hash = sha256Trunc12(payloadAlt);
  }
  const fingerprint_alt_sni_alpn_in_j4c = `${ja4_a}_${ja4_b}_${ja4_c_alt_sni_alpn_in_hash}`;

  const cipherWireStr = ciphers.map(hex4).join(',');
  const extWireStr = extTypes.map(hex4).join(',');
  const sigWireStr = signatureAlgorithms.map(hex4).join(',');

  /** JA4_r (FoxIO -r): sorted ciphers _ sorted extensions без SNI/ALPN (как JA4_c) _ sig по порядку на wire */
  let raw_r = `${ja4_a}_${sortedCipherHex || ''}_${extForC.join(',')}`;
  if (signatureAlgorithms.length > 0) {
    raw_r += `_${sigWireStr}`;
  }

  /** «Raw»-строка в стиле калькуляторов с SNI/ALPN в среднем сегменте (не JA4.md JA4_r) */
  let raw_r_alt_sni_alpn_in_segment = `${ja4_a}_${sortedCipherHex || ''}_${extForAltC.join(',')}`;
  if (signatureAlgorithms.length > 0) {
    raw_r_alt_sni_alpn_in_segment += `_${sigWireStr}`;
  }

  /** JA4_ro: порядок на wire; SNI/ALPN включены */
  let raw_o = `${ja4_a}_${cipherWireStr}_${extWireStr}`;
  if (signatureAlgorithms.length > 0) {
    raw_o += `_${sigWireStr}`;
  }

  return {
    fingerprint: `${ja4_a}_${ja4_b}_${ja4_c}`,
    fingerprint_alt_sni_alpn_in_j4c,
    ja4_a,
    ja4_b,
    ja4_c,
    ja4_c_alt_sni_alpn_in_hash,
    raw_r,
    raw_r_alt_sni_alpn_in_segment,
    raw_o,
  };
}

/**
 * @param {Buffer} tcpBuf
 */
export function ja4FromTcpBuf(tcpBuf) {
  const ch = extractFirstClientHelloBody(tcpBuf);
  if (!ch) return null;
  return ja4FromClientHelloBody(ch);
}

/**
 * Профиль handshake как {@link tlsClientHandshakeProfileFromTcpBuf} плюс JA4.
 * @param {Buffer} tcpBuf
 * @param {{ hexPreviewLen?: number }} [opts]
 */
export function tlsClientHandshakeProfileWithJa4FromTcpBuf(tcpBuf, opts = {}) {
  const parsed = parseFirstTlsClientHelloFromTcpBuf(tcpBuf);
  if ('needMore' in parsed && parsed.needMore) {
    return { ok: false, reason: 'incomplete_client_hello', minTotal: parsed.minTotal };
  }
  if (!parsed.ok) {
    return { ok: false, reason: parsed.reason };
  }
  const p = tlsClientHandshakeProfileFromSuccessfulParse(parsed, tcpBuf, opts);
  if (!p.ok) return p;
  try {
    const j4 = ja4FromClientHelloBody(parsed.clientHelloBody);
    return {
      ...p,
      ja4: {
        ...j4,
        note:
          'FoxIO JA4 (TCP TLS). https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md — fingerprint=канон; fingerprint_alt_sni_alpn_in_j4c — тот же ja4_a/b, но JA4_c от всех типов расширений включая 0000/0010 (не по спецификации; часть сайтов). raw_r=JA4_r, raw_o=JA4_ro. Счётчик расширений в ja4_a — число не-GREASE расширений на проводе (17→16 = реально исчез один тип, например padding 0015).',
      },
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      ...p,
      ja4: {
        error: msg,
        note: 'Исключение при расчёте JA4.',
      },
    };
  }
}
