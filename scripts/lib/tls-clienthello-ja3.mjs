/**
 * JA3 по сырым байтам первого ClientHello (алгоритм Salesforce JA3, GREASE из RFC 8701).
 * В строку JA3 входят только типы расширений (числа), не содержимое ALPN/SNI и т.п.
 * @see https://github.com/salesforce/ja3
 */
import crypto from 'node:crypto';

/** GREASE (RFC 8701) — общий набор для JA3/JA4. */
export const TLS_GREASE_VALUES = new Set([
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
 * Order-invariant JA3-подобная строка: те же компоненты, что после GREASE-filter,
 * но каждый числовой список отсортирован по возрастанию (для сравнения с Chrome
 * при перемешивании порядка расширений на wire). MD5 UTF-8 строки как у JA3.
 * Не заменяет классический JA3 для сверки с БД — там порядок wire.
 */
export function ja3SortedStringDigestFromComponents(
  legacyVersion,
  ciphers,
  extTypes,
  curves,
  ecPointFormats,
) {
  const sc = [...ciphers].sort((a, b) => a - b);
  const se = [...extTypes].sort((a, b) => a - b);
  const sg = [...curves].sort((a, b) => a - b);
  const sf = [...ecPointFormats].sort((a, b) => a - b);
  const ja3SortedString = [
    legacyVersion,
    sc.join('-'),
    se.join('-'),
    sg.join('-'),
    sf.join('-'),
  ].join(',');
  return {
    ja3SortedString,
    ja3SortedDigest: crypto.createHash('md5').update(ja3SortedString, 'utf8').digest('hex'),
  };
}

/**
 * Тело первого ClientHello из TCP при склейке нескольких TLS handshake records
 * (как на exit mux и у Chrome с фрагментированным ClientHello).
 * @param {Buffer} buf — TCP payload с начала соединения (первый байт обычно 0x16).
 * @returns {Buffer | null}
 */
export function extractFirstClientHelloBodyFromTcpMux(buf) {
  if (buf.length > TLS_MUX_MAX_CLIENT_BUF) return null;
  if (buf.length < 5 || buf[0] !== 0x16) return null;
  /** @type {Buffer[]} */
  const payloads = [];
  let offset = 0;
  for (;;) {
    if (buf.length - offset < 5) return null;
    if (buf[offset] !== 0x16) return null;
    const recLen = buf.readUInt16BE(offset + 3);
    const recordEnd = offset + 5 + recLen;
    if (recLen < 1 || recordEnd > TLS_MUX_MAX_CLIENT_BUF) return null;
    if (recordEnd > buf.length) return null;
    payloads.push(buf.subarray(offset + 5, recordEnd));
    offset = recordEnd;
    const combined = Buffer.concat(payloads);
    if (combined.length < 4) continue;
    if (combined[0] !== 1) return null;
    const hsLen = combined.readUIntBE(1, 3);
    const totalHs = 4 + hsLen;
    if (combined.length < totalHs) continue;
    return combined.subarray(4, totalHs);
  }
}

/**
 * Из буфера TCP вытаскивает тело ClientHello.
 * При типичном входе (начинается с TLS handshake record) склеивает несколько records.
 * Иначе — прежний однопроходный разбор по записям.
 * @param {Buffer} buf
 * @returns {Buffer | null}
 */
export function extractFirstClientHelloBody(buf) {
  if (buf.length >= 1 && buf[0] === 0x16) {
    const parsed = parseFirstTlsClientHelloFromTcpBuf(buf);
    if (parsed.ok === true && parsed.clientHelloBody) return parsed.clientHelloBody;
    if ('needMore' in parsed && parsed.needMore) return null;
    const mux = extractFirstClientHelloBodyFromTcpMux(buf);
    if (mux) return mux;
  }
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
 *   ja3SortedString: string,
 *   ja3SortedDigest: string,
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
    if (!TLS_GREASE_VALUES.has(cs)) ciphers.push(cs);
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
    if (TLS_GREASE_VALUES.has(et)) continue;
    extTypes.push(et);
    if (et === 0x000a && edata.length >= 2) {
      const glen = edata.readUInt16BE(0);
      for (let i = 2; i < 2 + glen && i + 2 <= edata.length; i += 2) {
        const g = edata.readUInt16BE(i);
        if (!TLS_GREASE_VALUES.has(g)) curves.push(g);
      }
    } else if (et === 0x000b && edata.length >= 1) {
      const flen = edata[0];
      for (let i = 1; i < 1 + flen && i < edata.length; i++) ecPointFormats.push(edata[i]);
    }
  }

  if (o !== extEnd) {
    throw new Error(
      'ja3: объявленная длина блока расширений не сходится с разбором (обрезанное hello или неверные поля длины)',
    );
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

  const sorted = ja3SortedStringDigestFromComponents(
    legacyVersion,
    ciphers,
    extTypes,
    curves,
    ecPointFormats,
  );

  return {
    legacyVersion,
    ciphers,
    extTypes,
    curves,
    ecPointFormats,
    ja3String,
    ja3Digest: crypto.createHash('md5').update(ja3String, 'utf8').digest('hex'),
    ja3SortedString: sorted.ja3SortedString,
    ja3SortedDigest: sorted.ja3SortedDigest,
  };
}

/**
 * Расширения 13 и 50 (signature_algorithms / signature_algorithms_cert) и объединённый
 * порядок как для JA4_c (обход расширений на проводе, GREASE отфильтрован).
 * @param {Buffer} body — тело ClientHello
 * @returns {{
 *   signature_algorithms: number[],
 *   signature_algorithms_cert: number[],
 *   ja4_signature_algorithms_wire: number[],
 * }}
 */
export function signatureAlgorithmsFromClientHelloBody(body) {
  let o = 0;
  if (body.length < 2) throw new Error('sigalgs: короткое ClientHello');
  o += 2 + 32;
  const sidLen = body[o];
  o += 1;
  if (body.length < o + sidLen + 2) throw new Error('sigalgs: обрезано (session id)');
  o += sidLen;
  const cipherLen = body.readUInt16BE(o);
  o += 2;
  if (cipherLen % 2 !== 0 || body.length < o + cipherLen + 1) {
    throw new Error('sigalgs: обрезано (cipher list)');
  }
  o += cipherLen;
  const compLen = body[o];
  o += 1;
  if (body.length < o + compLen + 2) throw new Error('sigalgs: обрезано (compression)');
  o += compLen;
  const extTotal = body.readUInt16BE(o);
  o += 2;
  const extEnd = o + extTotal;
  if (extEnd > body.length) throw new Error('sigalgs: обрезано (extensions)');

  /** @type {number[]} */
  const signatureAlgorithms = [];
  /** @type {number[]} */
  const signatureAlgorithmsCert = [];
  /** @type {number[]} */
  const ja4Merged = [];

  while (o + 4 <= extEnd && o + 4 <= body.length) {
    const et = body.readUInt16BE(o);
    const elen = body.readUInt16BE(o + 2);
    o += 4;
    if (o + elen > body.length || o + elen > extEnd) {
      throw new Error('sigalgs: обрезанное расширение');
    }
    const edata = body.subarray(o, o + elen);
    o += elen;
    if (TLS_GREASE_VALUES.has(et)) continue;

    const pushSigList = (into, mergeToo) => {
      if (edata.length < 2) return;
      const algLen = edata.readUInt16BE(0);
      for (let i = 2; i < 2 + algLen && i + 2 <= edata.length; i += 2) {
        const sid = edata.readUInt16BE(i);
        if (TLS_GREASE_VALUES.has(sid)) continue;
        into.push(sid);
        if (mergeToo) ja4Merged.push(sid);
      }
    };

    if (et === 13) {
      pushSigList(signatureAlgorithms, true);
    } else if (et === 50) {
      pushSigList(signatureAlgorithmsCert, true);
    }
  }

  if (o !== extEnd) {
    throw new Error('sigalgs: длина блока расширений не сходится');
  }

  return {
    signature_algorithms: signatureAlgorithms,
    signature_algorithms_cert: signatureAlgorithmsCert,
    ja4_signature_algorithms_wire: ja4Merged,
  };
}

/**
 * @param {Buffer} body — тело ClientHello (RFC 8446)
 * @returns {{
 *   ja3String: string,
 *   ja3Digest: string,
 *   ja3SortedString: string,
 *   ja3SortedDigest: string,
 * }}
 */
export function ja3FromClientHelloBody(body) {
  const c = ja3ComponentsFromClientHelloBody(body);
  return {
    ja3String: c.ja3String,
    ja3Digest: c.ja3Digest,
    ja3SortedString: c.ja3SortedString,
    ja3SortedDigest: c.ja3SortedDigest,
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

/**
 * JA3-поля из уже извлечённого тела ClientHello (тот же буфер, что для JA4 и проверки расширений).
 * @param {Buffer} clientHelloBody
 * @param {Buffer} tcpBuf исходный TCP (только для hex-превью с начала потока)
 * @param {{ hexPreviewLen?: number }} [opts]
 */
export function ja3DebugFromClientHelloBody(clientHelloBody, tcpBuf, opts = {}) {
  const c = ja3ComponentsFromClientHelloBody(clientHelloBody);
  const maxHex = opts.hexPreviewLen ?? JA3_HEX_PREVIEW_DEFAULT;
  const hexPreview = Buffer.from(tcpBuf.subarray(0, Math.min(maxHex, tcpBuf.length))).toString(
    'hex',
  );
  return {
    ja3Digest: c.ja3Digest,
    ja3String: c.ja3String,
    ja3SortedDigest: c.ja3SortedDigest,
    ja3SortedString: c.ja3SortedString,
    legacyVersion: c.legacyVersion,
    ciphers: c.ciphers,
    extTypes: c.extTypes,
    curves: c.curves,
    ecPointFormats: c.ecPointFormats,
    hexPreview,
  };
}

/**
 * Полный разбор для логов (--ja3-verbose): извлекает ClientHello из TCP и считает JA3.
 * @param {Buffer} tcpBuf — TCP payload от начала соединения
 * @param {{ hexPreviewLen?: number }} [opts]
 * @returns {{
 *   ja3Digest: string,
 *   ja3String: string,
 *   ja3SortedDigest: string,
 *   ja3SortedString: string,
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
  return ja3DebugFromClientHelloBody(ch, tcpBuf, opts);
}

/** GREASE для типов расширений TLS (RFC 8701). */
export function tlsExtensionTypeIsGrease(et) {
  return (et & 0x0f0f) === 0x0a0a && ((et >> 8) & 0xff) === (et & 0xff);
}

/**
 * Типы расширений, которые типичный клиент BoringSSL/Chromium уже кладёт в ClientHello
 * (или задаёт профиль/helper). Повтор через opaque даёт два блока с одним типом → alert 47.
 * Держать в синхроне с MeshvpnOpaqueExtensionBlocked в native/boring_tls/helper_main.cc.
 */
export const MESHVPN_OPAQUE_EXTENSION_SKIP_TYPES = new Set([
  0, 5, 10, 11, 13, 16, 43, 45, 50, 51,
  // 18 / 27: в профиле Chrome часто есть; BoringSSL-helper может не слать —
  // воспроизводим opaque; при дубликате стек+BoringSSL отсекается в форке (emit).
  21, // padding (стек добавляет после meshvpn_extra)
  23, // extended_master_secret
  35, // session_ticket
  41, // pre_shared_key
  65281, // renegotiation_info (0xff01)
]);

/**
 * Из тела ClientHello: расширения с сырыми телами для replay в boring-tls-helper
 * (поле `client_hello_extra_extensions` в профиле).
 * @param {Buffer} ch — тело ClientHello без handshake type/len
 * @returns {{ type: number, hex: string }[]}
 */
export function extractClientHelloOpaqueExtensionsForProfile(ch) {
  let o = 0;
  if (ch.length < 34) return [];
  o += 34;
  const sidLen = ch[o];
  o += 1;
  if (ch.length < o + sidLen + 2) return [];
  o += sidLen;
  const csLen = ch.readUInt16BE(o);
  o += 2;
  if (ch.length < o + csLen + 1) return [];
  o += csLen;
  const compLen = ch[o];
  o += 1;
  if (ch.length < o + compLen + 2) return [];
  o += compLen;
  const extLen = ch.readUInt16BE(o);
  o += 2;
  if (ch.length < o + extLen) return [];
  const extBlock = ch.subarray(o, o + extLen);
  /** @type {{ type: number, hex: string }[]} */
  const out = [];
  let eo = 0;
  while (eo + 4 <= extBlock.length) {
    const et = extBlock.readUInt16BE(eo);
    const el = extBlock.readUInt16BE(eo + 2);
    eo += 4;
    if (eo + el > extBlock.length) break;
    const ed = extBlock.subarray(eo, eo + el);
    eo += el;
    if (TLS_GREASE_VALUES.has(et) || tlsExtensionTypeIsGrease(et)) continue;
    if (MESHVPN_OPAQUE_EXTENSION_SKIP_TYPES.has(et)) continue;
    out.push({ type: et, hex: ed.toString('hex') });
  }
  return out;
}

/**
 * Профиль handshake из успешного {@link parseFirstTlsClientHelloFromTcpBuf} — один общий `clientHelloBody` для JA3/JA4.
 * @param {{ ok: true, sni: string[], alpn: string[], supportedVersions: number[], bytesConsumed: number, clientHelloBody: Buffer }} parsed
 * @param {Buffer} tcpBuf
 * @param {{ hexPreviewLen?: number }} [opts]
 */
export function tlsClientHandshakeProfileFromSuccessfulParse(parsed, tcpBuf, opts = {}) {
  let ja3d;
  try {
    ja3d = ja3DebugFromClientHelloBody(parsed.clientHelloBody, tcpBuf, opts);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, reason: 'ja3_components_failed', message: msg };
  }
  /** @type {ReturnType<typeof signatureAlgorithmsFromClientHelloBody> | null} */
  let sigAlgs = null;
  try {
    sigAlgs = signatureAlgorithmsFromClientHelloBody(parsed.clientHelloBody);
  } catch {
    sigAlgs = null;
  }
  /** @type {number | null} */
  let tlsRecordLegacyVersion = null;
  if (tcpBuf.length >= 3 && tcpBuf[0] === 0x16) {
    tlsRecordLegacyVersion = tcpBuf.readUInt16BE(1);
  }
  const clientHelloOpaqueExt = extractClientHelloOpaqueExtensionsForProfile(parsed.clientHelloBody);
  return {
    ok: true,
    ...(clientHelloOpaqueExt.length > 0
      ? { client_hello_extra_extensions: clientHelloOpaqueExt }
      : {}),
    tls: {
      tls_record_legacy_version: tlsRecordLegacyVersion,
      tls_record_legacy_hex:
        tlsRecordLegacyVersion != null ? `0x${tlsRecordLegacyVersion.toString(16)}` : null,
      clienthello_legacy_version: ja3d.legacyVersion,
      clienthello_legacy_hex: `0x${ja3d.legacyVersion.toString(16)}`,
      sni_hostnames: parsed.sni,
      offered_alpn_protocols: parsed.alpn,
      supported_versions_extension: parsed.supportedVersions,
      ...(sigAlgs && sigAlgs.signature_algorithms.length > 0
        ? { signature_algorithms: sigAlgs.signature_algorithms }
        : {}),
      ...(sigAlgs && sigAlgs.signature_algorithms_cert.length > 0
        ? { signature_algorithms_cert: sigAlgs.signature_algorithms_cert }
        : {}),
      ...(sigAlgs && sigAlgs.ja4_signature_algorithms_wire.length > 0
        ? { ja4_signature_algorithms_wire: sigAlgs.ja4_signature_algorithms_wire }
        : {}),
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
    ja3_sorted: {
      md5: ja3d.ja3SortedDigest,
      string_before_md5: ja3d.ja3SortedString,
      note:
        'Те же компоненты после GREASE-filter, списки отсортированы по возрастанию; стабильнее при permute_extensions у Chromium. Не совпадает с классическим JA3 в БД для того же браузера.',
    },
    wire: {
      hex_preview_first_tcp_bytes: ja3d.hexPreview,
    },
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
    if (eo + el > extBlock.length) {
      return { ok: false, reason: 'ext_length_overflow' };
    }
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
  if (eo !== extBlock.length) {
    return { ok: false, reason: 'ext_trailing_or_skipped_bytes' };
  }
  return { ok: true, sni, alpn, supportedVersions };
}

/**
 * Накопленный TCP от начала соединения до полного первого ClientHello (несколько TLS records).
 * @returns {{ needMore: true, minTotal: number } | { ok: false, reason: string } | { ok: true, sni: string[], alpn: string[], supportedVersions: number[], bytesConsumed: number, clientHelloBody: Buffer }}
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
      clientHelloBody: ch,
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
  return tlsClientHandshakeProfileFromSuccessfulParse(parsed, tcpBuf, opts);
}
