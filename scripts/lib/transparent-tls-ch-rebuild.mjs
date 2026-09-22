/**
 * Variable-length SNI replace/restore в первом TLS ClientHello (TCP stream).
 *
 * ECH (0xfe0d, включая GREASE ECH, который Chrome шлёт по умолчанию) НЕ блокируется:
 * переписывается только строка hostname в SNI, байты ECH-расширения не трогаются, а exit
 * восстанавливает исходный ClientHello байт-в-байт (SNI назад + ECH как был) и проксирует
 * сырой TCP — TLS терминируется между браузером и origin. Для поддержанного record layout
 * восстанавливаются и ClientHello, и исходные TLS records. GREASE ECH покрыт тестами;
 * сохранение байтов расширения НЕ доказывает работоспособность настоящего ECH/его routing.
 */

import {
  parseFirstTlsClientHelloFromTcpBuf,
  parseTlsClientHelloReadableExtensions,
} from './tls-clienthello-ja3.mjs';

// TLSPlaintext.fragment ceiling, RFC 8446 §5.1. No silent re-fragmentation:
// https://www.rfc-editor.org/rfc/rfc8446#section-5.1
const MAX_PLAINTEXT_RECORD_BYTES = 16 * 1024;

/**
 * @param {Buffer} chBody
 * @returns {{
 *   hostnameStartChBodyAbs: number,
 *   hostnameLenBytes: number,
 *   sniListLenPos: number,
 *   sniExtLenPos: number,
 *   extensionsTotalLenPos: number,
 * } | null}
 */
function findFirstSniLayoutInClientHelloBody(chBody) {
  let o = 0;
  if (chBody.length < 34) return null;
  o += 34;
  const sidLen = chBody[o];
  o += 1;
  if (chBody.length < o + sidLen + 2) return null;
  o += sidLen;
  const csLen = chBody.readUInt16BE(o);
  o += 2;
  if (chBody.length < o + csLen + 1) return null;
  o += csLen;
  const compLen = chBody[o];
  o += 1;
  if (chBody.length < o + compLen + 2) return null;
  o += compLen;
  const extensionsTotalLenPos = o;
  const extLen = chBody.readUInt16BE(o);
  o += 2;
  if (chBody.length < o + extLen) return null;
  const extBlockStart = o;
  const extBlock = chBody.subarray(extBlockStart, extBlockStart + extLen);

  let eo = 0;
  while (eo + 4 <= extBlock.length) {
    const et = extBlock.readUInt16BE(eo);
    const el = extBlock.readUInt16BE(eo + 2);
    const bodyRel = eo + 4;
    eo += 4 + el;
    const ed = extBlock.subarray(bodyRel, bodyRel + el);

    if (et === 0 && ed.length >= 2) {
      let listLen = ed.readUInt16BE(0);
      let so = 2;
      while (so + 3 <= ed.length && listLen >= 3) {
        const nt = ed[so];
        const nl = ed.readUInt16BE(so + 1);
        so += 3;
        if (so + nl > ed.length) break;
        if (nt === 0) {
          const hostnameStartChBodyAbs = extBlockStart + bodyRel + so;
          return {
            hostnameStartChBodyAbs,
            hostnameLenBytes: nl,
            sniListLenPos: extBlockStart + bodyRel,
            sniExtLenPos: extBlockStart + bodyRel - 2,
            extensionsTotalLenPos,
          };
        }
        so += nl;
        listLen -= 3 + nl;
      }
    }
  }
  return null;
}

/** @param {Buffer} chBody */
function clientHelloBlockedForEncSni(chBody) {
  let o = 0;
  if (chBody.length < 34) return 'ch_short';
  o += 34;
  const sidLen = chBody[o];
  o += 1 + sidLen;
  const csLen = chBody.readUInt16BE(o);
  o += 2 + csLen;
  const compLen = chBody[o];
  o += 1 + compLen;
  if (chBody.length < o + 2) return 'ch_short';
  const extLen = chBody.readUInt16BE(o);
  o += 2;
  const extEnd = o + extLen;
  if (chBody.length < extEnd) return 'ch_short';
  // ECH (0xfe0d) намеренно НЕ блокируется — см. шапку файла. Переписываем только SNI,
  // расширение ECH остаётся нетронутым, exit восстанавливает оригинальный ClientHello.
  return null;
}

/**
 * @param {Buffer} chBody
 * @param {string} newHostnameAscii
 */
function rebuildClientHelloBodyWithHostname(chBody, newHostnameAscii) {
  const blocked = clientHelloBlockedForEncSni(chBody);
  if (blocked) throw new Error(blocked);
  const layout = findFirstSniLayoutInClientHelloBody(chBody);
  if (!layout) throw new Error('sni_hostname_offset_not_found');

  const oldHost = chBody.subarray(
    layout.hostnameStartChBodyAbs,
    layout.hostnameStartChBodyAbs + layout.hostnameLenBytes,
  );
  const newB = Buffer.from(newHostnameAscii, 'utf8');
  if (newB.length < 1 || newB.length > 253) throw new Error('relay_sni_length');

  const delta = newB.length - oldHost.length;
  const out = Buffer.alloc(chBody.length + delta);
  chBody.copy(out, 0, 0, layout.hostnameStartChBodyAbs);
  newB.copy(out, layout.hostnameStartChBodyAbs);
  chBody.copy(
    out,
    layout.hostnameStartChBodyAbs + newB.length,
    layout.hostnameStartChBodyAbs + layout.hostnameLenBytes,
  );

  out.writeUInt16BE(newB.length, layout.hostnameStartChBodyAbs - 2);
  out.writeUInt16BE(out.readUInt16BE(layout.sniListLenPos) + delta, layout.sniListLenPos);
  out.writeUInt16BE(out.readUInt16BE(layout.sniExtLenPos) + delta, layout.sniExtLenPos);
  out.writeUInt16BE(
    out.readUInt16BE(layout.extensionsTotalLenPos) + delta,
    layout.extensionsTotalLenPos,
  );
  return out;
}

/**
 * @param {Buffer} tcpBuf
 * @param {{ bytesConsumed: number, clientHelloBody: Buffer }} parsed
 * @param {Buffer} newChBody
 */
function rebuildTcpPrefixWithClientHelloBody(tcpBuf, parsed, newChBody) {
  const layout = findFirstSniLayoutInClientHelloBody(parsed.clientHelloBody);
  if (!layout) throw new Error('sni_hostname_offset_not_found');
  const hostnameStart = 4 + layout.hostnameStartChBodyAbs;
  const delta = newChBody.length - parsed.clientHelloBody.length;
  const records = [];
  const payloads = [];
  let payloadOffset = 0;
  for (let at = 0; at < parsed.bytesConsumed;) {
    const size = tcpBuf.readUInt16BE(at + 3);
    if (size > MAX_PLAINTEXT_RECORD_BYTES) throw new Error('record_plaintext_oversize');
    const ownsSniStart = payloadOffset <= hostnameStart && hostnameStart < payloadOffset + size;
    const newSize = size + (ownsSniStart ? delta : 0);
    // Keep the first hostname byte in this same record in both directions.
    // The relay token is longer, so only this record grows on client→exit.
    // On restore the inverse delta recovers every original boundary, including
    // records splitting the SNI itself. No extra on-wire metadata is needed.
    if (newSize < 1 || newSize > MAX_PLAINTEXT_RECORD_BYTES ||
        (ownsSniStart && newSize <= hostnameStart - payloadOffset)) {
      throw new Error('record_layout_resize_unsupported');
    }
    records.push({ header: tcpBuf.subarray(at, at + 5), size: newSize });
    payloads.push(tcpBuf.subarray(at + 5, at + 5 + size));
    payloadOffset += size;
    at += 5 + size;
  }
  const oldPayload = Buffer.concat(payloads, payloadOffset);
  const handshakeHeader = Buffer.alloc(4);
  handshakeHeader[0] = 1;
  handshakeHeader.writeUIntBE(newChBody.length, 1, 3);
  // bytesConsumed includes the *whole* last record, not just ClientHello.
  // Preserve opaque bytes of a neighboring message (even its partial header).
  const newPayload = Buffer.concat([
    handshakeHeader, newChBody, oldPayload.subarray(4 + parsed.clientHelloBody.length),
  ]);
  const out = Buffer.alloc(parsed.bytesConsumed + delta);
  let source = 0;
  let target = 0;
  for (const { header, size } of records) {
    header.copy(out, target);
    out.writeUInt16BE(size, target + 3);
    newPayload.copy(out, target + 5, source, source + size);
    source += size;
    target += 5 + size;
  }
  return out;
}

/**
 * @returns {{ ok: false, reason: string, originHost?: string } | { ok: true, originHost: string, relayHost: string, prefixBuf: Buffer, tailAfterPrefix: Buffer }}
 */
export function replaceFirstSniInTcpBuffer(tcpBuf, newHostnameAscii) {
  const p = parseFirstTlsClientHelloFromTcpBuf(tcpBuf);
  if ('needMore' in p && p.needMore) {
    return { ok: false, reason: 'need_more_client_hello' };
  }
  if (!('ok' in p) || !p.ok) {
    return { ok: false, reason: p.reason ?? 'parse_fail' };
  }
  const extRead = parseTlsClientHelloReadableExtensions(p.clientHelloBody);
  if (!extRead.ok || !extRead.sni?.length) {
    return { ok: false, reason: 'no_sni' };
  }
  const blocked = clientHelloBlockedForEncSni(p.clientHelloBody);
  if (blocked) return { ok: false, reason: blocked };

  const originHost = extRead.sni[0];
  let prefixBuf;
  try {
    const newChBody = rebuildClientHelloBodyWithHostname(p.clientHelloBody, newHostnameAscii);
    prefixBuf = rebuildTcpPrefixWithClientHelloBody(tcpBuf, p, newChBody);
  } catch (e) {
    return { ok: false, reason: /** @type {Error} */ (e).message, originHost };
  }

  const tailAfterPrefix = Buffer.from(tcpBuf.subarray(p.bytesConsumed));
  return { ok: true, originHost, relayHost: newHostnameAscii, prefixBuf, tailAfterPrefix };
}

/**
 * @returns {{ ok: false, reason: string } | { ok: true, prefixBuf: Buffer, tailAfterPrefix: Buffer }}
 */
export function restoreFirstSniInTcpBuffer(tcpBuf, relayHostname, originHostname) {
  const p = parseFirstTlsClientHelloFromTcpBuf(tcpBuf);
  if ('needMore' in p && p.needMore) {
    return { ok: false, reason: 'need_more_client_hello' };
  }
  if (!('ok' in p) || !p.ok) {
    return { ok: false, reason: p.reason ?? 'parse_fail' };
  }
  const extRead = parseTlsClientHelloReadableExtensions(p.clientHelloBody);
  if (!extRead.ok || !extRead.sni?.length || extRead.sni[0] !== relayHostname) {
    return { ok: false, reason: 'sni_hostname_not_relay_expectation' };
  }

  let prefixBuf;
  try {
    const newChBody = rebuildClientHelloBodyWithHostname(p.clientHelloBody, originHostname);
    prefixBuf = rebuildTcpPrefixWithClientHelloBody(tcpBuf, p, newChBody);
  } catch (e) {
    return { ok: false, reason: /** @type {Error} */ (e).message };
  }

  const tailAfterPrefix = Buffer.from(tcpBuf.subarray(p.bytesConsumed));
  return { ok: true, prefixBuf, tailAfterPrefix };
}
