/**
 * Variable-length SNI replace/restore в первом TLS ClientHello (TCP stream).
 * ECH / HRR / второй ClientHello — отклоняются в v1.
 */

import {
  parseFirstTlsClientHelloFromTcpBuf,
  parseTlsClientHelloReadableExtensions,
} from './tls-clienthello-ja3.mjs';

const EXT_ECH = 0xfe0d;

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

    if (et === EXT_ECH) return null;

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
  let eo = o;
  while (eo + 4 <= extEnd) {
    const et = chBody.readUInt16BE(eo);
    eo += 4 + chBody.readUInt16BE(eo + 2);
    if (et === EXT_ECH) return 'ech_not_supported';
  }
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
 * @param {number} _oldBytesConsumed
 * @param {Buffer} newChBody
 */
function rebuildTcpPrefixWithClientHelloBody(tcpBuf, _oldBytesConsumed, newChBody) {
  const hsPlain = Buffer.allocUnsafe(4 + newChBody.length);
  hsPlain[0] = 1;
  hsPlain.writeUIntBE(newChBody.length, 1, 3);
  newChBody.copy(hsPlain, 4);

  const legacy = tcpBuf.length >= 3 && tcpBuf[0] === 0x16 ? tcpBuf.readUInt16BE(1) : 0x0301;
  const rec = Buffer.allocUnsafe(5 + hsPlain.length);
  rec[0] = 0x16;
  rec.writeUInt16BE(legacy, 1);
  rec.writeUInt16BE(hsPlain.length, 3);
  hsPlain.copy(rec, 5);
  return rec;
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
  let newChBody;
  try {
    newChBody = rebuildClientHelloBodyWithHostname(p.clientHelloBody, newHostnameAscii);
  } catch (e) {
    return { ok: false, reason: /** @type {Error} */ (e).message, originHost };
  }

  const prefixBuf = rebuildTcpPrefixWithClientHelloBody(tcpBuf, p.bytesConsumed, newChBody);
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

  let newChBody;
  try {
    newChBody = rebuildClientHelloBodyWithHostname(p.clientHelloBody, originHostname);
  } catch (e) {
    return { ok: false, reason: /** @type {Error} */ (e).message };
  }

  const prefixBuf = rebuildTcpPrefixWithClientHelloBody(tcpBuf, p.bytesConsumed, newChBody);
  const tailAfterPrefix = Buffer.from(tcpBuf.subarray(p.bytesConsumed));
  return { ok: true, prefixBuf, tailAfterPrefix };
}
