/**
 * MVP: находит ASCII hostname в расширении SNI первого ClientHello и перезаписывает in-place байты в буфере TCP.
 * Условие: длина UTF-8 у старого и нового имени совпадает (без изменения handshake lengths).
 */

import {
  parseFirstTlsClientHelloFromTcpBuf,
  parseTlsClientHelloReadableExtensions,
} from './tls-clienthello-ja3.mjs';

/**
 * По TCP-потоку карта plaintext handshake-byte-index → абсолютный offset в tcpBuf.
 */
export function handshakeByteIndexToTcpOffsetMap(tcpBuf, bytesConsumed) {
  /** @type {number[]} */
  const map = [];
  let tcpOff = 0;
  while (tcpOff < bytesConsumed) {
    if (tcpBuf.length < tcpOff + 5 || tcpBuf[tcpOff] !== 0x16) {
      throw new Error('transparent-tls: ожидался TLS record 0x16');
    }
    const rl = tcpBuf.readUInt16BE(tcpOff + 3);
    const payStart = tcpOff + 5;
    const recordEnd = payStart + rl;
    if (recordEnd > tcpBuf.length || recordEnd > bytesConsumed) {
      throw new Error('transparent-tls: обрезаны TLS-records handshake');
    }
    for (let j = 0; j < rl; j++) {
      map.push(payStart + j);
    }
    tcpOff = recordEnd;
  }
  return map;
}

/**
 * @param {Buffer} chBody — тело ClientHello
 * @returns {{ hostnameStartChBodyAbs: number, hostnameLenBytes: number } | null}
 */
function findFirstHostnameRangeInClientHelloBody(chBody) {
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
          const hostnameLenBytes = nl;
          return { hostnameStartChBodyAbs, hostnameLenBytes };
        }
        so += nl;
        listLen -= 3 + nl;
      }
    }
  }
  return null;
}

/**
 * @returns {{ ok: false, reason: string, originHost?: string } | { ok: true, replaced: true, originHost: string }}
 */
export function rewriteFirstSniInTcpBuffer(tcpBuf, newHostnameAscii) {
  const p = parseFirstTlsClientHelloFromTcpBuf(tcpBuf);
  if ('needMore' in p && p.needMore) {
    return { ok: false, reason: 'need_more_client_hello' };
  }
  if (!('ok' in p) || !p.ok) {
    return { ok: false, reason: p.reason ?? 'parse_fail' };
  }
  const ch = p.clientHelloBody;
  const extRead = parseTlsClientHelloReadableExtensions(ch);
  if (!extRead.ok || !extRead.sni?.length) {
    return { ok: false, reason: 'no_sni' };
  }
  const originHost = extRead.sni[0];
  const oldB = Buffer.from(originHost, 'utf8');
  const newB = Buffer.from(newHostnameAscii, 'utf8');
  if (oldB.length !== newB.length) {
    return {
      ok: false,
      reason: 'sni_utf8_length_mismatch',
      originHost,
    };
  }

  const r = findFirstHostnameRangeInClientHelloBody(ch);
  if (!r) return { ok: false, reason: 'sni_hostname_offset_not_found' };

  /** Тип handshake (1) + uint24 длина + тело ClientHello; hostname — в последнем теле. */
  const handshakeByteIndexHostname = 4 + r.hostnameStartChBodyAbs;
  const map = handshakeByteIndexToTcpOffsetMap(tcpBuf, p.bytesConsumed);
  if (handshakeByteIndexHostname + r.hostnameLenBytes > map.length) {
    return { ok: false, reason: 'hostname_outside_handshake_plaintext_map' };
  }
  for (let i = 0; i < r.hostnameLenBytes; i++) {
    if (tcpBuf[map[handshakeByteIndexHostname + i]] !== oldB[i]) {
      return { ok: false, reason: 'host_bytes_mismatch' };
    }
    tcpBuf[map[handshakeByteIndexHostname + i]] = newB[i];
  }
  return { ok: true, replaced: true, originHost };
}

/**
 * Обратное восстановление: ожидаемый SNI после локального патча → origin.
 */
export function restoreFirstSniInTcpBuffer(tcpBuf, patchedAscii, originAscii) {
  const p = parseFirstTlsClientHelloFromTcpBuf(tcpBuf);
  if ('needMore' in p && p.needMore) {
    return { ok: false, reason: 'need_more_client_hello' };
  }
  if (!('ok' in p) || !p.ok) {
    return { ok: false, reason: p.reason ?? 'parse_fail' };
  }
  const extRead = parseTlsClientHelloReadableExtensions(p.clientHelloBody);
  if (!extRead.ok || !extRead.sni?.length || extRead.sni[0] !== patchedAscii) {
    return { ok: false, reason: 'sni_hostname_not_patched_expectation' };
  }

  const pb = Buffer.from(patchedAscii, 'utf8');
  const ob = Buffer.from(originAscii, 'utf8');
  if (pb.length !== ob.length) {
    return { ok: false, reason: 'restore_length_mismatch' };
  }

  const r = findFirstHostnameRangeInClientHelloBody(p.clientHelloBody);
  if (!r) return { ok: false, reason: 'sni_hostname_offset_not_found' };
  const handshakeByteIndexHostname = 4 + r.hostnameStartChBodyAbs;
  const map = handshakeByteIndexToTcpOffsetMap(tcpBuf, p.bytesConsumed);
  if (handshakeByteIndexHostname + r.hostnameLenBytes > map.length) {
    return { ok: false, reason: 'hostname_outside_plaintext_map' };
  }
  for (let i = 0; i < r.hostnameLenBytes; i++) {
    if (tcpBuf[map[handshakeByteIndexHostname + i]] !== pb[i]) {
      return { ok: false, reason: 'patch_bytes_missing' };
    }
    tcpBuf[map[handshakeByteIndexHostname + i]] = ob[i];
  }
  return { ok: true, replaced: true };
}
