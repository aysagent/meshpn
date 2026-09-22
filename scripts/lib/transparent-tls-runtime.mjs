/** Режим --type=transparent-tls без TUN: enc-SNI relay (raw TCP TLS stream). */

import net from 'net';
import { RelaySession, readRelayHello, relayError } from './transparent-tls-io.mjs';
import { createHelloRetryGuard } from './transparent-tls-retry.mjs';
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  buildRelayHostname,
  decodeRelayFromHostname,
  encodeRelaySniLabel,
  looksLikeRelayEncSniHostname,
} from './transparent-tls-enc-sni.mjs';
import {
  replaceFirstSniInTcpBuffer,
  restoreFirstSniInTcpBuffer,
} from './transparent-tls-ch-rebuild.mjs';
import {
  extractFirstClientHelloBody,
  ja3DebugFromTcpBuf,
  ja3FromTcpBuf,
  parseFirstTlsClientHelloFromTcpBuf,
  parseTlsClientHelloReadableExtensions,
} from './tls-clienthello-ja3.mjs';
import { ja4FromTcpBuf } from './tls-clienthello-ja4.mjs';

/** @typedef {{ tlsLogJa3?: boolean, ja3Verbose?: boolean }} TransparentTlsLogOpts */
/** @typedef {'transparent-tls' | 'combo-tls'} TransparentTlsModeTag */

/**
 * Стандартный лог enc-SNI на проводе client↔exit; SNI только при sensitive=true.
 * @param {'client' | 'exit'} role
 * @param {TransparentTlsModeTag} mode
 * @param {{
 *   originSni: string,
 *   encSni: string,
 *   peer?: string,
 *   upstream?: string,
 *   originPort?: number,
 *   sensitive?: boolean,
 * }} info
 */
export function logEncSniWire(role, mode, info) {
  const parts = [`[clean-vpn ${mode} ${role}] enc-SNI wire`];
  if (info.peer) parts.push(`peer=${info.peer}`);
  if (info.upstream) parts.push(`upstream=${info.upstream}`);
  if (info.sensitive) {
    parts.push(`origin_sni=${info.originSni}`);
    parts.push(`enc_sni=${info.encSni}`);
  }
  if (info.originPort != null && info.originPort !== 443) {
    parts.push(`origin_port=${info.originPort}`);
  }
  console.log(parts.join(' '));
}

/**
 * Лог non-TLS потока на exit (dispatch).
 * @param {TransparentTlsModeTag} mode
 * @param {'ipv4-mux' | 'tls-mux'} forwardVia
 * @param {{ peer: string, firstByte: number, len: number, hexPreview: string }} info
 */
export function logNonTlsExitDispatch(mode, forwardVia, info) {
  const via =
    forwardVia === 'ipv4-mux'
      ? 'IPv4 mux (кадры uint32+pkt → TUN/NAT, как --type=socket)'
      : 'TLS mux (ожидается VPN ClientHello / boring-tls → TUN)';
  console.log(
    `[clean-vpn ${mode} exit] не TLS: peer=${info.peer} first_byte=0x${info.firstByte.toString(16).padStart(2, '0')} len=${info.len} prefix_hex=${info.hexPreview} → ${via}`,
  );
}

/**
 * Лог ветки combo-tls на exit.
 * @param {'transparent' | 'boring-tls'} branch
 * @param {string} peer
 * @param {{ wireSni?: string|null, encSni?: string|null, originSni?: string|null, note?: string, sensitive?: boolean }} [extra]
 */
export function logComboTlsExitBranch(branch, peer, extra = {}) {
  const parts = [`[clean-vpn combo-tls exit] route=${branch}`, `peer=${peer}`];
  if (extra.sensitive && extra.wireSni) parts.push(`wire_sni=${extra.wireSni}`);
  if (extra.sensitive && extra.encSni) parts.push(`enc_sni=${extra.encSni}`);
  if (extra.sensitive && extra.originSni) parts.push(`origin_sni=${extra.originSni}`);
  if (extra.note) parts.push(extra.note);
  console.log(parts.join(' '));
}

/**
 * Лог ветки combo-tls на client.
 * @param {'transparent' | 'boring-tls'} branch
 * @param {string} [detail]
 */
export function logComboTlsClientBranch(branch, detail) {
  const msg = detail ? ` ${detail}` : '';
  console.log(`[clean-vpn combo-tls client] route=${branch}${msg}`);
}

/**
 * @param {Buffer} buf
 */
function peekPrefixDescribe(buf) {
  return {
    firstByte: buf[0],
    len: buf.length,
    hexPreview: buf.subarray(0, Math.min(16, buf.length)).toString('hex'),
  };
}

export { peekPrefixDescribe };

/**
 * @param {string} roleTag 'client' | 'exit'
 * @param {string} phaseLabel
 * @param {Buffer} tcpBuf
 * @param {TransparentTlsLogOpts|null|undefined} opts
 */
function logTransparentTlsClientHelloFingerprints(roleTag, phaseLabel, tcpBuf, opts) {
  if (!opts?.tlsLogJa3 || !tcpBuf?.length) return;
  try {
    let recordLegacy = null;
    if (tcpBuf.length >= 3 && tcpBuf[0] === 0x16) {
      recordLegacy = tcpBuf.readUInt16BE(1);
    }

    let sniWire = [];
    /** @type {string[]} */
    let alpn = [];
    /** @type {number[]} */
    let sup = [];
    const chBody = extractFirstClientHelloBody(tcpBuf);
    const chLegacy = chBody && chBody.length >= 2 ? chBody.readUInt16BE(0) : null;
    if (chBody) {
      const ex = parseTlsClientHelloReadableExtensions(chBody);
      if (ex.ok) {
        sniWire = ex.sni ?? [];
        alpn = ex.alpn ?? [];
        sup = ex.supportedVersions ?? [];
      }
    }
    const sniStr = sniWire.length ? sniWire.join(',') : '—';
    const alpnStr = alpn.length ? alpn.join(',') : '—';
    const supStr = sup.length ? sup.join(',') : '—';
    const recStr = recordLegacy != null ? `0x${recordLegacy.toString(16)}` : '—';
    if (opts.ja3Verbose) {
      console.log(
        `[clean-vpn transparent-tls ${roleTag}] ${phaseLabel}: tls_record_legacy=${recStr} clienthello_legacy=${chLegacy ?? '—'} supported_versions=${supStr} offered_alpn=${alpnStr} wire_sni=${sniStr}`,
      );
    }

    const j4 = ja4FromTcpBuf(tcpBuf);
    if (j4) {
      console.log(`[clean-vpn transparent-tls ${roleTag}] ${phaseLabel}: ja4=${j4.fingerprint}`);
      console.log(`[clean-vpn transparent-tls ${roleTag}] ${phaseLabel}: ja4_alt_sni_alpn=${j4.fingerprint_alt_sni_alpn_in_j4c}`);
      if (opts.ja3Verbose) {
        console.log(`[clean-vpn transparent-tls ${roleTag}] ${phaseLabel}: ja4_a=${j4.ja4_a} ja4_b=${j4.ja4_b} ja4_c=${j4.ja4_c}`);
        console.log(
          `[clean-vpn transparent-tls ${roleTag}] ${phaseLabel}: ja4_raw_o=${j4.raw_o} | ja4_raw_r=${j4.raw_r} | ja4_raw_r_alt=${j4.raw_r_alt_sni_alpn_in_segment}`,
        );
      }
    } else {
      console.log(`[clean-vpn transparent-tls ${roleTag}] ${phaseLabel}: JA4 недоступен`);
    }

    if (opts.ja3Verbose) {
      const d = ja3DebugFromTcpBuf(tcpBuf);
      if (d) {
        console.log(`[clean-vpn transparent-tls ${roleTag}] ${phaseLabel}: ja3_md5=${d.ja3Digest} ja3_sorted_md5=${d.ja3SortedDigest}`);
        console.log(`[clean-vpn transparent-tls ${roleTag}] ${phaseLabel}: ja3_string=${d.ja3String}`);
        console.log(`[clean-vpn transparent-tls ${roleTag}] ${phaseLabel}: hex_preview=${d.hexPreview}`);
      } else {
        console.log(`[clean-vpn transparent-tls ${roleTag}] ${phaseLabel}: JA3(verbose) недоступен`);
      }
    } else {
      const j = ja3FromTcpBuf(tcpBuf);
      if (j) {
        console.log(
          `[clean-vpn transparent-tls ${roleTag}] ${phaseLabel}: ja3_md5=${j.ja3Digest} ja3_sorted_md5=${j.ja3SortedDigest}`,
        );
      }
    }
  } catch (e) {
    const msg = /** @type {Error} */ (e).message;
    console.warn(`[clean-vpn transparent-tls ${roleTag}] ${phaseLabel}: отпечатки: ${msg}`);
  }
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const requireAddon = createRequire(import.meta.url);
const TUN_LINUX_ADDON = path.join(__dirname, '../../native/tun_linux/build/Release/tun_linux.node');

/** @returns {{ address: string, port: number }} */
export function ipv4OriginalDestinationFromSock(sock) {
  const h = sock._handle;
  const fd = h && typeof h.fd === 'number' ? h.fd : undefined;
  if (fd === undefined || fd < 0) {
    throw new Error('transparent-tls: нет fd IPv4 TCP-сокета (нужен accept после REDIRECT)');
  }
  let mod;
  try {
    mod = requireAddon(TUN_LINUX_ADDON);
  } catch (e) {
    throw new Error(
      `transparent-tls: не загрузился tun_linux.node; соберите: npm run build:tun-linux`,
      { cause: e },
    );
  }
  if (typeof mod.originalDstIpv4FromFd !== 'function') {
    throw new Error('transparent-tls: tun_linux без originalDstIpv4FromFd — пересоберите addon');
  }
  return mod.originalDstIpv4FromFd(fd);
}

export function killPair(a, b) {
  killOne(a);
  killOne(b);
}

/** @param {import('stream').Duplex|null|undefined} s */
export function killOne(s) {
  try {
    s?.destroy?.();
  } catch {
    /* ignore */
  }
}

/**
 * Классификация префикса для combo-tls exit: enc-SNI relay vs TLS mux.
 * @param {Buffer} buf
 * @param {string} publicName
 * @param {Buffer} psk
 */
export function classifyComboTlsExitPrefix(buf, publicName, psk) {
  if (buf.length < 1) return { status: 'need_more', minTotal: 1 };
  if (buf[0] !== 0x16) return { status: 'tls_mux' };
  const parsed = parseFirstTlsClientHelloFromTcpBuf(buf);
  if ('needMore' in parsed && parsed.needMore) {
    return { status: 'need_more', minTotal: parsed.minTotal };
  }
  if (!('ok' in parsed) || !parsed.ok || !parsed.sni?.[0]) {
    return { status: 'tls_mux' };
  }
  if (!looksLikeRelayEncSniHostname(parsed.sni[0], publicName)) {
    return { status: 'tls_mux' };
  }
  const dec = decodeRelayFromHostname(parsed.sni[0], publicName, psk);
  if (!dec.ok) return { status: 'tls_mux' };
  return { status: 'relay', parsed, decoded: dec };
}

/**
 * Exit: decrypt SNI, restore ClientHello and relay with bounded I/O.
 * Returns a session handle; failures are handled internally (accept callbacks
 * need not await a promise). Optional connectors are used by the loopback lab.
 */
export function wireTransparentTlsEncSniSession(mux, opts) {
  let session;
  try { session = new RelaySession(mux, opts); }
  catch (error) {
    mux.destroy();
    opts.onSessionError?.(error);
    console.error('[transparent-tls exit]', error.code ?? 'TLS_RELAY_CONFIG');
    return null;
  }
  const ready = (async () => {
    const { vpnSecretBuf, publicName, logOpts } = opts;
    const mode = opts.modeTag ?? 'transparent-tls';
    const { buffer, parsed } = await readRelayHello(mux, session, opts.initialBuf);
    session.check();
    const dec = decodeRelayFromHostname(parsed.sni[0], publicName, vpnSecretBuf);
    if (!dec.ok) throw relayError('TLS_RELAY_DECODE', 'enc-SNI decode failed');
    const prefix = buffer.subarray(0, parsed.bytesConsumed);
    const restored = restoreFirstSniInTcpBuffer(prefix, parsed.sni[0], dec.hostname);
    if (!restored.ok) throw relayError('TLS_RELAY_REBUILD', 'SNI restore failed');
    const guard = createHelloRetryGuard(session, {
      parsed, prefix, role: 'exit', relayHost: parsed.sni[0], originHost: dec.hostname,
    });
    const tail = buffer.subarray(parsed.bytesConsumed);
    const prelude = relayPrelude(restored.prefixBuf, guard ? guard.forward(tail) : tail, session);
    const peer = `${mux.remoteAddress ?? '?'}:${mux.remotePort ?? '?'}`;
    logEncSniWire('exit', mode, {
      originSni: dec.hostname, encSni: parsed.sni[0], peer,
      originPort: dec.port, sensitive: logOpts?.ja3Verbose,
    });
    if (mode === 'combo-tls') logComboTlsExitBranch('transparent', peer, {
      originSni: dec.hostname, encSni: parsed.sni[0], sensitive: logOpts?.ja3Verbose,
    });
    logTransparentTlsClientHelloFingerprints('exit', 'Mux enc-SNI ClientHello', prefix, logOpts);
    logTransparentTlsClientHelloFingerprints('exit', 'К origin: ClientHello после restore', restored.prefixBuf, logOpts);
    const origin = await session.connect(() => opts.connectOrigin
      ? opts.connectOrigin(dec.hostname, dec.port) : net.connect(dec.port, dec.hostname));
    await session.bridge(mux, origin, prelude, guard);
  })();
  // Keep the accept path free of unhandled rejections; closed reports the reason.
  session.ready = ready.catch((error) => {
    const safe = safeRelayError(error);
    session.fail(safe);
    console.error('[transparent-tls exit]', safe.code);
  });
  return session;
}

function safeRelayError(error) {
  return error?.code?.startsWith('TLS_RELAY_')
    ? error : relayError('TLS_RELAY_INTERNAL', 'TLS relay failed', error);
}

function relayPrelude(prefix, tail, session) {
  if (prefix.length + tail.length > session.limits.maxPendingBytes) {
    throw relayError('TLS_RELAY_PENDING_LIMIT');
  }
  return Buffer.concat([prefix, tail]);
}

/** TCP exit listener without TUN. */
export function runTransparentTlsExitServer(host, listenPort, vpnSecretBuf, publicName) {
  const srv = net.createServer((mux) => {
    wireTransparentTlsEncSniSession(mux, { vpnSecretBuf, publicName, logOpts: {} });
  });
  srv.listen(listenPort, host, () => {
    console.log(`[clean-vpn] transparent-tls exit: enc-SNI relay без TUN, слушаю ${host}:${listenPort}`);
  });
  return srv;
}

/** Client: REDIRECT/TCP → rewrite SNI → raw TCP TLS stream to exit. */
export async function attachTransparentTlsClientSession(appSock, opts) {
  let session;
  try {
    session = new RelaySession(appSock, opts);
    const {
      upstreamHost, upstreamPort, vpnSecretBuf, publicName,
      explicitDestination, logOpts,
    } = opts;
    const pn = String(publicName || '').trim();
    if (!pn) throw relayError('TLS_RELAY_CONFIG', 'transparent-tls: --tls-public-name обязателен');
    const mode = opts.modeTag ?? 'transparent-tls';
    appSock.pause();
    const dst = explicitDestination != null && typeof explicitDestination.address === 'string'
      ? explicitDestination : ipv4OriginalDestinationFromSock(appSock);
    const { buffer, parsed } = await readRelayHello(appSock, session);
    session.check();
    let relayHostname;
    try {
      relayHostname = buildRelayHostname(encodeRelaySniLabel(vpnSecretBuf, {
        hostname: parsed.sni[0], port: dst.port,
      }), pn);
    } catch (cause) { throw relayError('TLS_RELAY_ENCODE', 'enc-SNI encode failed', cause); }
    const prefix = buffer.subarray(0, parsed.bytesConsumed);
    const rewritten = replaceFirstSniInTcpBuffer(prefix, relayHostname);
    if (!rewritten.ok) throw relayError('TLS_RELAY_REBUILD', 'SNI rebuild failed');
    const guard = createHelloRetryGuard(session, {
      parsed, prefix, role: 'client', relayHost: relayHostname, originHost: parsed.sni[0],
    });
    const tail = buffer.subarray(parsed.bytesConsumed);
    const prelude = relayPrelude(rewritten.prefixBuf, guard ? guard.forward(tail) : tail, session);
    logEncSniWire('client', mode, {
      originSni: parsed.sni[0], encSni: relayHostname,
      peer: `${appSock.remoteAddress ?? '?'}:${appSock.remotePort ?? '?'}`,
      upstream: `${upstreamHost}:${upstreamPort}`, originPort: dst.port,
      sensitive: logOpts?.ja3Verbose,
    });
    if (mode === 'combo-tls') logComboTlsClientBranch('transparent', logOpts?.ja3Verbose
      ? `origin_sni=${parsed.sni[0]} enc_sni=${relayHostname} so_orig=${dst.address}:${dst.port}` : undefined);
    logTransparentTlsClientHelloFingerprints('client', 'ClientHello браузера (до подмены)', prefix, logOpts);
    logTransparentTlsClientHelloFingerprints('client', 'ClientHello после enc-SNI rebuild', rewritten.prefixBuf, logOpts);
    const mux = await session.connect(() => opts.connectExit
      ? opts.connectExit(upstreamHost, upstreamPort) : net.connect(upstreamPort, upstreamHost));
    await session.bridge(appSock, mux, prelude, guard);
    return session;
  } catch (cause) {
    const error = safeRelayError(cause);
    if (session) session.fail(error);
    else {
      appSock.destroy();
      opts.onSessionError?.(error);
    }
    throw error;
  }
}
