/** Режим --type=transparent-tls без TUN: enc-SNI relay (raw TCP TLS stream). */

import net from 'net';
import { once } from 'events';
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
 * Стандартный лог enc-SNI на проводе client↔exit (всегда, без --tls-log-ja3).
 * @param {'client' | 'exit'} role
 * @param {TransparentTlsModeTag} mode
 * @param {{
 *   originSni: string,
 *   encSni: string,
 *   peer?: string,
 *   upstream?: string,
 *   originPort?: number,
 * }} info
 */
export function logEncSniWire(role, mode, info) {
  const parts = [`[clean-vpn ${mode} ${role}] enc-SNI wire`];
  if (info.peer) parts.push(`peer=${info.peer}`);
  if (info.upstream) parts.push(`upstream=${info.upstream}`);
  parts.push(`origin_sni=${info.originSni}`);
  parts.push(`enc_sni=${info.encSni}`);
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
 * @param {{ wireSni?: string|null, encSni?: string|null, originSni?: string|null, note?: string }} [extra]
 */
export function logComboTlsExitBranch(branch, peer, extra = {}) {
  const parts = [`[clean-vpn combo-tls exit] route=${branch}`, `peer=${peer}`];
  if (extra.wireSni) parts.push(`wire_sni=${extra.wireSni}`);
  if (extra.encSni) parts.push(`enc_sni=${extra.encSni}`);
  if (extra.originSni) parts.push(`origin_sni=${extra.originSni}`);
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
 * Duplex pipe с backpressure между двумя сокетами.
 * @param {import('stream').Duplex} src
 * @param {import('stream').Duplex} dst
 */
export function pipeDuplexWithBackpressure(src, dst) {
  /** @type {boolean} */
  let srcDrainWait = false;
  src.on('data', (chunk) => {
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (!b.length || dst.writableEnded || dst.writableFinished) return;
    if (!dst.write(b)) {
      src.pause();
      if (!srcDrainWait) {
        srcDrainWait = true;
        dst.once('drain', () => {
          srcDrainWait = false;
          src.resume();
        });
      }
    }
  });
}

/**
 * Exit: raw TCP enc-SNI relay — decrypt SNI, DNS connect, restore CH, pipe.
 * @param {import('net').Socket} mux
 * @param {{
 *   vpnSecretBuf: Buffer,
 *   publicName: string,
 *   logOpts?: TransparentTlsLogOpts|null,
 *   initialBuf?: Buffer,
 *   modeTag?: TransparentTlsModeTag,
 * }} opts
 */
export function wireTransparentTlsEncSniSession(mux, opts) {
  const { vpnSecretBuf, publicName, logOpts } = opts;
  const modeTag = opts.modeTag ?? 'transparent-tls';
  const peer = `${mux.remoteAddress ?? '?'}:${mux.remotePort ?? '?'}`;
  /** @type {Buffer[]} */
  let acc = opts.initialBuf?.length ? [opts.initialBuf] : [];
  let accLen = acc.reduce((n, b) => n + b.length, 0);
  /** @type {import('net').Socket|null} */
  let origin = null;
  /** @type {{ relaySni: string, originHost: string, port: number } | null} */
  let sess = null;
  let clientPrefixDone = false;
  /** @type {Buffer[]} */
  let pendingToOrigin = [];
  let originReady = false;
  let finalized = false;

  const fail = (msg) => {
    if (finalized) return;
    finalized = true;
    console.error('[transparent-tls exit]', msg);
    killPair(mux, origin);
  };

  const startOrigin = (hostname, port, /** @type {Buffer[]} */ firstWrites) => {
    if (logOpts?.tlsLogJa3) {
      console.log(
        `[clean-vpn transparent-tls exit] relay connect: origin=${hostname}:${port} enc_sni=${sess?.relaySni ?? '?'}`,
      );
    }
    pendingToOrigin = firstWrites.filter((b) => b.length);
    origin = net.connect(port, hostname);
    origin.once('close', () => killOne(mux));
    origin.once('connect', () => {
      originReady = true;
      for (const p of pendingToOrigin) {
        if (!(origin.writableEnded || origin.writableFinished)) origin.write(p);
      }
      pendingToOrigin.length = 0;
      if (origin && mux) pipeDuplexWithBackpressure(origin, mux);
    });
    origin.on('error', (err) => {
      console.error('[transparent-tls exit] origin:', err.message);
      killPair(mux, origin);
    });
  };

  const processAccumulated = () => {
    if (finalized || clientPrefixDone) return;
    const buf = Buffer.concat(acc, accLen);
    const parsed = parseFirstTlsClientHelloFromTcpBuf(buf);
    if ('needMore' in parsed && parsed.needMore) return;

    if (!('ok' in parsed) || !parsed.ok || !parsed.sni?.[0]) {
      fail(`ClientHello: ${'reason' in parsed ? parsed.reason : 'parse_fail'}`);
      return;
    }

    const dec = decodeRelayFromHostname(parsed.sni[0], publicName, vpnSecretBuf);
    if (!dec.ok) {
      fail(`enc-SNI: ${dec.reason}`);
      return;
    }

    sess = { relaySni: parsed.sni[0], originHost: dec.hostname, port: dec.port };
    logEncSniWire('exit', modeTag, {
      originSni: sess.originHost,
      encSni: sess.relaySni,
      peer,
      originPort: sess.port,
    });
    if (modeTag === 'combo-tls') {
      logComboTlsExitBranch('transparent', peer, {
        encSni: sess.relaySni,
        originSni: sess.originHost,
      });
    }

    const chPrefix = Buffer.from(buf.subarray(0, parsed.bytesConsumed));
    const tail = Buffer.from(buf.subarray(parsed.bytesConsumed));

    const muxTlsBefore =
      logOpts?.tlsLogJa3 ? Buffer.from(chPrefix) : null;
    const restored = restoreFirstSniInTcpBuffer(chPrefix, sess.relaySni, sess.originHost);
    if (!restored.ok) {
      fail(`restore SNI: ${restored.reason}`);
      return;
    }

    if (logOpts?.tlsLogJa3) {
      console.log(
        `[clean-vpn transparent-tls exit] restore SNI: ${sess.relaySni} → ${sess.originHost}`,
      );
      if (muxTlsBefore) {
        logTransparentTlsClientHelloFingerprints(
          'exit',
          'Mux enc-SNI ClientHello (relay SNI)',
          muxTlsBefore,
          logOpts,
        );
        logTransparentTlsClientHelloFingerprints(
          'exit',
          'К origin: ClientHello после restore',
          restored.prefixBuf,
          logOpts,
        );
      }
    }

    clientPrefixDone = true;
    acc.length = 0;
    accLen = 0;
    startOrigin(sess.originHost, sess.port, [restored.prefixBuf, tail]);
  };

  mux?.once?.('error', () => killPair(mux, origin));
  mux?.once?.('close', () => killOne(origin));

  mux?.on?.('data', (chunk) => {
    if (finalized) return;
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (clientPrefixDone) {
      if (originReady && origin && !(origin.writableEnded || origin.writableFinished)) {
        origin.write(b);
      } else if (!originReady) {
        pendingToOrigin.push(b);
      }
      return;
    }
    acc.push(b);
    accLen += b.length;
    processAccumulated();
  });

  if (accLen) processAccumulated();
}

/**
 * Серверную сторону exit (TCP listen без TUN).
 */
export function runTransparentTlsExitServer(host, listenPort, vpnSecretBuf, publicName) {
  const srv = net.createServer((mux) =>
    wireTransparentTlsEncSniSession(/** @type {import('net').Socket} */ (mux), {
      vpnSecretBuf,
      publicName,
      logOpts: {},
    }),
  );
  srv.listen(listenPort, host, () => {
    console.log(
      `[clean-vpn] transparent-tls exit: enc-SNI relay без TUN, слушаю ${host}:${listenPort}`,
    );
  });
  return srv;
}

/**
 * Client: REDIRECT/TCP → rebuild SNI → raw TCP TLS stream к exit.
 */
export async function attachTransparentTlsClientSession(
  appSock,
  {
    upstreamHost,
    upstreamPort,
    vpnSecretBuf,
    publicName,
    explicitDestination,
    logOpts,
    modeTag,
  },
) {
  const pn = String(publicName || '').trim();
  const mode = modeTag ?? 'transparent-tls';
  if (!pn) {
    throw new Error('transparent-tls: --tls-public-name обязателен для enc-SNI relay');
  }

  appSock.pause();
  const peer = `${appSock.remoteAddress ?? '?'}:${appSock.remotePort ?? '?'}`;
  const upstream = `${upstreamHost}:${upstreamPort}`;
  const dst =
    explicitDestination != null && typeof explicitDestination.address === 'string'
      ? { address: explicitDestination.address, port: explicitDestination.port }
      : ipv4OriginalDestinationFromSock(appSock);
  if (logOpts?.tlsLogJa3 || logOpts?.ja3Verbose) {
    console.log(
      `[clean-vpn transparent-tls client] enc-SNI relay: апстрим ipv4=${dst.address}:${dst.port}; publicName=${pn}`,
    );
  }

  /** @type {Buffer[]} */
  const chunks = [];
  const { prefixBuf, remaining, originHostAscii, relayHostname } = await new Promise(
    (resolve, reject) => {
      const onErr = reject;
      const onEnd = () => onErr(new Error('EOF before first TLS ClientHello is complete'));
      const cleanup = () => {
        appSock.off('data', onData);
        appSock.off('end', onEnd);
        appSock.off('error', onErr);
        appSock.off('close', onEnd);
      };
      function onData(/** @type {Buffer|string} */ piece) {
        chunks.push(Buffer.isBuffer(piece) ? piece : Buffer.from(piece));
        const buf = Buffer.concat(chunks);
        const parsed = parseFirstTlsClientHelloFromTcpBuf(buf);
        if ('needMore' in parsed && parsed.needMore) return;
        cleanup();
        if (!('ok' in parsed) || parsed.ok !== true) {
          reject(new Error(`ClientHello: ${'reason' in parsed ? parsed.reason : 'parse_fail'}`));
          return;
        }
        if (!parsed.sni?.[0]) {
          reject(new Error('нет plaintext SNI (ECH не поддерживается в v1)'));
          return;
        }
        const originHostAscii = parsed.sni[0];
        let relayHostname;
        try {
          const labels = encodeRelaySniLabel(vpnSecretBuf, {
            hostname: originHostAscii,
            port: dst.port,
          });
          relayHostname = buildRelayHostname(labels, pn);
        } catch (e) {
          reject(new Error(`enc-SNI encode: ${/** @type {Error} */ (e).message}`));
          return;
        }

        const tcpBufOriginalBrowser = Buffer.from(buf.subarray(0, parsed.bytesConsumed));
        const wr = replaceFirstSniInTcpBuffer(tcpBufOriginalBrowser, relayHostname);
        if (!wr.ok) {
          reject(new Error(`rebuild SNI (${originHostAscii} → enc): ${wr.reason}`));
          return;
        }

        logEncSniWire('client', mode, {
          originSni: originHostAscii,
          encSni: relayHostname,
          peer,
          upstream,
          originPort: dst.port,
        });
        if (mode === 'combo-tls') {
          logComboTlsClientBranch(
            'transparent',
            `origin_sni=${originHostAscii} enc_sni=${relayHostname} so_orig=${dst.address}:${dst.port}`,
          );
        }

        if (logOpts?.tlsLogJa3) {
          logTransparentTlsClientHelloFingerprints(
            'client',
            'ClientHello браузера (до подмены)',
            tcpBufOriginalBrowser,
            logOpts,
          );
          logTransparentTlsClientHelloFingerprints(
            'client',
            'ClientHello после enc-SNI rebuild (raw TCP к exit)',
            wr.prefixBuf,
            logOpts,
          );
        }

        const remaining = Buffer.from(buf.subarray(parsed.bytesConsumed));
        resolve({
          prefixBuf: wr.prefixBuf,
          remaining,
          originHostAscii,
          relayHostname,
        });
      }
      appSock.on('data', onData);
      appSock.once('end', onEnd);
      appSock.once('error', onErr);
      appSock.once('close', onEnd);
      queueMicrotask(() => {
        try {
          appSock.resume();
        } catch {
          /* ignore */
        }
      });
    },
  );

  const muxSock = /** @type {import('net').Socket} */ (net.connect(upstreamPort, upstreamHost));
  await once(muxSock, 'connect');

  muxSock.write(prefixBuf);
  if (remaining.length) muxSock.write(remaining);

  pipeDuplexWithBackpressure(muxSock, appSock);
  pipeDuplexWithBackpressure(appSock, muxSock);

  muxSock.on?.('error', () => killPair(appSock, muxSock));
  muxSock.on?.('close', () => killOne(appSock));
  appSock.on?.('error', () => killPair(appSock, muxSock));
  appSock.on?.('close', () => killOne(muxSock));
  muxSock.on?.('end', () => appSock?.end?.());
  appSock.on?.('end', () => muxSock?.end?.());
}
