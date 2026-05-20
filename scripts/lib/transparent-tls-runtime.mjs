/** Режим --type=transparent-tls без TUN (MVP relay). Вызывается из scripts/clean-vpn.js. */

import net from 'net';
import { randomInt } from 'crypto';
import { once } from 'events';
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  decodeVerifyOpen,
  encodeDataFrame,
  encodeOpenFrame,
  OP_DATA,
  randomNonce16,
  TransparentTlsStreamDecoder,
} from './transparent-tls-wire.mjs';
import {
  extractFirstClientHelloBody,
  ja3DebugFromTcpBuf,
  ja3FromTcpBuf,
  parseFirstTlsClientHelloFromTcpBuf,
  parseTlsClientHelloReadableExtensions,
} from './tls-clienthello-ja3.mjs';
import { ja4FromTcpBuf } from './tls-clienthello-ja4.mjs';
import {
  rewriteFirstSniInTcpBuffer,
  restoreFirstSniInTcpBuffer,
} from './transparent-tls-sn-patch.mjs';

/** @typedef {{ tlsLogJa3?: boolean, ja3Verbose?: boolean }} TransparentTlsLogOpts */

/**
 * JA3/JA4 первого ClientHello в TCP-буфере (--tls-log-ja3 / --ja3-verbose как на exit tls).
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
      if (j) console.log(`[clean-vpn transparent-tls ${roleTag}] ${phaseLabel}: ja3_md5=${j.ja3Digest} ja3_sorted_md5=${j.ja3SortedDigest}`);
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

/**
 * Плейсхолдер той же UTF-8 длины, что и реальный SNI (без пересборки длин в handshake).
 * Только [a-z0-9] — достаточно для MVP «иной hostname в ClientHello».
 */
export function randomAsciiHostnameSameUtf8ByteLength(realHostnameAscii) {
  const n = Buffer.byteLength(String(realHostnameAscii), 'utf8');
  if (n < 1 || n > 253) {
    throw new Error(`transparent-tls: длина SNI ${n} вне 1..253`);
  }
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (let i = 0; i < n; i++) {
    s += alphabet[randomInt(alphabet.length)];
  }
  return s;
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
 * Одно TCP-соединение client→exit после accept на exit (без TUN).
 * @param {TransparentTlsLogOpts|null} [logOpts] — `--tls-log-ja3` / `--ja3-verbose`
 */
export function wireTransparentTlsExitSession(mux, vpnSecretBuf, logOpts) {
  const dec = new TransparentTlsStreamDecoder({ maxInnerData: 768 * 1024 });
  /** @type {import('net').Socket|null} */
  let origin = null;
  /** @type {{ fakeHostAscii: string; originHostAscii: string } | null} */
  let sess = null;
  let firstUpstreamFromClient = true;

  /** @type {Buffer[]} */
  let pendingToOrigin = [];
  let originReady = false;

  /** @type {boolean} */
  let pumpStarted = false;

  mux?.once?.('error', () => killPair(mux, origin));
  mux?.once?.('close', () => killOne(origin));

  mux?.on?.('data', (chunk) => {
    try {
      for (const inner of dec.push(chunk)) {
        if (!sess) {
          let meta;
          try {
            meta = decodeVerifyOpen(vpnSecretBuf, inner);
          } catch (e) {
            console.error('[transparent-tls exit] OPEN:', /** @type {Error} */ (e).message);
            killPair(mux, origin);
            return;
          }
          sess = {
            fakeHostAscii: meta.fakeHostAscii,
            originHostAscii: meta.originHostAscii,
          };

          if (logOpts?.tlsLogJa3) {
            console.log(
              `[clean-vpn transparent-tls exit] OPEN: dst_tcp=${meta.ipv4Host}:${meta.port} | origin_sni(в кадре + для upstream)=${meta.originHostAscii} | fake_sni(в теле первого ClientHello по этому mux)=${meta.fakeHostAscii} | байты OPEN на проводе: plaintext+HMAC между client↔этот хост — не AEAD`,
            );
          }

          origin = net.connect(meta.port, meta.ipv4Host);
          origin.once?.('close', () => killOne(mux));
          origin?.once?.('connect', () => {
            originReady = true;
            for (const p of pendingToOrigin) {
              if (!(origin.writableEnded || origin.writableFinished)) origin.write(p);
            }
            pendingToOrigin.length = 0;
            if (!pumpStarted && mux && origin) {
              pumpStarted = true;
              pumpOriginChunksToMux(origin, mux);
            }
          });

          origin?.on?.('error', (err) => {
            console.error('[transparent-tls exit] origin:', err.message);
            killPair(mux, origin);
          });
          continue;
        }

        if (!origin || inner[0] !== OP_DATA) {
          killPair(mux, origin);
          return;
        }

        let plain = Buffer.from(inner.subarray(1));
        if (!plain.length) continue;

        if (firstUpstreamFromClient && sess) {
          firstUpstreamFromClient = false;
          /** Снимок по mux до restore (JA4 содержит fake SNI там, где строка входит в ja4-сегменты). */
          const muxTlsBufBeforeRestore =
            logOpts?.tlsLogJa3 ? Buffer.from(plain) : null;
          const r = restoreFirstSniInTcpBuffer(plain, sess.fakeHostAscii, sess.originHostAscii);
          if (!r.ok) {
            console.error('[transparent-tls exit] restore SNI:', r.reason);
            killPair(mux, origin);
            return;
          }
          if (logOpts?.tlsLogJa3) {
            console.log(
              `[clean-vpn transparent-tls exit] в сокет к origin подставили SNI обратно: relay_sni=${sess.fakeHostAscii} → upstream_sni=${sess.originHostAscii}`,
            );
            if (muxTlsBufBeforeRestore) {
              logTransparentTlsClientHelloFingerprints(
                'exit',
                'Mux CVPTX: ClientHello от клиента (подстановочный SNI в CH)',
                muxTlsBufBeforeRestore,
                logOpts,
              );
              logTransparentTlsClientHelloFingerprints(
                'exit',
                'К origin-серверу: ClientHello после in-place восстановления SNI',
                plain,
                logOpts,
              );
            }
          }
        }

        if (!(origin.writableEnded || origin.writableFinished)) {
          if (originReady) origin.write(plain);
          else pendingToOrigin.push(plain);
        }
      }
    } catch (e) {
      console.error('[transparent-tls exit] протокол:', /** @type {Error} */ (e).message);
      killPair(mux, origin);
    }
  });
}

/**
 * Перекачка origin readable → MUX в кадрах OP_DATA.
 * @param {import('stream').Duplex|null} origin
 * @param {import('net').Socket|null} mux
 */
export function pumpOriginChunksToMux(origin, mux) {
  if (!origin || !mux) return;
  /** @type {boolean} */
  let waitingMuxDrain = false;
  origin.on('data', (chunk) => {
    try {
      const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (!b.length) return;
      if (mux.writableEnded || mux.writableFinished) return;
      const enc = encodeDataFrame(Buffer.from(b));
      if (!mux.write(enc)) {
        if (!waitingMuxDrain) {
          waitingMuxDrain = true;
          mux.once('drain', () => {
            waitingMuxDrain = false;
            origin.resume();
          });
        }
        origin.pause();
      }
    } catch {
      killOne(origin);
    }
  });
}

/**
 * Серверную сторону exit (TCP listen без TUN).
 */
export function runTransparentTlsExitServer(host, listenPort, vpnSecretBuf) {
  const srv = net.createServer((mux) =>
    wireTransparentTlsExitSession(
      /** @type {import('net').Socket} */ (mux),
      vpnSecretBuf,
      {},
    ),
  );
  srv.listen(listenPort, host, () => {
    console.log(
      `[clean-vpn] transparent-tls exit: TCP relay без TUN, слушаю ${host}:${listenPort}`,
    );
  });
  return srv;
}

/**
 * Одно приложенческое соединение: REDIRECT/TCP → patch CH → multiplex к exit VPS.
 */
export async function attachTransparentTlsClientSession(
  appSock,
  {
    upstreamHost,
    upstreamPort,
    vpnSecretBuf,
    /** @type {{ address: string; port: number }|null|undefined} если задано — без SO_ORIGINAL_DST (фиксированный dst, см. `--tunnel-peer` у client) */
    explicitDestination,
    /** @type {TransparentTlsLogOpts|null|undefined} */
    logOpts,
  },
) {
  appSock.pause();
  const dst =
    explicitDestination != null && typeof explicitDestination.address === 'string'
      ? { address: explicitDestination.address, port: explicitDestination.port }
      : ipv4OriginalDestinationFromSock(appSock);
  if (logOpts?.tlsLogJa3 || logOpts?.ja3Verbose) {
    console.log(
      `[clean-vpn transparent-tls client] разбор первого TLS ClientHello: апстрим ${dst.address}:${dst.port}; JA3/JA4 появятся после успешной подмены SNI.`,
    );
  }

  /** @type {Buffer[]} */
  const chunks = [];
  const { prefixBuf, remaining, originHostAscii, fakeHostnameAscii } = await new Promise(
    (resolve, reject) => {
      const onErr = reject;
      const onEnd = () =>
        onErr(new Error('EOF before first TLS ClientHello is complete'));
      /** @type {(...args:any[])=>void} */
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
          reject(new Error('нет plaintext SNI (ECH/MODE не поддерживается в MVP)'));
          return;
        }
        const originHostAscii = parsed.sni[0];
        const fakeHostnameAscii = randomAsciiHostnameSameUtf8ByteLength(originHostAscii);

        /** Копия tcp до патча имени хоста в ClientHello. */
        const tcpBufOriginalBrowser = Buffer.from(buf.subarray(0, parsed.bytesConsumed));
        const prefixBuf = Buffer.from(tcpBufOriginalBrowser);
        const wr = rewriteFirstSniInTcpBuffer(prefixBuf, fakeHostnameAscii);
        if (!wr.ok) {
          reject(new Error(`patch SNI (${originHostAscii} → fake): ${wr.reason}`));
          return;
        }
        if (logOpts?.tlsLogJa3) {
          console.log(
            `[clean-vpn transparent-tls client] ClientHello уже обработан: origin_sni_браузера=${originHostAscii} подставили_sni_в_wire=${fakeHostnameAscii} ipv4_tls_dst_so_orig=${dst.address}:${dst.port}`,
          );
          logTransparentTlsClientHelloFingerprints(
            'client',
            'ClientHello браузера (до подмены, копия tcp)',
            tcpBufOriginalBrowser,
            logOpts,
          );
          logTransparentTlsClientHelloFingerprints(
            'client',
            'ClientHello после in-place подмены SNI (в OP_DATA до exit виден этот байтовый образ)',
            prefixBuf,
            logOpts,
          );
        }

        const remaining = Buffer.from(buf.subarray(parsed.bytesConsumed));
        resolve({ prefixBuf, remaining, originHostAscii, fakeHostnameAscii });
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

  /** @type {import('stream').Duplex|null} */
  const muxSock = /** @type {any} */ (net.connect(upstreamPort, upstreamHost));
  await once(muxSock, 'connect');

  const nonce = randomNonce16();
  muxSock.write(encodeOpenFrame(vpnSecretBuf, nonce, dst, originHostAscii, fakeHostnameAscii));
  muxSock.write(encodeDataFrame(prefixBuf));
  if (remaining.length) muxSock.write(encodeDataFrame(remaining));

  if (logOpts?.tlsLogJa3) {
    console.warn(
      `[clean-vpn transparent-tls client] CVPTX: кадр OPEN + первые OP_DATA идут на exit по открытому TCP (только целостность HMAC у OPEN); поля origin_sni, fake_sni из OPEN и байты патченного ClientHello читаются пассивно на этом участке.`,
    );
  }

  const muxDec = new TransparentTlsStreamDecoder({ maxInnerData: 768 * 1024 });
  muxSock.on?.('data', (raw) => {
    try {
      const inners = muxDec.push(raw);
      /** @type {number} */
      let i = 0;
      const pumpInnerPayloadsToApp = () => {
        for (;;) {
          if (i >= inners.length) return;
          const inner = inners[i];
          if (inner[0] !== OP_DATA) {
            i += 1;
            continue;
          }
          const pl = Buffer.from(inner.subarray(1));
          if (!pl.length) {
            i += 1;
            continue;
          }
          if (appSock.writableEnded || appSock.writableFinished) return;
          if (!appSock.write(pl)) {
            muxSock.pause();
            appSock.once('drain', () => {
              muxSock.resume();
              pumpInnerPayloadsToApp();
            });
            return;
          }
          i += 1;
        }
      };
      pumpInnerPayloadsToApp();
    } catch {
      killPair(appSock, muxSock);
    }
  });
  muxSock.on?.('error', () => killPair(appSock, muxSock));
  muxSock.on?.('close', () => killOne(appSock));
  appSock.on?.('error', () => killPair(appSock, muxSock));
  appSock.on?.('close', () => killOne(muxSock));
  /** Избежать множества обработчиков drain при нескольких appSock chunks подряд. */
  /** @type {boolean} */
  let muxDrainWait = false;
  appSock.on?.('data', (d) => {
    const enc = encodeDataFrame(Buffer.from(d));
    if (!(muxSock.writableEnded || muxSock.writableFinished)) {
      if (!muxSock.write(enc)) {
        appSock.pause();
        if (!muxDrainWait) {
          muxDrainWait = true;
          muxSock.once('drain', () => {
            muxDrainWait = false;
            appSock.resume();
          });
        }
      }
    }
  });

  muxSock.on?.('end', () => appSock?.end?.());
  appSock.on?.('end', () => muxSock?.end?.());
}
