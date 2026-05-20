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
import { parseFirstTlsClientHelloFromTcpBuf } from './tls-clienthello-ja3.mjs';
import {
  rewriteFirstSniInTcpBuffer,
  restoreFirstSniInTcpBuffer,
} from './transparent-tls-sn-patch.mjs';

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
 */
export function wireTransparentTlsExitSession(mux, vpnSecretBuf) {
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
          const r = restoreFirstSniInTcpBuffer(plain, sess.fakeHostAscii, sess.originHostAscii);
          if (!r.ok) {
            console.error('[transparent-tls exit] restore SNI:', r.reason);
            killPair(mux, origin);
            return;
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
  const loop = () => {
    /** @type {Buffer|null|string} */
    let d;
    for (;;) {
      d = origin.read();
      if (d === null) return;
      let b = Buffer.isBuffer(d) ? d : Buffer.from(d);
      if (!b.length) continue;
      const enc = encodeDataFrame(Buffer.from(b));
      if (!(mux.writableEnded || mux.writableFinished)) {
        if (!mux.write(enc)) {
          mux.once('drain', () => {
            origin.resume();
            loop();
          });
          origin.pause();
          return;
        }
      }
    }
  };
  origin.on('readable', loop);
  loop();
}

/**
 * Серверную сторону exit (TCP listen без TUN).
 */
export function runTransparentTlsExitServer(host, listenPort, vpnSecretBuf) {
  const srv = net.createServer((mux) =>
    wireTransparentTlsExitSession(/** @type {import('net').Socket} */ (mux), vpnSecretBuf),
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
  },
) {
  appSock.pause();
  const dst =
    explicitDestination != null && typeof explicitDestination.address === 'string'
      ? { address: explicitDestination.address, port: explicitDestination.port }
      : ipv4OriginalDestinationFromSock(appSock);

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

        const prefixBuf = Buffer.from(buf.subarray(0, parsed.bytesConsumed));
        const wr = rewriteFirstSniInTcpBuffer(prefixBuf, fakeHostnameAscii);
        if (!wr.ok) {
          reject(new Error(`patch SNI (${originHostAscii} → fake): ${wr.reason}`));
          return;
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

  const muxDec = new TransparentTlsStreamDecoder({ maxInnerData: 768 * 1024 });
  muxSock.on?.('data', (raw) => {
    try {
      for (const inner of muxDec.push(raw)) {
        if (inner[0] !== OP_DATA) continue;
        const pl = Buffer.from(inner.subarray(1));
        if (!(appSock.writableEnded || appSock.writableFinished)) appSock.write(pl);
      }
    } catch {
      killPair(appSock, muxSock);
    }
  });
  muxSock.on?.('error', () => killPair(appSock, muxSock));
  muxSock.on?.('close', () => killOne(appSock));
  appSock.on?.('error', () => killPair(appSock, muxSock));
  appSock.on?.('close', () => killOne(muxSock));
  appSock.on?.('data', (d) =>
    muxSock.write(encodeDataFrame(Buffer.from(d))),
  );

  muxSock.on?.('end', () => appSock?.end?.());
  appSock.on?.('end', () => muxSock?.end?.());
}
