#!/usr/bin/env node
/**
 * Локальный HTTPS-сервер: снимает ClientHello с сырого TCP (как mux на exit),
 * считает JA3 и «wireshark-поля», затем завершает TLS и отдаёт JSON по GET /ja3-snif.
 *
 * Сервер объявляет только ALPN http/1.1 (без h2), чтобы после рукопожатия разобрать
 * запрос как HTTP/1.1; предложенные клиентом ALPN в ClientHello всё равно попадают в JSON.
 *
 * Запуск из корня репо:
 *   node scripts/ja3-snif-server.mjs
 *   node scripts/ja3-snif-server.mjs --host=127.0.0.1 --port=8443
 *
 * В браузере (примите предупреждение о самоподписанном сертификате):
 *   https://127.0.0.1:8443/ja3-snif
 *
 * PEM по умолчанию: scripts/fixtures/boring-tls-local.* (как smoke-тест helper).
 * Свои: --cert=PATH --key=PATH или JA3_SNIF_CERT / JA3_SNIF_KEY.
 */
import fs from 'fs';
import net from 'net';
import path from 'path';
import tls from 'tls';
import { fileURLToPath } from 'url';
import {
  atomicWriteJsonFileSync,
  buildCompactProfileDocument,
} from './lib/boring-tls-clienthello-profile.mjs';
import {
  tlsClientHandshakeProfileWithJa4FromTcpBuf,
} from './lib/tls-clienthello-ja4.mjs';
import {
  parseFirstTlsClientHelloFromTcpBuf,
} from './lib/tls-clienthello-ja3.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(__dirname, '..');
const DEF_CERT = path.join(repoRoot, 'scripts/fixtures/boring-tls-local.cert.pem');
const DEF_KEY = path.join(repoRoot, 'scripts/fixtures/boring-tls-local.key.pem');

const ROUTE = '/ja3-snif';

function parseArgs(argv) {
  /** @type {{ host: string, port: number, cert: string, key: string, hexLen: number, profileSavePath: string|null }} */
  const out = {
    host: '0.0.0.0',
    port: 8443,
    cert: process.env.JA3_SNIF_CERT || DEF_CERT,
    key: process.env.JA3_SNIF_KEY || DEF_KEY,
    hexLen: 96,
    profileSavePath:
      process.env.JA3_SNIF_PROFILE_SAVE_PATH?.trim() || null,
  };
  for (const a of argv) {
    if (a.startsWith('--host=')) out.host = a.slice('--host='.length).trim();
    else if (a.startsWith('--port=')) out.port = parseInt(a.slice('--port='.length), 10);
    else if (a.startsWith('--cert=')) out.cert = path.resolve(a.slice('--cert='.length).trim());
    else if (a.startsWith('--key=')) out.key = path.resolve(a.slice('--key='.length).trim());
    else if (a.startsWith('--hex-preview-len=')) {
      out.hexLen = parseInt(a.slice('--hex-preview-len='.length), 10);
    } else if (a.startsWith('--profile-save-path=')) {
      const p = a.slice('--profile-save-path='.length).trim();
      out.profileSavePath = p ? path.resolve(p) : null;
    }
  }
  if (!Number.isFinite(out.port) || out.port < 1 || out.port > 65535) {
    throw new Error('неверный --port');
  }
  if (!Number.isFinite(out.hexLen) || out.hexLen < 0 || out.hexLen > 4096) {
    throw new Error('неверный --hex-preview-len');
  }
  return out;
}

/**
 * @param {string} statusLine
 * @param {Record<string, string>} headers
 * @param {string} body
 */
function httpMessage(statusLine, headers, body) {
  const h = Object.entries({ Connection: 'close', ...headers })
    .map(([k, v]) => `${k}: ${v}`)
    .join('\r\n');
  return `${statusLine}\r\n${h}\r\n\r\n${body}`;
}

/**
 * @param {string} headText
 * @param {string} name
 */
function headerValue(headText, name) {
  const want = name.toLowerCase();
  for (const line of headText.split('\r\n').slice(1)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const k = line.slice(0, idx).trim().toLowerCase();
    if (k === want) return line.slice(idx + 1).trim();
  }
  return '';
}

/**
 * @param {import('tls').TLSSocket} sock
 */
function readHttpHead(sock, maxBytes = 65536, ms = 20000) {
  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */
    const chunks = [];
    let total = 0;
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('timeout ожидания HTTP-заголовков'));
    }, ms);

    const cleanup = () => {
      clearTimeout(timer);
      sock.off('data', onData);
    };

    const onData = (c) => {
      chunks.push(c);
      total += c.length;
      if (total > maxBytes) {
        cleanup();
        reject(new Error('слишком большие HTTP-заголовки'));
        return;
      }
      const buf = Buffer.concat(chunks);
      const needle = Buffer.from('\r\n\r\n');
      const pos = buf.indexOf(needle);
      if (pos !== -1) {
        cleanup();
        resolve({
          headText: buf.subarray(0, pos).toString('latin1'),
          rest: buf.subarray(pos + needle.length),
        });
      }
    };

    sock.on('data', onData);
    sock.once('error', (e) => {
      cleanup();
      reject(e);
    });
  });
}

/**
 * @param {import('net').Socket} socket
 * @param {tls.SecureContext} secureContext
 * @param {{ hexLen: number, profileSavePath: string|null }} opts
 */
function handleInbound(socket, secureContext, opts) {
  /** @type {Buffer[]} */
  const chunks = [];
  const helloDeadline = setTimeout(() => {
    try {
      socket.destroy();
    } catch {
      /* ignore */
    }
  }, 30000);
  helloDeadline.unref?.();

  const failTcp = (reason) => {
    clearTimeout(helloDeadline);
    try {
      socket.destroy();
    } catch {
      /* ignore */
    }
    console.error('[ja3-snif] tcp:', reason);
  };

  const onData = (c) => {
    chunks.push(c);
    const buf = Buffer.concat(chunks);
    const p = parseFirstTlsClientHelloFromTcpBuf(buf);
    if ('needMore' in p && p.needMore) return;

    clearTimeout(helloDeadline);
    socket.off('data', onData);
    const fullBuf = Buffer.concat(chunks);

    if (!('ok' in p) || !p.ok) {
      failTcp(`ClientHello parse: ${p.reason || 'fail'}`);
      return;
    }

    const profile = tlsClientHandshakeProfileWithJa4FromTcpBuf(fullBuf, {
      hexPreviewLen: opts.hexLen,
    });
    if (!profile.ok) {
      failTcp(`profile: ${profile.reason}`);
      return;
    }

    try {
      socket.pause();
    } catch {
      /* ignore */
    }

    const tlsSock = new tls.TLSSocket(socket, {
      isServer: true,
      secureContext,
      ALPNProtocols: ['http/1.1'],
      requestCert: false,
      handshakeTimeout: 60000,
    });

    tlsSock.once('secure', () => {
      const negotiated =
        tlsSock.alpnProtocol === false ? '' : String(tlsSock.alpnProtocol || '');
      const peer = `${socket.remoteAddress ?? '?'}:${socket.remotePort ?? '?'}`;

      readHttpHead(tlsSock)
        .then(({ headText }) => {
          const first = headText.split('\r\n')[0] || '';
          const m = first.match(/^([A-Z]+)\s+(\S+)\s+HTTP\/\d+\.\d+\s*$/);
          const method = m ? m[1] : '';
          const reqPath = m ? m[2] : '';
          const ua = headerValue(headText, 'user-agent');

          const base = {
            meta: {
              path: ROUTE,
              note:
                'Поля tls / ja3 (wire) / ja3_sorted / ja4 / wire — из ClientHello до TLS на TCP. User-Agent — из первого HTTP-запроса после рукопожатия. Сервер предлагает только ALPN http/1.1; предложенный клиентом ALPN — tls_observed_in_clienthello.offered_alpn_protocols.',
            },
            http: {
              user_agent: ua || null,
              method: method || null,
              request_target: reqPath || null,
              request_line: first || null,
            },
            tls_observed_in_clienthello: profile.tls,
            ja3: profile.ja3,
            ja3_sorted: profile.ja3_sorted,
            ja4: profile.ja4,
            wire: {
              ...profile.wire,
              tcp_bytes_accumulated_for_clienthello: fullBuf.length,
            },
            tls_after_handshake: {
              negotiated_alpn: negotiated || null,
              tls_version_line:
                typeof tlsSock.getProtocol === 'function' ? tlsSock.getProtocol() : null,
            },
          };

          const jsonBody = JSON.stringify(base, null, 2);
          const cors = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json; charset=utf-8',
          };

          if (method === 'OPTIONS') {
            tlsSock.end(
              httpMessage('HTTP/1.1 204 No Content', {
                ...cors,
                'Access-Control-Allow-Methods': 'GET, OPTIONS',
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Max-Age': '86400',
              }, ''),
            );
            console.log(`[ja3-snif] OPTIONS ${peer} → 204`);
            return;
          }

          if (method !== 'GET' || reqPath !== ROUTE) {
            const errBody = JSON.stringify(
              {
                error: 'expected GET ' + ROUTE,
                got: { method: method || null, path: reqPath || null },
              },
              null,
              2,
            );
            tlsSock.end(
              httpMessage(
                'HTTP/1.1 404 Not Found',
                {
                  ...cors,
                  'Content-Type': 'application/json; charset=utf-8',
                  'Content-Length': String(Buffer.byteLength(errBody)),
                },
                errBody,
              ),
            );
            console.log(`[ja3-snif] ${method} ${reqPath} ${peer} → 404`);
            return;
          }

          tlsSock.end(
            httpMessage(
              'HTTP/1.1 200 OK',
              {
                ...cors,
                'Content-Length': String(Buffer.byteLength(jsonBody)),
              },
              jsonBody,
            ),
          );
          console.log(
            `[ja3-snif] GET ${ROUTE} ${peer} ja3=${profile.ja3.md5} ja3_sorted=${profile.ja3_sorted.md5} ja4=${profile.ja4 && profile.ja4.fingerprint ? profile.ja4.fingerprint : '?'}`,
          );

          if (opts.profileSavePath) {
            try {
              const doc = buildCompactProfileDocument(profile, ua || '');
              atomicWriteJsonFileSync(opts.profileSavePath, doc);
              console.log(`[ja3-snif] profile saved → ${opts.profileSavePath}`);
            } catch (e) {
              console.error('[ja3-snif] profile save failed:', e?.message || e);
            }
          }
        })
        .catch((e) => {
          console.error('[ja3-snif] http:', e?.message || e);
          try {
            tlsSock.destroy();
          } catch {
            /* ignore */
          }
        });
    });

    tlsSock.on('error', (e) => {
      console.error('[ja3-snif] tls:', e?.message || e);
      try {
        tlsSock.destroy();
      } catch {
        /* ignore */
      }
    });

    socket.unshift(fullBuf);
    try {
      socket.resume();
    } catch {
      /* ignore */
    }
  };

  socket.on('data', onData);
  socket.on('error', (e) => failTcp(e?.message || String(e)));
  socket.on('close', () => {
    clearTimeout(helloDeadline);
  });
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(`Использование: node scripts/ja3-snif-server.mjs [опции]
  --host=127.0.0.1   --port=8443
  --cert=PATH        --key=PATH   (или JA3_SNIF_CERT / JA3_SNIF_KEY)
  --hex-preview-len=96
  --profile-save-path=PATH   компактный JSON профиля после GET /ja3-snif (или JA3_SNIF_PROFILE_SAVE_PATH)
Откройте в браузере: https://127.0.0.1:8443/ja3-snif`);
    process.exit(0);
  }

  const cfg = parseArgs(argv);
  if (!fs.existsSync(cfg.cert) || !fs.existsSync(cfg.key)) {
    console.error(
      `[ja3-snif] Нет PEM: cert=${cfg.cert} key=${cfg.key}. Положите ключи или задайте --cert/--key.`,
    );
    process.exit(1);
  }

  const secureContext = tls.createSecureContext({
    cert: fs.readFileSync(cfg.cert),
    key: fs.readFileSync(cfg.key),
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
  });

  const srv = net.createServer((sock) =>
    handleInbound(sock, secureContext, {
      hexLen: cfg.hexLen,
      profileSavePath: cfg.profileSavePath,
    }),
  );

  srv.listen(cfg.port, cfg.host, () => {
    console.log(
      `[ja3-snif] слушаем https://${cfg.host}:${cfg.port}${ROUTE} (TLS 1.2–1.3, ALPN сервера: http/1.1)`,
    );
  });

  srv.on('error', (e) => {
    console.error('[ja3-snif]', e?.message || e);
    process.exit(1);
  });
}

main();
