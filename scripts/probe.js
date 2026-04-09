#!/usr/bin/env node
/**
 * Проверка реакции exit на TLS passthrough (active probing): ClientHello без clean-vpn-tls,
 * с ALPN clean-vpn-probe (маркер для логов probeTool=true на exit).
 *
 * Usage:
 *   node scripts/probe.js --type=handshake --server=EXIT:443 --domain=www.google.com:443
 *   node scripts/probe.js --type=full --server=EXIT:443 --domain=www.google.com:443 [--timeout=15000]
 *
 * --domain host:port должен совпадать с --tls-probe-target на exit (по умолчанию www.google.com:443).
 * Не используйте SNI, совпадающий с --tls-public-name на exit — трафик уйдёт на публичный TLS, не passthrough.
 */

import tls from 'tls';
import process from 'process';

/** Должен совпадать с TLS_ALPN_PROBE в scripts/clean-vpn.js */
const TLS_ALPN_PROBE = 'clean-vpn-probe';

function parseArgs(argv) {
  const out = {
    type: null,
    server: null,
    domain: null,
    timeout: 15000,
  };
  for (const a of argv) {
    if (a.startsWith('--type=')) out.type = a.slice('--type='.length);
    else if (a.startsWith('--server=')) out.server = a.slice('--server='.length);
    else if (a.startsWith('--domain=')) out.domain = a.slice('--domain='.length);
    else if (a.startsWith('--timeout=')) {
      const n = parseInt(a.slice('--timeout='.length), 10);
      if (Number.isFinite(n) && n > 0) out.timeout = n;
    }
  }
  return out;
}

function parseHostPort(s, label) {
  const m = String(s).match(/^(.+):(\d+)$/);
  if (!m) throw new Error(`Неверный ${label}=${s}, ожидается host:port`);
  return { host: m[1], port: parseInt(m[2], 10) };
}

/**
 * @param {{ type: string, server: string, domain: string, timeout: number }} args
 * @returns {Promise<boolean>}
 */
function runProbe(args) {
  const { host: exitHost, port: exitPort } = parseHostPort(args.server, '--server');
  const { host: sniHost } = parseHostPort(args.domain, '--domain');
  const timeout = args.timeout;

  return new Promise((resolve) => {
    let settled = false;
    function done(ok) {
      if (settled) return;
      settled = true;
      resolve(ok);
    }

    const sock = tls.connect({
      host: exitHost,
      port: exitPort,
      servername: sniHost,
      ALPNProtocols: [TLS_ALPN_PROBE, 'http/1.1'],
      rejectUnauthorized: false,
    });

    const timer = setTimeout(() => {
      try {
        sock.destroy();
      } catch {
        /* ignore */
      }
      done(false);
    }, timeout);

    sock.once('secureConnect', () => {
      clearTimeout(timer);
      if (args.type === 'handshake') {
        try {
          sock.end();
        } catch {
          /* ignore */
        }
        done(true);
        return;
      }

      const req = `GET / HTTP/1.1\r\nHost: ${sniHost}\r\nConnection: close\r\n\r\n`;
      try {
        sock.write(req);
      } catch {
        done(false);
        return;
      }

      let acc = Buffer.alloc(0);
      const readTimer = setTimeout(() => {
        try {
          sock.destroy();
        } catch {
          /* ignore */
        }
        done(false);
      }, timeout);

      const onError = () => {
        clearTimeout(readTimer);
        sock.off('data', onData);
        sock.off('close', onClose);
        done(false);
      };
      const onClose = () => {
        clearTimeout(readTimer);
        sock.off('data', onData);
        sock.off('error', onError);
        done(false);
      };
      const onData = (chunk) => {
        acc = Buffer.concat([acc, chunk]);
        if (acc.indexOf('HTTP/') !== -1) {
          clearTimeout(readTimer);
          sock.off('data', onData);
          sock.off('error', onError);
          sock.off('close', onClose);
          try {
            sock.end();
          } catch {
            /* ignore */
          }
          done(true);
        }
      };
      sock.on('data', onData);
      sock.once('error', onError);
      sock.once('close', onClose);
    });

    sock.once('error', () => {
      clearTimeout(timer);
      done(false);
    });
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.type || !args.server || !args.domain) {
    console.error(
      'Usage: node scripts/probe.js --type=handshake|full --server=HOST:PORT --domain=HOST:PORT [--timeout=ms]',
    );
    process.exit(2);
  }
  if (args.type !== 'handshake' && args.type !== 'full') {
    console.error('Invalid --type (use handshake or full)');
    process.exit(2);
  }

  try {
    parseHostPort(args.server, '--server');
    parseHostPort(args.domain, '--domain');
  } catch (e) {
    console.error(e?.message || e);
    process.exit(2);
  }

  const ok = await runProbe(args);
  console.log(ok ? 'RESULT ok' : 'RESULT not ok');
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e?.message || e);
  console.log('RESULT not ok');
  process.exit(1);
});
