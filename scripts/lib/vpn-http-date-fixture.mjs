/** Test-only extraction of actual CLI TLS/Bearer/HTTP functions; no main(), TUN or host writes. */
import fs from 'node:fs';
import { runInNewContext } from 'node:vm';
import assert from 'node:assert/strict';
import { createHmac, timingSafeEqual } from 'node:crypto';
import net from 'node:net';
import tls from 'node:tls';
import http2 from 'node:http2';
import { once } from 'node:events';
import { createHttpDateRecovery, CLOCK_UPDATED, responseHeaders, vpnResponseAccepted } from './vpn-http-date.mjs';

const source = fs.readFileSync(new URL('../clean-vpn.js', import.meta.url), 'utf8');
const names = ['computeTlsVpnBearerToken', 'verifyTlsVpnBearerToken', 'tlsVpnExporterFromSocket',
  'tlsVpnBearerFromAuthorizationHeader', 'mapCoverOutcomeFromParts', 'mapCoverOutcome', 'parseHttpRequestForVpn',
  'tlsPreviewHex16', 'tlsPeerTuple', 'tlsAlpnToHttpLabel', 'http2StreamToSocketLike', 'wireExitTlsSocket',
  'wireExitHttp2VpnInjected', 'establishCleanVpnOverH2', 'completeCleanVpnTlsSession', 'connectCleanVpnTlsClient',
  'resolveTlsAlpnProtocols'];
const functions = names.map(name => {
  const start = source.search(new RegExp(`^(?:async )?function ${name}\\(`, 'm'));
  const end = source.indexOf('\n}', start) + 2;
  assert.ok(start > 0 && end > start, name); return source.slice(start, end);
}).join('\n');
const constants = ['TLS_VPN_TOKEN_WINDOW_MS', 'TLS_VPN_TOKEN_CONTEXT_V1', 'TLS_VPN_TOKEN_CONTEXT_V2',
  'TLS_VPN_EXPORTER_LABEL', 'TLS_VPN_EXPORTER_LEN', 'TLS_VPN_USER_AGENT', 'TLS_VPN_CIPHERS_1_3',
  'TLS_VPN_ECDH_CURVES', 'TLS_ALPN_HTTP1_ONLY', 'TLS_ALPN_PREFER_H2', 'TLS_HTTP_WORKS_BODY', 'TLS_CLIENT_HANDSHAKE_MS']
  .map(name => { const match = source.match(new RegExp(`const ${name} =[\\s\\S]*?;\\n`)); assert.ok(match, name); return match[0]; }).join('\n');

export function loadTlsDateFixture({ wall = Date.now, recovery, logs = [] } = {}) {
  class Clock extends Date { constructor(...args) { super(...(args.length ? args : [wall()])); } static now() { return wall(); } }
  const noop = () => {};
  return runInNewContext(`${constants}\n${functions}\n({${names.join(',')}})`, {
    Buffer, Date: Clock, setTimeout, clearTimeout, setImmediate, net, tls, http2, createHmac, timingSafeEqual,
    console: { log: s => logs.push(s), warn: s => logs.push(s), error: s => logs.push(s) },
    tlsHttpDateRecovery: recovery ?? createHttpDateRecovery({ windowMs: 900000, wall, setClock: () => { throw Error('fixture refuses real clock write'); }, log: noop }),
    CLOCK_UPDATED, responseHeaders, vpnResponseAccepted, IPV6_HEADER: 'x-clean-vpn-ipv6',
    tlsLogBearerDebug: noop, tlsMuxDebugEnabled: () => false,
    tlsClientIp: s => s.remoteAddress, tlsCoverShouldThrottle: () => false,
    applyCleanVpnTlsTcpBuffers: noop, applyCleanVpnHttp2ConnWindow: noop,
    applyCleanVpnHttp2StreamWindow: noop, resolveCleanVpnHttp2Settings: () => ({}),
    TCP_BENIGN_AFTER_DATA_CODES: new Set(),
  });
}

export const fixtureCert = fs.readFileSync(new URL('../fixtures/boring-tls-local.cert.pem', import.meta.url));
const fixtureKey = fs.readFileSync(new URL('../fixtures/boring-tls-local.key.pem', import.meta.url));

export async function startDateExit({ protocol, secret, wall = Date.now, onBridge = () => {}, logs = [] }) {
  const api = loadTlsDateFixture({ wall, logs });
  const options = { key: fixtureKey, cert: fixtureCert, minVersion: 'TLSv1.3', ALPNProtocols: [protocol] };
  const sockets = new Set(); let accepts = 0, bridges = 0;
  const startBridge = sock => { bridges++; onBridge(sock); };
  let h2;
  const server = protocol === 'h2' ? net.createServer(sock => {
    api.wireExitHttp2VpnInjected(sock, Buffer.alloc(0), { vpnSecret: secret, tlsExitHttp2Server: h2, startBridge });
  }) : tls.createServer(options, sock => api.wireExitTlsSocket(sock, { vpnSecret: secret, startBridge }));
  if (protocol === 'h2') { h2 = http2.createSecureServer(options); h2.on('sessionError', () => {}); }
  server.on('connection', sock => { accepts++; sockets.add(sock); sock.once('close', () => sockets.delete(sock)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return { port: server.address().port, accepts: () => accepts, bridges: () => bridges, logs,
    async close() { for (const sock of sockets) sock.destroy(); await new Promise(r => server.close(r)); h2?.close(); } };
}
