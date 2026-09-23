/** DoH TLS over an in-memory enc-SNI relay. Only the numeric exit is dialled. */
import net from 'node:net';
import tls from 'node:tls';
import https from 'node:https';
import { duplexPair } from 'node:stream';
import { dnsUpstreamSummary, dnsUpstreamTlsOptions } from './dns-upstream-config.mjs';
import { isPublicRelayAddress } from './transparent-tls-destination.mjs';
import { encodeRelayHostname } from './transparent-tls-enc-sni.mjs';
import { attachTransparentTlsClientSession } from './transparent-tls-runtime.mjs';

const targets = new WeakMap();
const invalid = () => Object.assign(new Error('DNS_EXIT_CONFIG'), { code: 'DNS_EXIT_CONFIG' });

function create(options, lab) {
  let profile, exitAddress, exitPort, publicName, secret;
  try {
    ({ profile, exitAddress, exitPort, publicName, secret } = options);
    if (Object.keys(options).some((key) => !['profile', 'exitAddress', 'exitPort', 'publicName', 'secret'].includes(key))) throw invalid();
    const summary = dnsUpstreamSummary(profile); // Rejects unbranded/cloned profiles.
    if (summary.scope !== (lab ? 'loopback-lab' : 'public-contract')) throw invalid();
    if (typeof exitAddress !== 'string' || !(lab ? exitAddress === '127.0.0.1' : isPublicRelayAddress(exitAddress))) throw invalid();
    if (!Number.isInteger(exitPort) || exitPort < 1 || exitPort > 65535) throw invalid();
    if (typeof publicName !== 'string' || publicName.length > 253 || !publicName.includes('.') || net.isIP(publicName)
      || !publicName.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))) throw invalid();
    if (!Buffer.isBuffer(secret) || secret.length !== 32) throw invalid();
    secret = Buffer.from(secret); publicName = publicName.toLowerCase();
    // Check enc-SNI size before creating any listener or connection.
    encodeRelayHostname(secret, { hostname: profile.hostname, port: profile.port }, publicName);
  } catch { throw invalid(); }

  const sockets = new Set(), jobs = new Set();
  let closing = false, closePromise, connections = 0;
  const track = (socket) => {
    sockets.add(socket); socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket)); return socket;
  };
  const agent = new https.Agent({ keepAlive: false, maxSockets: 64, maxTotalSockets: 64, maxCachedSessions: 0 });
  agent.createConnection = () => {
    if (closing) throw invalid();
    const [tlsSide, relaySide] = duplexPair(); track(tlsSide); track(relaySide);
    let secure;
    const destroy = () => { tlsSide.destroy(); relaySide.destroy(); secure?.destroy(); };
    tlsSide.once('close', destroy); relaySide.once('close', destroy);
    try {
      secure = track(tls.connect({ socket: tlsSide, ...dnsUpstreamTlsOptions(profile), ALPNProtocols: ['http/1.1'] }));
      secure.once('close', destroy);
      const job = attachTransparentTlsClientSession(relaySide, {
        vpnSecretBuf: secret, publicName, upstreamHost: exitAddress, upstreamPort: exitPort,
        // Runtime routes by TLS SNI + this port, never by bootstrap IP from the client.
        explicitDestination: { address: profile.addresses[0].address, port: profile.port },
        connectExit: () => {
          if (closing) throw invalid();
          connections++;
          return track(net.connect({ host: exitAddress, port: exitPort, family: net.isIP(exitAddress), autoSelectFamily: false,
            lookup: () => { throw invalid(); } }));
        },
      }).then((session) => session.closed).catch(() => {}).finally(() => { destroy(); jobs.delete(job); });
      jobs.add(job);
      return secure;
    } catch (error) { destroy(); throw error; }
  };
  const transport = Object.freeze({
    close() {
      if (closePromise) return closePromise;
      closing = true;
      closePromise = (async () => {
        const closed = [...sockets].map((socket) => new Promise((resolve) => { socket.once('close', resolve); socket.destroy(); }));
        agent.destroy(); await Promise.all([...closed, ...jobs]); secret.fill(0);
      })();
      return closePromise;
    },
    stats: () => ({ connections, sockets: sockets.size, jobs: jobs.size, closing }),
  });
  targets.set(transport, () => {
    if (closing) throw invalid();
    return { address: profile.hostname, port: profile.port, ...dnsUpstreamTlsOptions(profile),
      authority: profile.authority, path: profile.path, agent };
  });
  return transport;
}

export const createDnsExitTransport = (options) => create(options, false);
/** JS test API only: no JSON or CLI switch can select this scope. */
export const createLabDnsExitTransport = (options) => create(options, true);
export function dnsExitTransportTarget(transport) {
  const get = targets.get(transport); if (!get) throw invalid(); return get();
}
