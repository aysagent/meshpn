/** Application-level exit admission. No firewall, routing or client DNS changes. */
import dns from 'node:dns/promises';
import net from 'node:net';
import { relayError } from './transparent-tls-io.mjs';

// Conservative public-unicast policy, based on IANA special-purpose registries.
// Some globally reachable special-use exceptions are intentionally excluded.
const excluded4 = new net.BlockList();
for (const [address, bits] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3],
]) excluded4.addSubnet(address, bits, 'ipv4');
const global6 = new net.BlockList();
global6.addSubnet('2000::', 3, 'ipv6');
const excluded6 = new net.BlockList();
for (const [address, bits] of [
  ['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20],
]) excluded6.addSubnet(address, bits, 'ipv6');

export function isPublicRelayAddress(address) {
  if (typeof address !== 'string' || address.includes('%')) return false;
  const family = net.isIP(address);
  if (family === 4) return !excluded4.check(address, 'ipv4');
  // Also excludes mapped/compatible IPv4, NAT64, ULA, link-local, multicast,
  // unspecified and future allocations outside the current global-unicast /3.
  return family === 6 && global6.check(address, 'ipv6') && !excluded6.check(address, 'ipv6');
}

function validRoute(hostname, port) {
  return typeof hostname === 'string' && hostname.length <= 253 && hostname.length > 0
    && hostname.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))
    && Number.isInteger(port) && port >= 1 && port <= 65535;
}

export const EXIT_DNS_MAX_PENDING = 64;
export const EXIT_DNS_MAX_ANSWERS = 64;

export class ExitDestinationPolicy {
  #lookup;
  #loopback;
  #pending = 0;

  constructor({ lookup = (...args) => dns.lookup(...args), loopback } = {}) {
    if (typeof lookup !== 'function' || (loopback !== undefined
      && (!loopback || !validRoute(loopback.hostname, loopback.port)))) {
      throw relayError('TLS_RELAY_CONFIG', 'invalid destination policy');
    }
    this.#lookup = lookup;
    // Explicit test-only pin; never a wildcard permission for private networks.
    this.#loopback = loopback === undefined ? undefined : Object.freeze({ ...loopback });
  }

  async resolve(hostname, port) {
    if (!validRoute(hostname, port)) throw relayError('TLS_RELAY_DESTINATION');
    if (this.#loopback) {
      if (hostname !== this.#loopback.hostname || port !== this.#loopback.port) throw relayError('TLS_RELAY_DESTINATION');
      return Object.freeze({ address: '127.0.0.1', family: 4, port });
    }
    if (net.isIP(hostname)) {
      if (!isPublicRelayAddress(hostname)) throw relayError('TLS_RELAY_DESTINATION');
      return Object.freeze({ address: hostname, family: 4, port });
    }
    // No resolver search domains, local aliases, or legacy numeric IP syntax.
    if (!hostname.includes('.') || /^(?:0x[\da-f]+|\d+)(?:\.(?:0x[\da-f]+|\d+))*$/i.test(hostname)
      || /(?:^|\.)(?:localhost|local|internal|home\.arpa)$/i.test(hostname)) {
      throw relayError('TLS_RELAY_DESTINATION');
    }
    if (this.#pending >= EXIT_DNS_MAX_PENDING) throw relayError('TLS_RELAY_DNS_BUSY');
    this.#pending++;
    let answers;
    try {
      // Absolute name prevents OS search-suffix expansion. One lookup, both
      // families; inspect ALL answers before selecting a numeric destination.
      answers = await this.#lookup(`${hostname}.`, { all: true, verbatim: true });
    } catch {
      throw relayError('TLS_RELAY_DNS');
    } finally {
      // OS getaddrinfo cannot reliably be cancelled. Keep its budget occupied
      // until it really settles, even after the owning session timed out.
      this.#pending--;
    }
    if (!Array.isArray(answers) || !answers.length || answers.length > EXIT_DNS_MAX_ANSWERS) throw relayError('TLS_RELAY_DNS');
    if (!answers.every((entry) => entry && entry.family === net.isIP(entry.address)
      && isPublicRelayAddress(entry.address))) throw relayError('TLS_RELAY_DESTINATION');
    const { address, family } = answers[0];
    return Object.freeze({ address, family, port });
  }
}

export const defaultExitDestinationPolicy = new ExitDestinationPolicy();

/** One deadline covers DNS + TCP. Abort/late DNS must never open a new socket. */
export async function connectRelayDestination(session, policy, hostname, port, connector) {
  session.check();
  session.state = 'connecting';
  const cancel = session.timer(session.limits.connectTimeoutMs, () => session.fail(relayError('TLS_RELAY_CONNECT_TIMEOUT')));
  let aborted;
  const abort = new Promise((_, reject) => {
    aborted = () => reject(session.signal.reason);
    session.signal.addEventListener('abort', aborted, { once: true });
  });
  try {
    const target = await Promise.race([policy.resolve(hostname, port), abort]);
    session.check();
    const socket = await session.connect(() => connector
      ? connector(target.address, target.port, target.family)
      : net.connect({ host: target.address, port: target.port, family: target.family, autoSelectFamily: false }));
    session.check();
    // Defence against accidental connector re-resolution or a wrong test pin.
    const allowed = new net.BlockList();
    allowed.addAddress(target.address, target.family === 4 ? 'ipv4' : 'ipv6');
    const peerFamily = net.isIP(socket.remoteAddress);
    if (!peerFamily || socket.remotePort !== target.port || socket.remoteAddress.includes('%')
      || !allowed.check(socket.remoteAddress, peerFamily === 4 ? 'ipv4' : 'ipv6')) {
      throw relayError('TLS_RELAY_DESTINATION_PEER');
    }
    return socket;
  } finally {
    cancel();
    session.signal.removeEventListener('abort', aborted);
  }
}
