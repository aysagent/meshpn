/** Offline DoH identity/bootstrap contract. Does not dial or change exit routing. */
import net from 'node:net';
import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { isPublicRelayAddress } from './transparent-tls-destination.mjs';

export const DNS_UPSTREAM_CONFIG_MAX_BYTES = 128 * 1024;
const compiled = new WeakSet();
const fail = () => { throw Object.assign(new Error('DNS_UPSTREAM_CONFIG'), { code: 'DNS_UPSTREAM_CONFIG' }); };
const requireValue = (value) => { if (!value) fail(); };
function fields(value, names) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype);
  requireValue(Reflect.ownKeys(value).length === names.length);
  for (const name of names) requireValue(Object.getOwnPropertyDescriptor(value, name)?.value !== undefined);
}
function hostname(value, lab) {
  requireValue(typeof value === 'string' && value.length <= 253 && value.length > 0 && !net.isIP(value));
  requireValue(value.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)));
  const name = value.toLowerCase();
  requireValue((lab && name === 'localhost') || (name.includes('.')
    && !/^(?:0x[\da-f]+|\d+)(?:\.(?:0x[\da-f]+|\d+))*$/i.test(name)
    && !/(?:^|\.)(?:localhost|local|internal|home\.arpa)$/.test(name)));
  return name;
}
function compile(input, lab) {
  try {
    fields(input, ['schema', 'transport', 'hostname', 'port', 'path', 'bootstrap', 'trust']);
    requireValue(input.schema === 1 && input.transport === 'doh');
    const name = hostname(input.hostname, lab);
    requireValue(Number.isInteger(input.port) && input.port >= 1 && input.port <= 65535);
    // Deliberately no URI template, query string, escapes, auth, dot segments or redirects.
    requireValue(typeof input.path === 'string' && input.path.length <= 256 && /^\/[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)*$/.test(input.path));
    fields(input.bootstrap, ['addresses']);
    const ips = input.bootstrap.addresses;
    requireValue(Array.isArray(ips) && ips.length >= 1 && ips.length <= 8);
    const addresses = [], seen = new net.BlockList();
    for (const address of ips) {
      requireValue(typeof address === 'string' && (lab ? address === '127.0.0.1' : isPublicRelayAddress(address)));
      const family = net.isIP(address), type = family === 4 ? 'ipv4' : 'ipv6';
      if (seen.check(address, type)) continue;
      seen.addAddress(address, type); addresses.push(Object.freeze({ address, family, port: input.port }));
    }
    let ca, trust;
    if (Object.getOwnPropertyDescriptor(input.trust ?? {}, 'mode')?.value === 'bundled') {
      fields(input.trust, ['mode']); ca = [...tls.rootCertificates]; trust = Object.freeze({ mode: 'bundled' });
    } else {
      fields(input.trust, ['mode', 'certificates']); requireValue(input.trust.mode === 'custom');
      const pems = input.trust.certificates;
      requireValue(Array.isArray(pems) && pems.length >= 1 && pems.length <= 8);
      ca = []; const fingerprints = new Set();
      for (const pem of pems) {
        requireValue(typeof pem === 'string' && pem.length <= 16384
          && /^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END CERTIFICATE-----\r?\n?$/.test(pem));
        const cert = new X509Certificate(pem);
        requireValue(cert.ca && Date.parse(cert.validFrom) <= Date.now() && Date.parse(cert.validTo) > Date.now());
        if (fingerprints.has(cert.fingerprint256)) continue;
        fingerprints.add(cert.fingerprint256); ca.push(cert.toString());
      }
      trust = Object.freeze({ mode: 'custom', fingerprints: Object.freeze([...fingerprints]) });
    }
    const profile = Object.freeze({ schema: 1, scope: lab ? 'loopback-lab' : 'public-contract',
      transport: 'doh', hostname: name, port: input.port, path: input.path,
      authority: input.port === 443 ? name : `${name}:${input.port}`,
      addresses: Object.freeze(addresses), trust, ca: Object.freeze(ca) });
    compiled.add(profile); return profile;
  } catch { fail(); } // Never echo names, IPs, PEM, raw OpenSSL errors or parser excerpts.
}

export const compileDnsUpstream = (input) => compile(input, false);
/** Explicit lab-only entry point. JSON/CLI cannot enable private address admission. */
export const compileLabDnsUpstream = (input) => compile(input, true);
// JSON.parse establishes grammar first. This token walk only rejects duplicate
// (including escaped-equivalent) object keys and excessive container depth.
function uniqueJsonKeys(text) {
  const stack = [];
  for (const [token] of text.matchAll(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\],]/g)) {
    const current = stack.at(-1);
    if (token === '{' || token === '[') {
      requireValue(stack.length < 16); stack.push({ object: token === '{', keys: new Set(), key: true });
    } else if (token === '}' || token === ']') stack.pop();
    else if (token === ',') { if (current) current.key = true; }
    else if (current?.object && current.key) {
      const key = JSON.parse(token); requireValue(!current.keys.has(key)); current.keys.add(key); current.key = false;
    }
  }
}
export function parseDnsUpstream(text) {
  try {
    requireValue(typeof text === 'string' && Buffer.byteLength(text) <= DNS_UPSTREAM_CONFIG_MAX_BYTES);
    const input = JSON.parse(text); uniqueJsonKeys(text); return compileDnsUpstream(input);
  } catch { fail(); }
}
export function dnsUpstreamTlsOptions(profile) {
  requireValue(compiled.has(profile));
  return { servername: profile.hostname, ca: [...profile.ca], rejectUnauthorized: true,
    minVersion: 'TLSv1.3', checkServerIdentity: (_name, cert) => tls.checkServerIdentity(profile.hostname, cert) };
}
export function labDnsUpstreamTarget(profile, relayPort) {
  requireValue(compiled.has(profile) && profile.scope === 'loopback-lab');
  requireValue(Number.isInteger(relayPort) && relayPort >= 1024 && relayPort <= 65535);
  return { address: '127.0.0.1', port: relayPort, ...dnsUpstreamTlsOptions(profile),
    authority: profile.authority, path: profile.path };
}
export function dnsUpstreamSummary(profile) {
  requireValue(compiled.has(profile));
  return { schema: 1, scope: profile.scope, status: 'validated-offline', transport: profile.transport,
    addressCount: profile.addresses.length, families: [...new Set(profile.addresses.map((x) => x.family))],
    trust: profile.trust.mode, caCount: profile.ca.length, runtimeEnabled: false };
}
