/** Strict, read-only baseline assessment. Data here is NOT mutation authority. */
import assert from 'node:assert/strict';
import { isIP } from 'node:net';
import { networkConfigPath, filterNetworkdState } from './dns-client-ownership.mjs';
import { compileDnsDomainPolicy } from './dns-domain-policy.mjs';
import { validateDnsReadyName } from './dns-adapter-ready.mjs';
import { makeDnsQuery, parseDnsQuery } from './lab-dns-wire.mjs';
import { validateResolvedSettings } from './dns-resolved-backend.mjs';

const exact = (v, names) => {
  assert.ok(v && typeof v === 'object' && !Array.isArray(v));
  assert.deepEqual(Object.keys(v).sort(), [...names].sort());
};
export function validateVps2DnsConfig(v) {
  exact(v, ['schema', 'kind', 'client', 'uplink', 'networkFile', 'adapterPort', 'readyName', 'domainPolicy']);
  assert.equal(v.schema, 1); assert.equal(v.kind, 'clean-vpn-dns-client'); assert.equal(v.client, 'vps2');
  assert.match(v.uplink, /^[a-zA-Z0-9_-]{1,15}$/);
  assert.ok(v.uplink !== 'lo' && !v.uplink.startsWith('cvdns'));
  exact(v.networkFile, ['path', 'sha256']); assert.ok(networkConfigPath(v.networkFile.path));
  assert.match(v.networkFile.sha256, /^[a-f0-9]{64}$/);
  assert.ok(Number.isInteger(v.adapterPort) && v.adapterPort >= 1024 && v.adapterPort <= 65535);
  compileDnsDomainPolicy(v.domainPolicy);
  assert.equal(v.readyName, validateDnsReadyName(v.readyName, v.domainPolicy));
  // Canonical input makes policy comparison with adapter credentials exact.
  assert.ok(v.domainPolicy.denySuffixes.every((s) => s === s.toLowerCase() && !s.endsWith('.')));
  return v;
}
const ipv4 = (s) => {
  assert.equal(isIP(s), 4); return s.split('.').reduce((n, b) => n * 256 + Number(b), 0);
};
function coversReserved(destination) {
  if (destination === 'default') return false;
  assert.equal(typeof destination, 'string');
  const parts = destination.split('/'); assert.ok(parts.length <= 2);
  const address = ipv4(parts[0]), bits = parts.length === 1 ? 32 : Number(parts[1]);
  assert.ok(Number.isInteger(bits) && bits >= 0 && bits <= 32);
  if (parts.length === 2) assert.equal(String(bits), parts[1]);
  // An ordinary default route is expected, more-specific routes are conflicts.
  if (bits === 0) { assert.equal(address, 0); return false; }
  const size = 2 ** (32 - bits); return Math.floor(address / size) === Math.floor(ipv4('192.0.2.1') / size);
}
export function assessVps2DnsBaseline(config, evidence) {
  validateVps2DnsConfig(config);
  const denied = compileDnsDomainPolicy(config.domainPolicy);
  const checkDomain = (name) => {
    assert.equal(typeof name, 'string'); assert.ok(!name.startsWith('~') && name !== '.');
    assert.equal(denied.denies(parseDnsQuery(makeDnsQuery(name))), true, 'unapproved baseline domain');
  };
  assert.equal(evidence.resolverTarget, '/run/systemd/resolve/stub-resolv.conf');
  const resolver = evidence.resolverText.split('\n').map((s) => s.trim()).filter((s) => s && !s.startsWith('#'));
  let nameservers = 0;
  for (const line of resolver) {
    const [key, ...values] = line.split(/\s+/);
    if (key === 'nameserver') { assert.deepEqual(values, ['127.0.0.53']); nameservers++; }
    else if (key === 'options') { assert.ok(values.every((s) => ['edns0', 'trust-ad'].includes(s))); }
    else if (key === 'search') { assert.ok(values.length > 0 && values.length <= 32); values.forEach(checkDomain); }
    else assert.fail('unsupported resolver directive');
  }
  assert.equal(nameservers, 1);
  const hosts = evidence.nssText.split('\n').map((s) => s.split('#')[0].trim()).filter((s) => /^hosts\s*:/.test(s));
  assert.equal(hosts.length, 1); assert.match(hosts[0], /^hosts\s*:\s*files\s+dns\s*$/);
  assert.ok(Array.isArray(evidence.addresses) && evidence.addresses.length <= 64);
  const names = new Set(), indexes = new Set();
  for (const link of evidence.addresses) {
    assert.equal(typeof link.ifname, 'string'); assert.ok(Number.isInteger(link.ifindex) && link.ifindex > 0);
    assert.ok(!names.has(link.ifname) && !indexes.has(link.ifindex)); names.add(link.ifname); indexes.add(link.ifindex);
    assert.ok(!link.ifname.startsWith('cvdns'), 'baseline inspection requires no existing DNS link');
    assert.ok(Array.isArray(link.addr_info) && link.addr_info.length <= 64);
    for (const address of link.addr_info) {
      assert.ok(['inet', 'inet6'].includes(address.family));
      assert.equal(isIP(address.local), address.family === 'inet' ? 4 : 6);
      assert.notEqual(address.local, '192.0.2.1', 'reserved DNS address already assigned');
    }
  }
  const uplink = evidence.addresses.find((v) => v.ifname === config.uplink);
  assert.ok(uplink && uplink.ifindex > 1 && uplink.flags.includes('UP'));
  assert.ok(uplink.addr_info.some((a) => a.family === 'inet' && a.scope === 'global'));
  assert.ok(Array.isArray(evidence.routes4) && evidence.routes4.length <= 512);
  for (const route of evidence.routes4) assert.equal(coversReserved(route.dst), false, 'reserved DNS address route conflict');
  assert.ok(evidence.routes4.some((r) => r.dst === 'default' && r.dev === config.uplink && (!r.type || r.type === 'unicast')));
  const network = filterNetworkdState(evidence.networkState);
  assert.equal(network.NETWORK_FILE, config.networkFile.path);
  assert.equal(evidence.networkFileSha256, config.networkFile.sha256);
  assert.equal(network.ADMIN_STATE, 'configured');
  for (const name of [...(network.DOMAINS ?? []), ...(network.ROUTE_DOMAINS ?? [])]) checkDomain(name);
  assert.deepEqual(evidence.adapterDomainPolicy, config.domainPolicy);
  assert.equal(evidence.manager.ResolvConfMode, 'stub');
  assert.ok(Array.isArray(evidence.manager.DNSEx) && evidence.manager.DNSEx.length > 0 && evidence.manager.DNSEx.length <= 8);
  for (const item of evidence.manager.DNSEx) {
    assert.ok(Array.isArray(item) && item.length === 5 && item[0] === uplink.ifindex, 'unexpected DNS link/global source');
    validateResolvedSettings({ DNSEx: [item.slice(1)], Domains: [], DefaultRoute: false });
  }
  assert.deepEqual(evidence.manager.FallbackDNSEx, []);
  assert.ok(Array.isArray(evidence.manager.Domains) && evidence.manager.Domains.length <= 32);
  for (const item of evidence.manager.Domains) {
    assert.ok(Array.isArray(item) && item.length === 3 && item[0] === uplink.ifindex && typeof item[2] === 'boolean'); checkDomain(item[1]);
  }
  return { schema: 1, kind: 'clean-vpn-dns-vps2-baseline', mode: 'read-only', baselineChecksPassed: true,
    activationAuthorized: false, systemSettingsChanged: false, dnsQueriesSent: 0,
    limitations: ['baseline-only-not-active-recovery', 'point-in-time-not-manager-lock', 'disk-config-not-loaded-config-proof',
      'no-adapter-credential-or-readiness-proof', 'no-networkd-owned-link-exclusion-proof', 'not-a-leak-test'] };
}
