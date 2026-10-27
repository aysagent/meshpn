// Selected ingress -> isolated native client. No host default route or resolver edits.
import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';
const keys = (v, list) => assert.deepEqual(Object.keys(v).sort(), list.sort(), 'unexpected_gateway_fields');
const number = ip => ip.split('.').reduce((n, b) => n * 256 + Number(b), 0);
const network = cidr => {
  const [ip, bits, extra] = String(cidr).split('/');
  assert.ok(isIPv4(ip) && /^(?:[1-9]|[12][0-9]|30)$/.test(bits) && !extra, 'invalid_gateway_cidr');
  const size = 2 ** (32 - Number(bits)), start = number(ip);
  assert.equal(start % size, 0, 'canonical_gateway_network_required');
  return { start, end: start + size - 1, bits: Number(bits) };
};
const contains = (cidr, ip) => { const n = network(cidr); return isIPv4(ip) && number(ip) > n.start && number(ip) < n.end; };
const privateRange = cidr => { const n = network(cidr); return ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].some(c => { const p = network(c); return n.start >= p.start && n.end <= p.end; }); };
export function validateGatewayConfig(c) {
  keys(c, ['schema', 'ingress', 'bridge', 'table', 'priority', 'bypass', 'dnsUid']); assert.equal(c.schema, 1);
  keys(c.ingress, ['interface', 'subnet']); keys(c.bridge, ['interface', 'subnet', 'host', 'client']);
  for (const dev of [c.ingress.interface, c.bridge.interface]) { assert.match(dev, /^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/); assert.ok(!['lo', 'cvpn0'].includes(dev)); }
  assert.notEqual(c.ingress.interface, c.bridge.interface);
  assert.ok(privateRange(c.ingress.subnet)); assert.ok(privateRange(c.bridge.subnet) && c.bridge.subnet.startsWith('192.168.'), 'runtime_bridge_requires_192_168');
  const a = network(c.ingress.subnet), b = network(c.bridge.subnet), tun = network('10.99.0.0/24');
  assert.ok(a.end < b.start || b.end < a.start, 'ingress_bridge_overlap');
  assert.ok(a.end < tun.start || tun.end < a.start, 'ingress_tunnel_overlap');
  assert.ok(contains(c.bridge.subnet, c.bridge.host) && contains(c.bridge.subnet, c.bridge.client)); assert.notEqual(c.bridge.host, c.bridge.client);
  for (const value of [c.table, c.priority]) assert.ok(Number.isInteger(value) && value >= 10000 && value <= 30000);
  assert.ok(Array.isArray(c.bypass) && c.bypass.length <= 16 && new Set(c.bypass).size === c.bypass.length && c.bypass.every(privateRange));
  assert.ok(c.dnsUid === null || Number.isInteger(c.dnsUid) && c.dnsUid >= 100 && c.dnsUid <= 2147483646, 'dedicated_nonroot_dns_uid_required');
  return c;
}
export function gatewayPlan(c, id) {
  validateGatewayConfig(c); assert.match(id, /^[a-f0-9]{24}$/);
  const table = String(c.table), priority = String(c.priority), chain = 'CVPN_GW', dns = 'CVPN_GD', tag = 'cvpn-gw-' + id;
  const operations = [], comment = ['-m', 'comment', '--comment', tag];
  const rule = (family, t, hook, spec, first = false) => {
    const bin = family === 6 ? 'ip6tables-nft' : 'iptables-nft', base = ['-w', '5', '-t', t];
    operations.push({ kind: 'firewall', family, table: t, expected: ['-A', hook, ...spec],
      add: [bin, [...base, first ? '-I' : '-A', hook, ...(first ? ['1'] : []), ...spec]],
      del: [bin, [...base, '-D', hook, ...spec]] });
  };
  const create = name => operations.push({ kind: 'firewall', family: 4, table: 'filter', expected: ['-N', name],
    add: ['iptables-nft', ['-w', '5', '-t', 'filter', '-N', name]], del: ['iptables-nft', ['-w', '5', '-t', 'filter', '-X', name]] });
  const route = (words, match) => operations.push({ kind: 'route', match: { ...match, table: c.table },
    add: ['ip', ['-4', 'route', 'add', ...words, 'table', table]], del: ['ip', ['-4', 'route', 'del', ...words, 'table', table]] });
  create(chain); rule(4, 'filter', chain, [...comment, '-j', 'DROP']);
  rule(4, 'filter', 'FORWARD', ['-i', c.ingress.interface, ...comment, '-j', chain], true);
  rule(6, 'filter', 'FORWARD', ['-i', c.ingress.interface, ...comment, '-j', 'DROP'], true);
  // The dedicated resolver must explicitly use bridge.client as upstream.
  // Guard it, including existing sockets; do not rewrite a running daemon's
  // bound upstream sockets behind its back. Config ownership is separate.
  if (c.dnsUid !== null) {
    create(dns); rule(4, 'filter', dns, [...comment, '-j', 'DROP']);
    for (const proto of ['udp', 'tcp']) {
      rule(4, 'filter', 'OUTPUT', ['-m', 'owner', '--uid-owner', String(c.dnsUid), '-p', proto, '--dport', '53', ...comment, '-j', dns], true);
      rule(6, 'filter', 'OUTPUT', ['-m', 'owner', '--uid-owner', String(c.dnsUid), '-p', proto, '--dport', '53', ...comment, '-j', 'DROP'], true);
    }
  }
  route(['unreachable', 'default', 'metric', '32767'], { dst: 'default', type: 'unreachable', metric: 32767 });
  for (const dst of c.bypass) route(['throw', dst], { dst, type: 'throw' });
  route(['default', 'via', c.bridge.client, 'dev', c.bridge.interface, 'metric', '10'], { dst: 'default', gateway: c.bridge.client, dev: c.bridge.interface, metric: 10 });
  operations.push({ kind: 'policy', match: { priority: c.priority, table: c.table, iif: c.ingress.interface },
    add: ['ip', ['-4', 'rule', 'add', 'priority', priority, 'iif', c.ingress.interface, 'lookup', table]],
    del: ['ip', ['-4', 'rule', 'del', 'priority', priority, 'iif', c.ingress.interface, 'lookup', table]] });
  rule(4, 'nat', 'POSTROUTING', ['-s', c.ingress.subnet, '-o', c.bridge.interface, ...comment, '-j', 'SNAT', '--to-source', c.bridge.host], true);
  for (const dst of c.bypass) rule(4, 'filter', chain, ['-s', c.ingress.subnet, '-d', dst, ...comment, '-j', 'RETURN'], true);
  rule(4, 'filter', 'FORWARD', ['-i', c.bridge.interface, '-o', c.ingress.interface, '-d', c.ingress.subnet, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', ...comment, '-j', 'ACCEPT'], true);
  rule(4, 'filter', chain, ['-s', c.ingress.subnet, '-o', c.bridge.interface, ...comment, '-j', 'ACCEPT'], true);
  for (const proto of ['udp', 'tcp']) {
    rule(4, 'nat', 'PREROUTING', ['-i', c.ingress.interface, '-s', c.ingress.subnet, '-p', proto, '--dport', '53', ...comment, '-j', 'DNAT', '--to-destination', c.bridge.client + ':53'], true);
  }
  if (c.dnsUid !== null) rule(4, 'filter', dns, ['-d', c.bridge.client, '-o', c.bridge.interface, ...comment, '-j', 'ACCEPT'], true);
  return { tag, operations };
}

export function canonicalGatewayRule(line) {
  const tokens = (Array.isArray(line) ? line.join(' ') : line).replace(/"/g, '').replace(/ -m (tcp|udp)(?= |$)/g, '')
    .replace(/\b(\d+\.\d+\.\d+\.\d+)\/32\b/g, '$1')
    .replace(/--ctstate ([A-Z,]+)/g, (_, states) => '--ctstate ' + states.split(',').sort().join(',')).trim().split(/\s+/);
  // iptables relocates -p ahead of owner/source selectors. All generated
  // options here are value pairs (no negations or zero-argument flags).
  const pairs = []; for (let i = 0; i < tokens.length; i += 2) pairs.push(tokens.slice(i, i + 2).join(' '));
  return pairs.sort().join(' ');
}
