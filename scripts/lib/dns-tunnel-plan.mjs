/** Fixed, data-only network plan for plain DNS. No OS calls or arbitrary argv
 * loaded from configuration. Lifecycle owner must journal/apply/undo the plan. */
import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';
import { tunnelDnsServers } from './dns-tunnel-forwarder.mjs';
import { TUNNEL_DNS_ADDRESS as ADDRESS, TUNNEL_DNS_PORT as PORT } from './dns-tunnel-stub.mjs';

export const TUNNEL_DNS_TABLE = 19998;
export const TUNNEL_DNS_PRIORITIES = Object.freeze([10996, 10997]);
export const TUNNEL_DNS_CHAINS = Object.freeze(['CVPN-DNS-OUT', 'CVPN-DNS-IN', 'CVPN-DNS-NAT']);
const iface = (v) => assert.ok(typeof v === 'string' && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}$/.test(v) && v !== 'lo');
function cidr(v) {
  assert.equal(typeof v, 'string'); const [address, prefix, extra] = v.split('/');
  assert.ok(isIPv4(address) && /^(?:[1-9]|[12][0-9]|3[0-2])$/.test(prefix) && extra === undefined);
  const n = address.split('.').reduce((s, b) => ((s << 8) | Number(b)) >>> 0, 0);
  const mask = (0xffffffff << (32 - Number(prefix))) >>> 0;
  assert.equal((n & mask) >>> 0, n, 'LAN network address required'); return v;
}
export function compileTunnelDnsPlan({ tun, primary, fromTun = null, lanSubnet = null, lanInterface = null }) {
  iface(tun);
  if (fromTun !== null) { iface(fromTun); assert.notEqual(tun, fromTun); assert.equal(lanSubnet, null); }
  if (lanSubnet !== null) { cidr(lanSubnet); iface(lanInterface); assert.notEqual(tun, lanInterface); }
  else assert.equal(lanInterface, null);
  const servers = tunnelDnsServers(primary), operations = [];
  const [outChain, inputChain, natChain] = TUNNEL_DNS_CHAINS;
  const add = (stage, file, args, remove) => operations.push({ stage, file, args, remove });
  const chain = (stage, table, name) => add(stage, 'iptables', ['-w', '5', '-t', table, '-N', name], ['-w', '5', '-t', table, '-X', name]);
  const rule = (stage, file, table, name, spec, first = false) => {
    const tagged = ['-m', 'comment', '--comment', 'clean-vpn-dns-tunnel', ...spec];
    add(stage, file, ['-w', '5', '-t', table, first ? '-I' : '-A', name, ...(first ? ['1'] : []), ...tagged],
      ['-w', '5', '-t', table, '-D', name, ...tagged]);
  };
  const selected = fromTun ? ['-i', fromTun] : lanSubnet ? ['-i', lanInterface, '-s', lanSubnet] : null;
  const selectedInterface = fromTun ?? lanInterface;
  chain('guard', 'filter', outChain);
  for (const server of servers) rule('guard', 'iptables', 'filter', outChain,
    ['-s', ADDRESS, '-o', tun, '-d', server, '-j', 'RETURN']);
  if (!fromTun) rule('guard', 'iptables', 'filter', outChain, ['-d', '127.0.0.0/8', '-j', 'RETURN']);
  rule('guard', 'iptables', 'filter', outChain, ['-j', 'REJECT']);
  chain('guard', 'filter', inputChain);
  // Attach a closed listener scope BEFORE bind. Activation opens only selected
  // clients, after the listener and upstream route are ready.
  rule('guard', 'iptables', 'filter', inputChain, ['-j', 'REJECT']);
  for (const protocol of ['udp', 'tcp']) {
    const dns = ['-p', protocol, '--dport', '53'], listener = ['-p', protocol, '--dport', String(PORT)];
    rule('guard', 'iptables', 'filter', 'OUTPUT', [...(fromTun ? ['-s', ADDRESS] : []), ...dns, '-j', outChain], true);
    // If TUN's local address disappears, old DNAT packets must not follow the
    // host's private/uplink route to 10.99.0.2:1053.
    rule('guard', 'iptables', 'filter', 'OUTPUT', ['-d', ADDRESS, '-m', 'addrtype', '!', '--dst-type', 'LOCAL', ...listener, '-j', 'REJECT'], true);
    rule('guard', 'iptables', 'filter', 'INPUT', ['-d', ADDRESS, ...listener, '-j', inputChain], true);
    if (!fromTun) rule('guard', 'ip6tables', 'filter', 'OUTPUT', ['!', '-d', '::1/128', ...dns, '-j', 'REJECT'], true);
    if (selected) {
      rule('guard', 'iptables', 'filter', 'FORWARD', [...selected, '-d', ADDRESS, ...listener, '-j', 'REJECT'], true);
      for (const hook of ['INPUT', 'FORWARD']) {
        rule('guard', 'iptables', 'filter', hook, [...selected, ...dns, '-j', 'REJECT'], true);
        rule('guard', 'ip6tables', 'filter', hook, ['-i', selectedInterface, ...dns, '-j', 'REJECT'], true);
      }
    }
  }
  const table = String(TUNNEL_DNS_TABLE);
  add('route', 'ip', ['-4', 'route', 'add', 'unreachable', 'default', 'metric', '32767', 'table', table],
    ['-4', 'route', 'del', 'unreachable', 'default', 'metric', '32767', 'table', table]);
  for (const [index, server] of servers.entries()) {
    add('route', 'ip', ['-4', 'route', 'add', `${server}/32`, 'dev', tun, 'src', ADDRESS, 'table', table],
      ['-4', 'route', 'del', `${server}/32`, 'dev', tun, 'src', ADDRESS, 'table', table]);
    const selectors = ['priority', String(TUNNEL_DNS_PRIORITIES[index]), 'from', `${ADDRESS}/32`, 'to', `${server}/32`, 'lookup', table];
    add('route', 'ip', ['-4', 'rule', 'add', ...selectors], ['-4', 'rule', 'del', ...selectors]);
  }
  if (!fromTun) rule('activate', 'iptables', 'filter', inputChain, ['-i', 'lo', '-j', 'ACCEPT'], true);
  if (selected) for (const protocol of ['udp', 'tcp']) rule('activate', 'iptables', 'filter', inputChain,
    [...selected, '-p', protocol, '-m', 'conntrack', '--ctstate', 'DNAT', '--ctorigdstport', '53', '-j', 'ACCEPT'], true);
  chain('activate', 'nat', natChain);
  for (const protocol of ['udp', 'tcp']) {
    const dns = ['-p', protocol, '--dport', '53'];
    rule('activate', 'iptables', 'nat', natChain, ['-p', protocol, '-j', 'DNAT', '--to-destination', `${ADDRESS}:${PORT}`]);
    if (!fromTun) rule('activate', 'iptables', 'nat', 'OUTPUT',
      ['!', '-s', ADDRESS, '!', '-d', '127.0.0.0/8', ...dns, '-j', natChain], true);
    if (selected) rule('activate', 'iptables', 'nat', 'PREROUTING', [...selected, ...dns, '-j', natChain], true);
  }
  return { schema: 1, kind: 'clean-vpn-tunnel-dns-plan', tun, servers, fromTun, lanSubnet, lanInterface,
    listener: { address: ADDRESS, port: PORT }, operations };
}
