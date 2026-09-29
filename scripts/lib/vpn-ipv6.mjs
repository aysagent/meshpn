/** IPv6 inside the existing authenticated TLS packet stream, not a second transport. */
import assert from 'node:assert/strict';
import { isIPv4, isIPv6 } from 'node:net';

export const CLIENT6 = 'fd42:6376:706e::2';
export const EXIT6 = 'fd42:6376:706e::1';
export const IPV6_TABLE = '19997';
export const IPV6_PRIORITY = '10995';
export const IPV6_HEADER = 'x-clean-vpn-ipv6';
export const isVpnIpv6Rule = r => String(r.priority) === IPV6_PRIORITY && String(r.table) === IPV6_TABLE && r.src === 'all' &&
  (r.dst === '2000::/3' && (r.dstlen === undefined || r.dstlen === 3) || r.dst === '2000::' && r.dstlen === 3) &&
  Object.keys(r).every(k => ['priority', 'table', 'src', 'dst', 'dstlen'].includes(k));
const clientBytes = Buffer.from('fd426376706e00000000000000000002', 'hex');
const exitBytes = Buffer.from('fd426376706e00000000000000000001', 'hex');
export const validV6Interface = s => typeof s === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,14}$/.test(s) && !['lo', 'all', 'default'].includes(s);

export function overlapsVpnIpv6(cidr) {
  if (typeof cidr !== 'string' || cidr === 'default') return false;
  const [addr, bits = '128'] = cidr.split('/');
  if (!isIPv6(addr) || addr.includes('.') || !/^\d+$/.test(bits)) return false;
  const prefix = Number(bits); if (prefix < 1 || prefix > 128) return false;
  const halves = addr.split('::'), head = halves[0] ? halves[0].split(':') : [], tail = halves[1] ? halves[1].split(':') : [];
  const words = halves.length === 1 ? head : [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail];
  const value = BigInt('0x' + words.map(w => w.padStart(4, '0')).join(''));
  const shift = BigInt(128 - Math.min(prefix, 126));
  return value >> shift === BigInt('0xfd426376706e00000000000000000000') >> shift;
}

export function validateIpv6Options(args) {
  assert.ok(args.ipv6 === undefined || args.ipv6 === null || ['off', 'auto'].includes(args.ipv6), '--ipv6=auto|off');
  if (args.ipv6 !== 'auto') return;
  assert.equal(args.type, 'tls', '--ipv6=auto initially supports only --type=tls');
  assert.ok(!args.tlsRaw && !args.fromTun && !args.clientLanSubnet, '--ipv6=auto is authenticated TLS host-only (no raw/LAN/from-tun)');
  assert.ok(['client', 'exit'].includes(args.role));
  if (args.role === 'client') {
    assert.equal(args.splitDefault, true, '--ipv6=auto requires --split-default');
    assert.ok(isIPv4(args.server?.split(':')[0]), '--ipv6=auto requires an IPv4 outer --server');
  }
}

export function ipv6PacketAllowed(pkt, role, direction) {
  if (!['client', 'exit'].includes(role) || !['in', 'out'].includes(direction)) return false;
  if (!Buffer.isBuffer(pkt) || pkt.length < 40 || pkt.length > 65535 || pkt[0] >>> 4 !== 6) return false;
  const size = pkt.readUInt16BE(4); if (!size || size + 40 !== pkt.length) return false;
  const src = pkt.subarray(8, 24), dst = pkt.subarray(24, 40);
  const outboundClient = (role === 'client') === (direction === 'out');
  if (outboundClient) return src.equals(clientBytes) && ((dst[0] & 0xe0) === 0x20 || dst.equals(exitBytes));
  return dst.equals(clientBytes) && src[0] !== 0xff && !src.equals(Buffer.alloc(16));
}

/** One fixed plan. Journal stores validated config, never executable argv. */
export function ipv6Plan(c) {
  assert.ok(['client', 'exit'].includes(c.role)); assert.ok(validV6Interface(c.tun));
  assert.match(c.id, /^[a-f0-9]{24}$/);
  assert.ok(c.ext === null || validV6Interface(c.ext)); assert.notEqual(c.ext, c.tun);
  assert.equal(typeof c.forward, 'boolean');
  assert.match(c.tunForward, /^[01]$/);
  assert.ok(c.role === 'exit' || !c.forward);
  const chain = `CV6_${c.id.slice(0, 16)}`, tag = `clean-vpn-ipv6-${c.id}`;
  const ops = [];
  const fw = (table, action, name, rest = []) => {
    const prefix = ['-w', '5', '-t', table];
    if (action === '-N') ops.push({ kind: 'chain', file: 'ip6tables', args: [...prefix, '-N', name], remove: [...prefix, '-X', name], check: [...prefix, '-S', name] });
    else {
      const rule = [...rest, '-m', 'comment', '--comment', tag];
      ops.push({ kind: 'fw', file: 'ip6tables', args: [...prefix, action, name, ...(action === '-I' ? ['1'] : []), ...rule],
        remove: [...prefix, '-D', name, ...rule], check: [...prefix, '-C', name, ...rule] });
    }
  };
  if (c.role === 'client') {
    fw('filter', '-N', chain);
    for (const rule of [['-o', 'lo'], ['-d', 'fe80::/10'], ['-d', 'ff02::/16'],
      ['-o', c.tun, '-s', `${CLIENT6}/128`, '-d', '2000::/3'], ['-o', c.tun, '-s', `${CLIENT6}/128`, '-d', `${EXIT6}/128`]])
      fw('filter', '-A', chain, [...rule, '-j', 'RETURN']);
    fw('filter', '-A', chain, ['-j', 'REJECT', '--reject-with', 'icmp6-adm-prohibited']);
    fw('filter', '-I', 'OUTPUT', ['-j', chain]);
  }
  const address = c.role === 'client' ? CLIENT6 : EXIT6;
  ops.push({ kind: 'addr', name: c.tun, address, file: 'ip', args: ['-6', 'addr', 'add', `${address}/126`, 'dev', c.tun, 'nodad'],
    remove: ['-6', 'addr', 'del', `${address}/126`, 'dev', c.tun] });
  if (c.role === 'client') {
    ops.push({ kind: 'route', file: 'ip', route: 'unreachable', args: ['-6', 'route', 'add', 'unreachable', 'default', 'table', IPV6_TABLE, 'metric', '32767'],
      remove: ['-6', 'route', 'del', 'unreachable', 'default', 'table', IPV6_TABLE, 'metric', '32767'] });
    ops.push({ kind: 'rule', file: 'ip', args: ['-6', 'rule', 'add', 'pref', IPV6_PRIORITY, 'to', '2000::/3', 'lookup', IPV6_TABLE],
      remove: ['-6', 'rule', 'del', 'pref', IPV6_PRIORITY, 'to', '2000::/3', 'lookup', IPV6_TABLE] });
  } else if (c.forward) {
    assert.ok(c.ext);
    ops.push({ kind: 'sysctl', file: 'sysctl', key: `net/ipv6/conf/${c.tun}/forwarding`,
      args: ['-w', `net/ipv6/conf/${c.tun}/forwarding=1`], remove: ['-w', `net/ipv6/conf/${c.tun}/forwarding=${c.tunForward}`] });
    // Enabling global IPv6 forwarding changes all interfaces. Require it to be
    // preconfigured; never silently change Docker/RA/other interfaces on exit.
    fw('nat', '-I', 'POSTROUTING', ['-s', `${CLIENT6}/128`, '-o', c.ext, '-j', 'MASQUERADE']);
    fw('filter', '-I', 'FORWARD', ['-i', c.tun, '-s', `${CLIENT6}/128`, '-o', c.ext, '-d', '2000::/3', '-j', 'ACCEPT']);
    fw('filter', '-I', 'FORWARD', ['-i', c.ext, '-o', c.tun, '-d', `${CLIENT6}/128`, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT']);
    // Prevent other IPv6 destinations/sources from crossing this TUN, even
    // when the host's FORWARD policy permits them.
    fw('filter', '-I', 'FORWARD', ['-i', c.tun, '!', '-s', `${CLIENT6}/128`, '-j', 'DROP']);
    fw('filter', '-I', 'FORWARD', ['-i', c.tun, '!', '-d', '2000::/3', '-j', 'DROP']);
  } else fw('filter', '-I', 'FORWARD', ['-i', c.tun, '-j', 'REJECT', '--reject-with', 'icmp6-adm-prohibited']);
  return ops;
}

export function ipv6TunnelRoute(c) {
  return { kind: 'route', route: 'tunnel', file: 'ip', args: ['-6', 'route', 'add', '2000::/3', 'dev', c.tun, 'src', CLIENT6, 'table', IPV6_TABLE],
    remove: ['-6', 'route', 'del', '2000::/3', 'dev', c.tun, 'src', CLIENT6, 'table', IPV6_TABLE] };
}
