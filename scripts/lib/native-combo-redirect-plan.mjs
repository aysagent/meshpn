/** Fixed, data-only overlay for the direct Radxa combo trial. No OS calls. */
import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';
import { transparentSpecialIPv4 } from './native-transparent-network.mjs';

const iface = value => {
  assert.equal(typeof value, 'string');
  assert.match(value, /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}$/);
  assert.notEqual(value, 'lo'); return value;
};
const ipNumber = value => value.split('.').reduce((n, part) => ((n << 8) | Number(part)) >>> 0, 0);
function cidr(value) {
  assert.equal(typeof value, 'string');
  const [address, prefixText, extra] = value.split('/'), prefix = Number(prefixText);
  assert.ok(isIPv4(address) && extra === undefined && Number.isInteger(prefix) && prefix >= 0 && prefix <= 32);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  assert.equal((ipNumber(address) & mask) >>> 0, ipNumber(address), 'CIDR network address required');
  return value;
}
const rule = (table, chain, spec, { first = false } = {}) => ({ file: 'iptables',
  args: ['-w', '5', '-t', table, first ? '-I' : '-A', chain, ...(first ? ['1'] : []), ...spec],
  remove: ['-w', '5', '-t', table, '-D', chain, ...spec] });

export function validateNativeComboRedirectConfig(config) {
  assert.deepEqual(Object.keys(config).sort(), ['deny_ipv4', 'endpoint', 'interface', 'listen_port', 'subnet'].sort());
  iface(config.interface); cidr(config.subnet);
  assert.ok(config.subnet.startsWith('192.168.'), 'reviewed private USB subnet required');
  assert.ok(isIPv4(config.endpoint) && !config.endpoint.startsWith('0.') && !config.endpoint.startsWith('127.'));
  assert.ok(Number.isInteger(config.listen_port) && config.listen_port >= 1024 && config.listen_port <= 65535);
  assert.ok(![1053, 2222, 443].includes(config.listen_port), 'listener collision');
  assert.ok(Array.isArray(config.deny_ipv4) && config.deny_ipv4.length <= 64);
  assert.equal(new Set(config.deny_ipv4).size, config.deny_ipv4.length);
  config.deny_ipv4.forEach(cidr); return config;
}

export function nativeComboRedirectPlan(config, id) {
  validateNativeComboRedirectConfig(config); assert.match(id, /^[a-f0-9]{24}$/);
  const tag = `clean-vpn-native-combo-${id}`, chain = `CVPN-CT-${id.slice(0, 16)}`;
  const scoped = ['-i', config.interface, '-s', config.subnet];
  const operations = [
    // Closed local listener before any redirect can become reachable.
    rule('filter', 'INPUT', ['-p', 'tcp', '--dport', String(config.listen_port),
      '-m', 'comment', '--comment', tag, '-j', 'DROP'], { first: true }),
    { file: 'iptables', args: ['-w', '5', '-t', 'nat', '-N', chain],
      remove: ['-w', '5', '-t', 'nat', '-X', chain] },
  ];
  // Non-public/control destinations are not relayed. The FORWARD drop below
  // prevents any TCP/443 which was not redirected from downgrading to boring.
  for (const destination of new Set([...transparentSpecialIPv4, ...config.deny_ipv4, `${config.endpoint}/32`]))
    operations.push(rule('nat', chain, ['-d', destination, '-j', 'RETURN']));
  operations.push(rule('nat', chain, ['-m', 'addrtype', '--dst-type', 'LOCAL', '-j', 'RETURN']),
    rule('nat', chain, ['-p', 'tcp', '--dport', '443', '-j', 'REDIRECT', '--to-ports', String(config.listen_port)]),
    // Appended after the first cvks4 hook: traffic allowed by cvks4 returns to
    // FORWARD and is denied here unless PREROUTING already made it local.
    rule('filter', 'FORWARD', [...scoped, '-p', 'tcp', '--dport', '443',
      '-m', 'comment', '--comment', tag, '-j', 'DROP']),
    rule('filter', 'INPUT', [...scoped, '-p', 'tcp', '--dport', String(config.listen_port),
      '-m', 'conntrack', '--ctstate', 'DNAT', '--ctorigdstport', '443',
      '-m', 'comment', '--comment', tag, '-j', 'ACCEPT'], { first: true }),
    // Activation is deliberately last. All preceding states are fail-closed.
    rule('nat', 'PREROUTING', [...scoped, '-p', 'tcp', '--dport', '443',
      '-m', 'comment', '--comment', tag, '-j', chain], { first: true }));
  return { schema: 1, kind: 'clean-vpn-native-combo-redirect-plan', tag, chain, operations };
}
