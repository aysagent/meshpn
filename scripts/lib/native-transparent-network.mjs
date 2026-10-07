// Dedicated standalone transparent gateway. Network control only: no packets.
import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';
const keys = (v, fields) => assert.deepEqual(Object.keys(v).sort(), fields.sort());
const iface = v => { assert.equal(typeof v, 'string'); assert.match(v, /^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/); assert.notEqual(v, 'lo'); };
const number = ip => ip.split('.').reduce((n, b) => n * 256 + Number(b), 0);
const port = v => assert.ok(Number.isInteger(v) && v > 0 && v <= 65535);
export const transparentSpecialIPv4 = Object.freeze(['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
  '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.31.196.0/24', '192.52.193.0/24',
  '192.88.99.0/24', '192.168.0.0/16', '192.175.48.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
  '224.0.0.0/4', '240.0.0.0/4']);
function cidr(v) {
  assert.equal(typeof v, 'string');
  const [ip, bits, extra] = v.split('/');
  assert.ok(isIPv4(ip) && /^(?:0|[1-9]|[12][0-9]|3[0-2])$/.test(bits) && extra === undefined);
  assert.equal(number(ip) % 2 ** (32 - Number(bits)), 0);
  return { ip, bits: Number(bits) };
}
export function validateTransparentNetworkProfile(c) {
  keys(c, ['version', 'transport', 'role', 'uplink', 'endpoint', 'port', 'listen_port', 'lan', 'deny_ipv4']);
  assert.equal(c.version, 1); assert.equal(c.transport, 'transparent-tls');
  assert.ok(['client', 'exit'].includes(c.role)); iface(c.uplink);
  assert.ok(isIPv4(c.endpoint) && number(c.endpoint) > 0 && number(c.endpoint) < 0xe0000000);
  assert.ok(!c.endpoint.startsWith('127.') && !c.endpoint.startsWith('0.'));
  port(c.port); port(c.listen_port);
  assert.ok(Array.isArray(c.deny_ipv4) && c.deny_ipv4.length <= 64);
  assert.equal(new Set(c.deny_ipv4).size, c.deny_ipv4.length); c.deny_ipv4.forEach(cidr);
  if (c.role === 'exit') { assert.equal(c.lan, null); assert.equal(c.listen_port, c.port); }
  else {
    keys(c.lan, ['interface', 'subnet']); iface(c.lan.interface); assert.notEqual(c.lan.interface, c.uplink);
    const n = cidr(c.lan.subnet);
    assert.ok(n.bits >= 16 && n.bits <= 30 && number(n.ip) >= 0xc0a80000 && number(n.ip) < 0xc0a90000);
    assert.notEqual(c.listen_port, 2222, 'management_listener_collision');
    assert.notEqual(Math.floor(number(c.endpoint) / 2 ** (32 - n.bits)), Math.floor(number(n.ip) / 2 ** (32 - n.bits)), 'exit_on_lan');
  }
  return c;
}
const table = (name, chains, rules) => `*${name}\n${chains.map(c => `:${c} ${name === 'filter' ? 'DROP' : 'ACCEPT'} [0:0]`).join('\n')}\n${rules.join('\n')}\nCOMMIT\n`;
export function transparentNetworkPlan(input) {
  const c = validateTransparentNetworkProfile(input);
  const filter = ['-A INPUT -i lo -j ACCEPT', '-A OUTPUT -o lo -j ACCEPT'];
  const nat = [];
  if (c.role === 'client') {
    const { interface: dev, subnet } = c.lan;
    filter.push(`-A INPUT -i ${c.uplink} -p udp -m udp --sport 67 --dport 68 -j ACCEPT`,
      `-A OUTPUT -o ${c.uplink} -p udp -m udp --sport 68 --dport 67 -j ACCEPT`,
      `-A OUTPUT -o ${c.uplink} -d ${c.endpoint}/32 -p tcp -m tcp --dport ${c.port} -j ACCEPT`,
      `-A INPUT -i ${c.uplink} -s ${c.endpoint}/32 -p tcp -m tcp --sport ${c.port} -m conntrack --ctstate ESTABLISHED -j ACCEPT`,
      `-A INPUT -i ${dev} -s ${subnet} -p tcp -m tcp --dport 2222 -j ACCEPT`,
      `-A INPUT -i ${dev} -s ${subnet} -p tcp -m tcp --dport ${c.listen_port} -m conntrack --ctstate DNAT -j ACCEPT`,
      `-A OUTPUT -o ${dev} -d ${subnet} -m conntrack --ctstate ESTABLISHED -j ACCEPT`);
    // Local/control destinations return to DROP/FORWARD, never to the relay.
    for (const dst of [...transparentSpecialIPv4, ...c.deny_ipv4, c.endpoint + '/32'])
      nat.push(`-A PREROUTING -i ${dev} -s ${subnet} -d ${dst} -j RETURN`);
    nat.push(`-A PREROUTING -i ${dev} -s ${subnet} -m addrtype --dst-type LOCAL -j RETURN`,
      `-A PREROUTING -i ${dev} -s ${subnet} -p tcp -m tcp --dport 443 -j REDIRECT --to-ports ${c.listen_port}`);
  } else {
    filter.push(`-A INPUT -i ${c.uplink} -d ${c.endpoint}/32 -p tcp -m tcp --dport ${c.port} -j ACCEPT`,
      `-A OUTPUT -o ${c.uplink} -s ${c.endpoint}/32 -p tcp -m tcp --sport ${c.port} -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT`);
    for (const dst of [...transparentSpecialIPv4, ...c.deny_ipv4, c.endpoint + '/32'])
      filter.push(`-A OUTPUT -o ${c.uplink} -d ${dst} -j DROP`);
    filter.push(`-A OUTPUT -o ${c.uplink} -p tcp -m tcp --dport 443 -j ACCEPT`,
      `-A INPUT -i ${c.uplink} -p tcp -m tcp --sport 443 -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT`);
  }
  return {
    ipv6: table('filter', ['INPUT', 'FORWARD', 'OUTPUT'], ['-A INPUT -i lo -j ACCEPT', '-A OUTPUT -o lo -j ACCEPT']),
    ipv4: table('filter', ['INPUT', 'FORWARD', 'OUTPUT'], filter),
    nat: table('nat', ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING'], nat),
    mangle: table('mangle', ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'], []),
    tun: [], forwarding: false,
  };
}
