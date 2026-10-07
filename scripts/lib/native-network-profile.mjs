// Dedicated native-only IPv4 host/namespace. Pure plan: no sockets or OS writes.
import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';
const keys = (v, list) => assert.deepEqual(Object.keys(v).sort(), list.sort());
const iface = v => { assert.match(v, /^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/); assert.notEqual(v, 'lo'); };
const number = ip => ip.split('.').reduce((n, b) => n * 256 + Number(b), 0);
function cidr(value) {
  const [ip, bits, extra] = String(value).split('/');
  assert.ok(isIPv4(ip) && /^(?:[1-9]|[12][0-9]|3[0-2])$/.test(bits) && extra === undefined);
  return { ip, bits: Number(bits), base: Math.floor(number(ip) / 2 ** (32 - Number(bits))) };
}
export function validateNativeNetworkProfile(c) {
  keys(c, ['version', 'role', 'tun', 'tun_address', 'mtu', 'uplink', 'endpoint', 'port', 'lan']);
  assert.equal(c.version, 1); assert.ok(['client', 'exit'].includes(c.role));
  iface(c.tun); iface(c.uplink); assert.notEqual(c.tun, c.uplink);
  assert.ok(isIPv4(c.endpoint)); assert.ok(number(c.endpoint) > 0 && number(c.endpoint) < 0xe0000000);
  assert.ok(Number.isInteger(c.port) && c.port > 0 && c.port <= 65535);
  assert.ok(Number.isInteger(c.mtu) && c.mtu >= 1280 && c.mtu <= 1500);
  const a = cidr(c.tun_address);
  assert.ok(a.ip.startsWith('10.99.0.') && number(a.ip) % 256 >= (c.role === 'client' ? 2 : 1) && number(a.ip) % 256 <= 254);
  assert.equal(a.bits, c.role === 'client' ? 32 : 24);
  if (c.role === 'exit') { assert.equal(number(a.ip) % 256, 1); assert.equal(c.lan, null); }
  if (c.lan !== null) {
    keys(c.lan, ['interface', 'subnet']); iface(c.lan.interface);
    assert.ok(![c.tun, c.uplink].includes(c.lan.interface));
    const n = cidr(c.lan.subnet); assert.ok(n.bits >= 16 && n.bits <= 30);
    assert.equal(number(n.ip) % 2 ** (32 - n.bits), 0);
    assert.ok(number(n.ip) >= 0xc0a80000 && number(n.ip) < 0xc0a90000, 'reviewed_private_lan_required');
  }
  return c;
}
const table = (name, chains, rules) => `*${name}\n${chains.map(([c, p]) => `:${c} ${p} [0:0]`).join('\n')}\n${rules.join('\n')}\nCOMMIT\n`;
export function nativeNetworkPlan(input) {
  const c = validateNativeNetworkProfile(input), client = c.role === 'client';
  const ip = c.tun_address.split('/')[0], network = ip.split('.').slice(0, 3).join('.') + '.0/24';
  const filter = ['-A INPUT -i lo -j ACCEPT', '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
    '-A OUTPUT -o lo -j ACCEPT'];
  if (client) {
    filter.push(`-A INPUT -i ${c.uplink} -p udp -m udp --sport 67 --dport 68 -j ACCEPT`,
      `-A OUTPUT -o ${c.uplink} -p udp -m udp --sport 68 --dport 67 -j ACCEPT`,
      `-A OUTPUT -o ${c.uplink} -d ${c.endpoint}/32 -p tcp -m tcp --dport ${c.port} -j ACCEPT`,
      `-A OUTPUT -o ${c.tun} -j ACCEPT`);
    if (c.lan) {
      const { interface: dev, subnet } = c.lan;
      // Local management remains accessible; this does not allow uplink bypass.
      filter.push(`-A INPUT -i ${dev} -s ${subnet} -p tcp -m tcp --dport 2222 -j ACCEPT`);
      for (const p of ['tcp', 'udp']) filter.push(`-A INPUT -i ${dev} -s ${subnet} -d ${ip}/32 -p ${p} -m ${p} --dport 1053 -m conntrack --ctstate DNAT -j ACCEPT`);
      filter.push(`-A OUTPUT -o ${dev} -d ${subnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`,
        `-A FORWARD -i ${dev} -s ${subnet} -o ${c.tun} -j ACCEPT`,
        `-A FORWARD -i ${c.tun} -o ${dev} -d ${subnet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`);
    }
  } else {
    filter.push(`-A INPUT -i ${c.uplink} -d ${c.endpoint}/32 -p tcp -m tcp --dport ${c.port} -j ACCEPT`,
      `-A OUTPUT -o ${c.uplink} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`,
      `-A FORWARD -i ${c.tun} -s ${network} -o ${c.uplink} -j ACCEPT`,
      `-A FORWARD -i ${c.uplink} -o ${c.tun} -d ${network} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`);
  }
  const nat = [], mangle = [];
  if (client) {
    for (const p of ['udp', 'tcp']) {
      // Source address alone also matches normal applications routed over TUN.
      for (const server of ['1.1.1.1', '8.8.8.8']) nat.push(`-A OUTPUT -s ${ip}/32 -d ${server}/32 -p ${p} -m ${p} --dport 53 -m mark --mark 0x43564e -j ACCEPT`);
      nat.push(`-A OUTPUT ! -d 127.0.0.0/8 -p ${p} -m ${p} --dport 53 -j DNAT --to-destination ${ip}:1053`);
      if (c.lan) nat.push(`-A PREROUTING -i ${c.lan.interface} -s ${c.lan.subnet} -p ${p} -m ${p} --dport 53 -j DNAT --to-destination ${ip}:1053`);
    }
    if (c.lan) {
      nat.push(`-A POSTROUTING -s ${c.lan.subnet} -o ${c.tun} -j SNAT --to-source ${ip}`);
      for (const direction of [`-i ${c.lan.interface} -o ${c.tun} -s ${c.lan.subnet}`, `-i ${c.tun} -o ${c.lan.interface} -d ${c.lan.subnet}`])
        mangle.push(`-A FORWARD ${direction} -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ${c.mtu - 40}`);
    }
  } else nat.push(`-A POSTROUTING -s ${network} -o ${c.uplink} -j MASQUERADE`);
  return { ipv6: table('filter', [['INPUT', 'DROP'], ['FORWARD', 'DROP'], ['OUTPUT', 'DROP']],
    ['-A INPUT -i lo -j ACCEPT', '-A OUTPUT -o lo -j ACCEPT']),
  ipv4: table('filter', [['INPUT', 'DROP'], ['FORWARD', 'DROP'], ['OUTPUT', 'DROP']], filter),
  nat: table('nat', [['PREROUTING', 'ACCEPT'], ['INPUT', 'ACCEPT'], ['OUTPUT', 'ACCEPT'], ['POSTROUTING', 'ACCEPT']], nat),
  mangle: table('mangle', [['PREROUTING', 'ACCEPT'], ['INPUT', 'ACCEPT'], ['FORWARD', 'ACCEPT'], ['OUTPUT', 'ACCEPT'], ['POSTROUTING', 'ACCEPT']], mangle),
  tun: [['tuntap', 'add', 'dev', c.tun, 'mode', 'tun'], ['addr', 'add', c.tun_address, 'dev', c.tun], ['link', 'set', c.tun, 'mtu', String(c.mtu), 'up']],
  forwarding: !client || c.lan !== null };
}

// Whole dedicated tables only; refuses even compatible pre-existing rules.
export function assertEmptyNativeTables(text) {
  for (const line of text.trim().split('\n')) {
    if (!line || line.startsWith('#') || line.startsWith('*') || line === 'COMMIT') continue;
    assert.match(line, /^:(?:INPUT|OUTPUT|FORWARD|PREROUTING|POSTROUTING) ACCEPT \[\d+:\d+\]$/, 'foreign_firewall_refused');
  }
}
export const canonicalNativeTables = text => text.split('\n').filter(l => l && !l.startsWith('#')).map(l => l.replace(/\[\d+:\d+\]/g, '[0:0]')).join('\n');
