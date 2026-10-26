// Network control only. All tunnel/TLS/DNS payload processing remains native.
import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';

export function runtimePlan(c, { uplink = 'eth0', mtu = 1400, lan = null } = {}) {
  assert.equal(c.version, 1);
  assert.ok(['client', 'exit'].includes(c.role));
  assert.equal(c.transport, undefined, 'runtime_v1_requires_boring_tls');
  assert.equal(c.tun, 'cvpn0', 'runtime_owns_cvpn0');
  assert.match(uplink, /^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/);
  assert.ok(!['lo', c.tun].includes(uplink));
  assert.ok(Number.isInteger(mtu) && mtu >= 1280 && mtu <= 1500);
  assert.ok(isIPv4(c.address) && !/^(0|127|10\.99\.0)\./.test(c.address));
  assert.ok(Number(c.address.split('.')[0]) < 224);
  assert.ok(Number.isInteger(c.port) && c.port > 0 && c.port <= 65535);
  const client = c.role === 'client', peer = c.peer_ipv4 ?? '10.99.0.2';
  if (lan !== null) {
    assert.equal(client, true, 'lan_client_only');
    assert.deepEqual(Object.keys(lan).sort(), ['interface', 'subnet']);
    assert.match(lan.interface, /^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/);
    assert.ok(!['lo', c.tun, uplink].includes(lan.interface));
    const [ip, bits, extra] = String(lan.subnet).split('/');
    assert.ok(isIPv4(ip) && ip.startsWith('192.168.') && /^(1[6-9]|2[0-9]|30)$/.test(bits) && !extra, 'reviewed_private_lan_required');
    const n = ip.split('.').reduce((v, b) => v * 256 + Number(b), 0);
    assert.equal(n % 2 ** (32 - Number(bits)), 0, 'lan_network_address_required');
  }
  assert.match(peer, /^10\.99\.0\.[0-9]{1,3}$/);
  assert.ok(isIPv4(peer) && Number(peer.split('.')[3]) >= 2 && Number(peer.split('.')[3]) <= 254);
  if (client) assert.equal(c.dns, true, 'runtime_requires_native_dns');
  const address = client ? peer : '10.99.0.1';
  const rules = { input: ['-i lo -j ACCEPT', '-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'],
    output: ['-o lo -j ACCEPT'], forward: [], dns: [], nat: [], ingress: [], mss: [] };
  if (client) {
    rules.output.push(`-d ${c.address}/32 -o ${uplink} -p tcp --dport ${c.port} -j ACCEPT`, `-o ${c.tun} -j ACCEPT`);
    for (const proto of ['udp', 'tcp']) {
      for (const server of ['1.1.1.1', '8.8.8.8']) rules.dns.push(`-s ${address}/32 -d ${server}/32 -p ${proto} --dport 53 -m mark --mark 0x43564e -j ACCEPT`);
      // Includes 127.0.0.11 (Docker embedded resolver), never host DNS fallback.
      rules.dns.push(`-p ${proto} --dport 53 -j DNAT --to-destination ${address}:1053`);
      if (lan) {
        rules.ingress.push(`-s ${lan.subnet} -i ${lan.interface} -p ${proto} --dport 53 -j DNAT --to-destination ${address}:1053`);
        rules.input.push(`-s ${lan.subnet} -d ${address}/32 -i ${lan.interface} -p ${proto} --dport 1053 -m conntrack --ctstate DNAT -j ACCEPT`);
      }
    }
    if (lan) {
      rules.output.push(`-d ${lan.subnet} -o ${lan.interface} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`);
      rules.forward.push(`-s ${lan.subnet} -i ${lan.interface} -o ${c.tun} -j ACCEPT`,
        `-d ${lan.subnet} -i ${c.tun} -o ${lan.interface} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`);
      rules.nat.push(`-s ${lan.subnet} -o ${c.tun} -j SNAT --to-source ${address}`);
      for (const direction of [`-s ${lan.subnet} -i ${lan.interface} -o ${c.tun}`, `-d ${lan.subnet} -i ${c.tun} -o ${lan.interface}`])
        rules.mss.push(`${direction} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss ${mtu - 40}`);
    }
  } else {
    rules.input.push(`-d ${c.address}/32 -i ${uplink} -p tcp --dport ${c.port} -j ACCEPT`);
    rules.output.push(`-o ${uplink} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`);
    rules.forward.push(`-s 10.99.0.0/24 -i ${c.tun} -o ${uplink} -j ACCEPT`,
      `-d 10.99.0.0/24 -i ${uplink} -o ${c.tun} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`);
    rules.nat.push(`-s 10.99.0.0/24 -o ${uplink} -j MASQUERADE`);
  }
  const table = (family, name, entries) => ({ family, name, entries: entries.map(([hook, chain, body]) => ({ hook, chain, rules: body })) });
  const filter = names => names.map(([hook, body]) => [hook, `CVPN_R_${hook}`, [...body, '-j DROP']]);
  const tables = [table(6, 'filter', filter([['INPUT', ['-i lo -j ACCEPT']], ['OUTPUT', ['-o lo -j ACCEPT']], ['FORWARD', []]])),
    table(4, 'filter', filter([['INPUT', rules.input], ['OUTPUT', rules.output], ['FORWARD', rules.forward]])),
    table(4, 'nat', [['OUTPUT', 'CVPN_R_DNS', rules.dns], ['POSTROUTING', 'CVPN_R_NAT', rules.nat],
      ...(lan ? [['PREROUTING', 'CVPN_R_INGRESS', rules.ingress]] : [])]),
    ...(lan ? [table(4, 'mangle', [['FORWARD', 'CVPN_R_MSS', rules.mss]])] : [])];
  return { version: 1, role: c.role, uplink, mtu, address, endpoint: c.address, port: c.port, tun: c.tun,
    tunAddress: `${address}/${client ? 32 : 24}`, lan, forwarding: !client || lan !== null, tables };
}

export function restoreTable(t) {
  return `*${t.name}\n${t.entries.map(e => `:${e.chain} - [0:0]`).join('\n')}\n` +
    t.entries.flatMap(e => [`-I ${e.hook} 1 -j ${e.chain}`, ...e.rules.map(r => `-A ${e.chain} ${r}`)]).join('\n') + '\nCOMMIT\n';
}

// iptables normalizes -p tcp into -p tcp -m tcp; compare canonical tokens.
const canonical = line => line.replace(/ -m (tcp|udp)(?= |$)/g, '')
  .replace(/--ctstate ([A-Z,]+)/g, (_, states) => '--ctstate ' + states.split(',').sort().join(','))
  .replace(/\s+/g, ' ').trim();
export function auditRuntimeTables(plan, saved) {
  for (const t of plan.tables) {
    const lines = saved[`${t.family}/${t.name}`].split('\n').map(canonical);
    for (const e of t.entries) {
      assert.equal(lines.filter(l => l.startsWith(`-A ${e.hook} `))[0], `-A ${e.hook} -j ${e.chain}`, 'guard_not_first');
      const actual = lines.filter(l => l.startsWith(`-A ${e.chain} `));
      assert.deepEqual(actual, e.rules.map(r => canonical(`-A ${e.chain} ${r}`)), `guard_changed_${t.family}_${t.name}_${e.chain}: ${JSON.stringify(actual)}`);
      assert.equal(lines.filter(l => l.endsWith(`-j ${e.chain}`)).length, 1, 'guard_jump_changed');
    }
  }
}
