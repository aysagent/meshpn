// Network control only. All tunnel/TLS/DNS payload processing remains native.
import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';
import {validateRelayHealth} from './native-relay-health.mjs';
import { validateTransparentNetworkProfile, transparentSpecialIPv4 } from './native-transparent-network.mjs';
const privateDnsOutput=tun=>['udp','tcp'].map(proto=>`-s 10.99.0.1/32 -d 10.99.0.0/24 -o ${tun} -p ${proto} --sport 1055 -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT`);

// Shared by provisioning and health. Full credential/schema validation remains
// in the native engine, before the runtime performs network mutations.
export function runtimePacketConfig(c) {
  if (c.transport !== 'combo-tls') return c;
  assert.deepEqual(Object.keys(c).sort(), ['boring', 'role', 'transparent', 'transport', 'version']);
  assert.equal(c.version, 1);
  const p = c.boring, r = c.transparent;
  assert.equal(p.role, c.role); assert.equal(r.role, c.role);
  assert.equal(r.version, 1); assert.equal(r.transport, 'transparent-tls');
  assert.equal(r.destination_policy?.mode, 'public-https', 'runtime_combo_requires_public_https');
  assert.equal(r.destinations, undefined);
  if(r.secret_path!==undefined)assert.notEqual(p.secret_path, r.secret_path, 'combo_separate_keys_required');
  if (c.role === 'client') {
    assert.equal(r.exit.ipv4, p.address); assert.equal(r.exit.port, p.port);
    assert.equal(p.sni, r.public_name);
    assert.notEqual(r.listen.port, 1053, 'relay_dns_listener_collision');
  } else {
    assert.equal(r.listen.ipv4, p.address); assert.equal(r.listen.port, p.port);
    assert.equal(typeof r.replay_directory, 'string');
  }
  return p;
}

function comboRuntimePlan(c, options) {
  const packet = runtimePacketConfig(c), r = c.transparent;
  const {relayHealth=null,...packetOptions}=options;
  const plan = runtimePlan(packet, packetOptions), client = c.role === 'client';
  if (client) {
    assert.ok(plan.lan, 'combo_runtime_requires_explicit_lan');
    assert.equal(r.listen.ipv4, '0.0.0.0', 'combo_runtime_lan_listener_required');
  }
  validateTransparentNetworkProfile({ version: 1, transport: 'transparent-tls', role: c.role,
    uplink: plan.uplink, endpoint: packet.address, port: packet.port, listen_port: r.listen.port,
    lan: plan.lan, deny_ipv4: r.destination_policy.deny_ipv4 });
  const filter = plan.tables.find(t => t.family === 4 && t.name === 'filter');
  const chain = hook => filter.entries.find(e => e.hook === hook).rules;
  const denied = [...transparentSpecialIPv4, ...r.destination_policy.deny_ipv4, packet.address + '/32'];
  if (client) {
    const from = `-s ${plan.lan.subnet} -i ${plan.lan.interface}`;
    const ingress = plan.tables.find(t => t.family === 4 && t.name === 'nat').entries.find(e => e.hook === 'PREROUTING').rules;
    for (const dst of denied) ingress.push(`-s ${plan.lan.subnet} -d ${dst} -i ${plan.lan.interface} -j RETURN`);
    ingress.push(`${from} -m addrtype --dst-type LOCAL -j RETURN`,
      `${from} -p tcp --dport 443 -j REDIRECT --to-ports ${r.listen.port}`);
    chain('INPUT').splice(-1, 0, `${from} -p tcp --dport ${r.listen.port} -m conntrack --ctstate DNAT -j ACCEPT`);
    // An ineligible HTTPS destination must never fall through to the TUN.
    chain('FORWARD').unshift(`${from} -p tcp --dport 443 -j DROP`);
    if(relayHealth){
      validateRelayHealth(relayHealth,r);
      const relayHealthSource=plan.address;
      const output=chain('OUTPUT');
      output.unshift(`-s ${relayHealthSource}/32 -d 127.0.0.1/32 -p tcp --dport ${r.listen.port} -m conntrack --ctstate DNAT -j ACCEPT`,`-s ${relayHealthSource}/32 -d ${relayHealth.ipv4}/32 -p tcp --dport 443 -j DROP`);
      plan.tables.find(t=>t.family===4&&t.name==='nat').entries.find(e=>e.hook==='OUTPUT').rules.unshift(
        `-s ${relayHealthSource}/32 -d ${relayHealth.ipv4}/32 -p tcp --dport 443 -j REDIRECT --to-ports ${r.listen.port}`);
    }
  } else {
    assert.equal(relayHealth,null,'relay_health_client_only');
    const output = chain('OUTPUT');
    output.splice(0, output.length, '-o lo -j ACCEPT',
      ...(packet.private_peer_dns?privateDnsOutput(packet.tun):[]),
      `-s ${packet.address}/32 -o ${plan.uplink} -p tcp --sport ${packet.port} -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT`,
      ...denied.map(dst => `-d ${dst} -o ${plan.uplink} -j DROP`),
      `-o ${plan.uplink} -p tcp --dport 443 -j ACCEPT`, '-j DROP');
  }
  return { ...plan, transport: 'combo-tls', relayPort: r.listen.port, relayHealth };
}

export function runtimePlan(c, { uplink = 'eth0', mtu = 1400, lan = null, relayHealth = null } = {}) {
  if (c.transport === 'combo-tls') return comboRuntimePlan(c, { uplink, mtu, lan, relayHealth });
  assert.equal(relayHealth,null,'relay_health_combo_only');
  assert.equal(c.version, 1);
  assert.ok(['client', 'exit'].includes(c.role));
  if('private_peer_dns' in c){assert.equal(c.role,'exit','private_peer_dns_exit_only');assert.equal(typeof c.private_peer_dns,'boolean');}
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
      // OUTPUT can retain the original uplink interface after local DNS DNAT
      // (e.g. Podman's bridge resolver). Permit only the translated local stub.
      rules.output.push(`-d ${address}/32 -p ${proto} --dport 1053 -m addrtype --dst-type LOCAL -m conntrack --ctstate DNAT -j ACCEPT`);
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
    if(c.private_peer_dns){for(const proto of ['udp','tcp'])rules.input.push(`-s 10.99.0.0/24 -d 10.99.0.1/32 -i ${c.tun} -p ${proto} --dport 1055 -j ACCEPT`);rules.output.push(...privateDnsOutput(c.tun));}
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

// Static-IP container recreation may change the link address while peers still
// cache its predecessor. Announce only addresses actually assigned to our two
// approved interfaces; never flush a peer/host neighbor table.
export function runtimeAnnouncements(plan, links) {
  const commands = [];
  for (const iface of [plan.uplink, ...(plan.lan ? [plan.lan.interface] : [])]) {
    const matches = links.filter(l => l.ifname === iface);
    assert.equal(matches.length, 1, 'announcement_interface_missing');
    const addresses = matches[0].addr_info.filter(a => a.family === 'inet');
    assert.ok(addresses.length > 0 && addresses.length <= 8, 'bounded_interface_addresses_required');
    for (const a of addresses) {
      assert.ok(isIPv4(a.local) && !/^(0|127)\./.test(a.local));
      commands.push(['-q', '-U', '-c', '2', '-w', '2', '-I', iface, a.local]);
    }
  }
  return commands;
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
