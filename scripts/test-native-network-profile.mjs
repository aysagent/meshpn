import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { nativeNetworkPlan, assertEmptyNativeTables, canonicalNativeTables } from './lib/native-network-profile.mjs';
import { applyNativeNetworkProfile } from './lib/native-network-apply.mjs';
import { nativeNetworkUnit } from './lib/native-network-unit.mjs';
import { nativeSitePlan } from './lib/native-site-plan.mjs';
const client = { version: 1, role: 'client', tun: 'tun0', tun_address: '10.99.0.2/32', mtu: 1400, uplink: 'wan0', endpoint: '154.62.226.216', port: 443, lan: { interface: 'lan0', subnet: '192.168.7.0/24' } };
const exit = { ...client, role: 'exit', tun_address: '10.99.0.1/24', lan: null };
test('native client plan confines forwarding and SNAT, intercepts plain DNS, prevents recursive native DNS', () => {
  const p = nativeNetworkPlan(client);
  assert.match(p.ipv4, /:OUTPUT DROP/); assert.match(p.ipv6, /:FORWARD DROP/);
  assert.match(p.ipv4, /-A FORWARD -i lan0 -s 192.168.7.0\/24 -o tun0 -j ACCEPT/);
  assert.ok(!p.ipv4.includes('-A FORWARD -i lan0 -o wan0'));
  assert.match(p.nat, /-s 10.99.0.2\/32 -d 1.1.1.1\/32.*--mark 0x43564e -j ACCEPT/);
  assert.ok(!p.nat.includes('! -s'));
  assert.equal((p.nat.match(/--to-destination 10.99.0.2:1053/g) ?? []).length, 4);
  assert.match(p.nat, /-s 192.168.7.0\/24 -o tun0 -j SNAT --to-source 10.99.0.2/);
  assert.equal((p.mangle.match(/--set-mss 1360/g) ?? []).length, 2);
  assert.equal(p.forwarding, true);
});
test('exit confines forwarding/NAT to tunnel subnet and selected uplink', () => {
  const p = nativeNetworkPlan(exit);
  assert.match(p.nat, /-s 10.99.0.0\/24 -o wan0 -j MASQUERADE/);
  assert.match(p.ipv4, /-i tun0 -s 10.99.0.0\/24 -o wan0/);
  assert.ok(!p.nat.includes('DNAT')); assert.ok(!p.ipv4.includes(':OUTPUT ACCEPT'));
});
for (const [key, value] of [['tun', 'tun0;reboot'], ['tun_address', '10.99.0.2/24'], ['mtu', 500], ['port', 0], ['uplink', 'tun0'], ['endpoint', '224.0.0.22'], ['role', 'legacy'], ['extra', true]])
  test(`profile rejects ${key}`, () => assert.throws(() => nativeNetworkPlan({ ...client, [key]: value })));
test('only empty dedicated firewall can be claimed, no compatible adoption', () => {
  assertEmptyNativeTables('*filter\n:INPUT ACCEPT [3:40]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT');
  for (const s of [':OUTPUT DROP [0:0]', ':FOREIGN - [0:0]', '-A OUTPUT -j ACCEPT']) assert.throws(() => assertEmptyNativeTables(s));
  assert.equal(canonicalNativeTables('# time\n:INPUT ACCEPT [4:8]\n'), ':INPUT ACCEPT [0:0]');
});
function fixture() {
  let state = null, forward = '0', interfaces = ['wan0', 'lan0'].map((ifname, i) => ({ ifname, ifindex: i + 1, link_type: 'ether', flags: [] }));
  const commands = [], records = [], empty = '*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n';
  const tables = { ipv6: empty, ipv4: empty, nat: empty.replace('filter', 'nat'), mangle: empty.replace('filter', 'mangle') };
  const io = { scope: { boot: 'test', net: 'net:[1]', user: 'user:[1]' }, read: () => state,
    save: s => { state = structuredClone(s); records.push(state.stage); },
    run: (bin, args, input) => {
      commands.push([bin, args, input]);
      if (bin.endsWith('tables-save')) return args.length === 0 ? (bin.startsWith('ip6') ? tables.ipv6 : [tables.ipv4, tables.nat, tables.mangle].join('')) : tables[bin.startsWith('ip6') ? 'ipv6' : args[1] === 'filter' ? 'ipv4' : args[1]];
      if (bin.endsWith('tables-restore')) { if (args[0] !== '--test') { const key = input.match(/^\*(\w+)/)[1]; tables[bin.startsWith('ip6') ? 'ipv6' : key === 'filter' ? 'ipv4' : key] = input; } return ''; }
      if (['iptables', 'ip6tables'].includes(bin)) {
        const text = tables[bin.startsWith('ip6') ? 'ipv6' : args[3] === 'filter' ? 'ipv4' : args[3]];
        if (args[4] === '-C') return '';
        return text.split('\n').filter(l => l.startsWith(':') || l.startsWith('-A ')).map(l => l.startsWith(':') ? '-P ' + l.slice(1).split(' ').slice(0, 2).join(' ') : l).join('\n');
      }
      if (bin === 'sysctl') { if (args[0] === '-w') forward = '1'; return forward; }
      if (bin === 'ip') {
        if (args.join(' ') === '-j -d link show') return JSON.stringify(interfaces);
        if (args.includes('addr') && args.includes('-j')) return JSON.stringify([{ addr_info: [{ family: 'inet', local: '10.99.0.2', prefixlen: 32 }] }]);
        if (args[0] === 'tuntap') interfaces.push({ ifname: 'tun0', ifindex: 3, linkinfo: { info_kind: 'tun' }, flags: ['UP'], mtu: 1400 });
        return '';
      }
      throw Error('unexpected command');
    } };
  return { io, commands, records, tables, interfaces, state: () => state };
}
test('fresh lifecycle closes both families before TUN/forwarding and audits repeated start without writes', () => {
  const f = fixture(); assert.equal(applyNativeNetworkProfile(client, f.io).status, 'installed');
  assert.deepEqual(f.records, ['prepared', 'ipv6', 'ipv4', 'nat', 'mangle', 'tun', 'installed']);
  const close = f.commands.findIndex(([b, a]) => b === 'iptables-restore' && a[0] === '--wait');
  assert.ok(close < f.commands.findIndex(([b, a]) => b === 'ip' && a[0] === 'tuntap'));
  const count = f.commands.length; assert.equal(applyNativeNetworkProfile(client, f.io).status, 'verified');
  assert.ok(f.commands.slice(count).every(([b, a]) => b.endsWith('tables-save') || a[0] === '-j' || a[0] === '-n'));
});
for (const stage of ['prepared', 'ipv6', 'ipv4', 'nat', 'mangle', 'tun']) test(`cut at ${stage}: no blind partial replay or removal`, () => {
  const f = fixture(), save = f.io.save;
  f.io.save = s => { save(s); if (s.stage === stage) throw Error('cut'); };
  assert.throws(() => applyNativeNetworkProfile(client, f.io));
  const count = f.commands.length;
  assert.throws(() => applyNativeNetworkProfile(client, f.io), /partial_network_install/);
  assert.equal(f.commands.length, count);
});
test('foreign rule and live uplink rejected before writes', () => {
  for (const mutate of [f => { f.tables.ipv4 += '-A OUTPUT -j ACCEPT\n'; }, f => { f.interfaces[0].flags = ['UP']; }]) {
    const f = fixture(); mutate(f); assert.throws(() => applyNativeNetworkProfile(client, f.io));
    assert.equal(f.records.length, 0); assert.ok(!f.commands.some(([b]) => b.endsWith('restore')));
  }
});
test('same-boot restart refuses drift without modifying it', () => {
  for (const change of [f => { f.tables.ipv4 += '-A OUTPUT -j ACCEPT\n'; }, f => { f.interfaces[2].ifindex++; }, f => { f.io.scope.boot = 'next'; }]) {
    const f = fixture(); applyNativeNetworkProfile(client, f.io); change(f); const count = f.commands.length;
    assert.throws(() => applyNativeNetworkProfile(client, f.io));
    assert.ok(!f.commands.slice(count).some(([b]) => b.endsWith('restore')));
  }
});
test('network unit has no stop teardown and binds to externally prepared links', () => {
  const unit = nativeNetworkUnit({ script: '/opt/control/network.mjs', config: '/etc/native/client.json', linkUnit: 'site-links.service' });
  assert.match(unit, /BindsTo=site-links.service/); assert.match(unit, /RemainAfterExit=yes/);
  assert.ok(!unit.includes('ExecStop=')); assert.ok(!unit.includes('ProtectKernelTunables=yes'));
});
test('site binds engine/config/mark and gates uplink after profile; both roles', () => {
  for (const profile of [client, exit]) {
    const args = { name: 'site', target: '/opt/clean-vpn-native/site', site: { link_unit: 'links.service', profile }, engine: { role: profile.role, tun: 'tun0', address: profile.endpoint, port: 443, dns: true }, capability: { dns_socket_mark: '0x43564e' } };
    const plan = nativeSitePlan(args);
    assert.equal(plan.activation, 'native-site.target');
    assert.match(plan.units.get('native-site-uplink.service'), /Requires=native-site-network.service/);
    assert.match(plan.units.get('native-site-network.service'), /Requires=links.service/);
    assert.ok(!plan.units.get('native-site.service').includes('WantedBy='));
    assert.throws(() => nativeSitePlan({ ...args, engine: { ...args.engine, port: 444 } }));
    if (profile.role === 'client') {
      assert.throws(() => nativeSitePlan({ ...args, capability: {} }));
      assert.throws(() => nativeSitePlan({ ...args, engine: { ...args.engine, peer_ipv4: '10.99.0.3' } }));
    }
  }
});
test('boot observer outlives the target it stops; VM drivers refuse development host', () => {
  const source = fs.readFileSync(new URL('./lib/native-site-boot-vm.mjs', import.meta.url), 'utf8');
  assert.ok(source.includes('Wants=native-lab-defaults.service'));
  assert.ok(!source.includes('Requires=native-lab-defaults.service'));
  for (const file of ['native-site-boot-vm.mjs', 'native-site-vm-install.mjs']) {
    const r = spawnSync(process.execPath, ['scripts/lib/' + file, 'prepare'], { timeout: 3000, encoding: 'utf8' });
    assert.notEqual(r.status, 0); assert.ok(!r.error, 'fixture must exit rather than time out');
  }
  const r = spawnSync('sh', ['scripts/lib/native-network-vm.sh', 'network'], { timeout: 3000, encoding: 'utf8' });
  assert.notEqual(r.status, 0); assert.ok(!r.error);
});
