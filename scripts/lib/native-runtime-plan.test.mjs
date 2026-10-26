import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runtimePlan, restoreTable, auditRuntimeTables } from './native-runtime-plan.mjs';
import { cleanupLab } from '../clean-vpn-native-runtime-cleanup.mjs';
const client = { version: 1, role: 'client', address: '192.0.2.10', port: 443, tun: 'cvpn0', dns: true };
test('DNS catches Docker loopback resolver; only marked native upstreams bypass DNAT', () => {
  const p = runtimePlan(client), nat = restoreTable(p.tables[2]);
  assert.ok(nat.indexOf('--mark 0x43564e') < nat.indexOf('--to-destination'));
  assert.ok(!nat.includes('! -d 127.'));
  assert.equal(nat.match(/-j DNAT/g).length, 2);
  assert.ok(nat.includes('-I OUTPUT 1 -j CVPN_R_DNS'));
});
test('client has no generic established OUTPUT bypass and rejects forwarded gateway traffic', () => {
  const p = runtimePlan(client), filter = p.tables[1];
  const output = filter.entries.find(e => e.hook === 'OUTPUT');
  assert.ok(output.rules.every(r => !r.includes('ESTABLISHED')));
  assert.equal(output.rules.at(-1), '-j DROP');
  assert.deepEqual(filter.entries.find(e => e.hook === 'FORWARD').rules, ['-j DROP']);
  assert.ok(restoreTable(p.tables[0]).includes('-A CVPN_R_OUTPUT -j DROP'));
});
test('restart detects modified guard and a rule inserted ahead of it, preserves foreign tail rules', () => {
  const p = runtimePlan(client);
  const save = () => Object.fromEntries(p.tables.map(t => [`${t.family}/${t.name}`, restoreTable(t).replaceAll('-I ', '-A ').replaceAll(' 1 -j ', ' -j ') + '-A OUTPUT -j FOREIGN\n']));
  auditRuntimeTables(p, save());
  const changed = save(); changed['4/filter'] = '-A OUTPUT -j ACCEPT\n' + changed['4/filter'];
  assert.throws(() => auditRuntimeTables(p, changed), /guard_not_first/);
  const absent = save(); absent['4/filter'] = absent['4/filter'].replace('-A CVPN_R_OUTPUT -j DROP', '');
  assert.throws(() => auditRuntimeTables(p, absent), /guard_changed/);
});
test('unsafe role/config/transport/interface inputs fail before OS mutation', () => {
  for (const patch of [{ tun: 'eth0' }, { dns: false }, { transport: 'combo-tls' }, { port: 0 }, { address: '127.0.0.1' }, { peer_ipv4: '10.99.0.1' }])
    assert.throws(() => runtimePlan({ ...client, ...patch }));
  assert.throws(() => runtimePlan(client, { uplink: 'eth0; true' }));
});
test('exit accepts distinct peers on the native TUN and restricts reverse forwarding', () => {
  const p = runtimePlan({ ...client, role: 'exit', dns: false });
  assert.equal(p.tunAddress, '10.99.0.1/24');
  const rules = p.tables[1].entries.find(e => e.hook === 'FORWARD').rules;
  assert.ok(rules[1].includes('--ctstate ESTABLISHED,RELATED'));
  assert.ok(restoreTable(p.tables[2]).includes('-s 10.99.0.0/24 -o eth0 -j MASQUERADE'));
});
test('explicit LAN gateway forwards only through TUN and redirects ingress DNS', () => {
  const p = runtimePlan(client, { lan: { interface: 'eth1', subnet: '192.168.88.0/24' } });
  assert.equal(p.forwarding, true);
  const filter = restoreTable(p.tables[1]), nat = restoreTable(p.tables[2]);
  assert.ok(filter.includes('-s 192.168.88.0/24 -i eth1 -o cvpn0 -j ACCEPT'));
  assert.ok(!filter.includes('-i eth1 -o eth0 -j ACCEPT'));
  assert.ok(nat.includes('-A CVPN_R_INGRESS -s 192.168.88.0/24 -i eth1 -p udp --dport 53 -j DNAT'));
  assert.ok(nat.includes('-j SNAT --to-source 10.99.0.2'));
  assert.ok(restoreTable(p.tables[3]).includes('--set-mss 1360'));
  for (const lan of [{ interface: 'eth0', subnet: '192.168.88.0/24' }, { interface: 'eth1', subnet: '192.168.88.1/24' },
    { interface: 'eth1', subnet: '0.0.0.0/0' }]) assert.throws(() => runtimePlan(client, { lan }));
});
test('independent cleanup requires both an owned name and an owned label', () => {
  const prefix = 'cvpnrt-0123456789abcdef', journal = { schema: 1, kind: 'native-runtime-lab-ownership', prefix };
  const mutations = [];
  const fake = args => {
    if (args.includes('--filter')) return args[0] === 'ps' ? prefix + '-client\n' : '';
    if (args[0] === 'inspect') return JSON.stringify([{ Config: { Labels: { 'org.meshpn.native-runtime-lab': prefix } } }]);
    mutations.push(args); return '';
  };
  assert.equal(cleanupLab(journal, fake).removed.length, 1); assert.deepEqual(mutations, [['rm', '-f', prefix + '-client']]);
  assert.throws(() => cleanupLab(journal, args => args.includes('--filter') ? 'somebody-elses-vpn\n' : '{}'), /foreign_name_refused/);
  assert.throws(() => cleanupLab(journal, args => args.includes('--filter') ? prefix + '-client\n' : JSON.stringify([{ Config: { Labels: {} } }])), /foreign_label_refused/);
  assert.deepEqual(cleanupLab(journal, () => '').removed, []);
});
