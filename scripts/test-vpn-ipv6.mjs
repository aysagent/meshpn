import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ipv6PacketAllowed, ipv6Plan, validateIpv6Options, isVpnIpv6Rule, overlapsVpnIpv6 } from './lib/vpn-ipv6.mjs';
import { validateIpv6State } from './lib/vpn-ipv6-runtime.mjs';
import { recoverIpv6 } from './clean-vpn-ipv6-recover.mjs';
const client = Buffer.from('fd426376706e00000000000000000002', 'hex'), global = Buffer.from('26064700470000000000000000001111', 'hex');
function packet(src = client, dst = global) { const b = Buffer.alloc(48); b[0] = 0x60; b.writeUInt16BE(8, 4); b[6] = 17; src.copy(b, 8); dst.copy(b, 24); return b; }
const config = role => ({ role, tun: 'tun0', ext: role === 'exit' ? 'eth0' : null, id: 'a'.repeat(24), forward: role === 'exit', tunForward: '0' });
test('internal ULA prefix collisions fail closed, including covering routes', () => {
  for (const cidr of ['fd42:6376:706e::/48', 'fc00::/7', 'fd42:6376:706e::1/128', 'fd42:6376:706e::3/128']) assert.ok(overlapsVpnIpv6(cidr), cidr);
  for (const cidr of ['default', '::/0', 'fe80::/10', 'fd42:6376:706e::4/126', '::ffff:192.0.2.1/128']) assert.equal(overlapsVpnIpv6(cidr), false, cidr);
});
test('IPv6 iproute2 rule JSON supports separate dstlen and rejects foreign selectors', () => {
  const r = { priority: 10995, src: 'all', dst: '2000::', dstlen: 3, table: '19997' };
  assert.ok(isVpnIpv6Rule(r)); assert.ok(isVpnIpv6Rule({ priority: 10995, src: 'all', dst: '2000::/3', table: '19997' }));
  assert.equal(isVpnIpv6Rule({ ...r, fwmark: '0x1' }), false); assert.equal(isVpnIpv6Rule({ ...r, dstlen: 32 }), false);
});
test('IPv6 source/destination isolation and strict frame lengths', () => {
  assert.ok(ipv6PacketAllowed(packet(), 'client', 'out')); assert.ok(ipv6PacketAllowed(packet(), 'exit', 'in'));
  assert.ok(ipv6PacketAllowed(packet(global, client), 'exit', 'out')); assert.ok(ipv6PacketAllowed(packet(global, client), 'client', 'in'));
  for (const p of [packet(global, global), packet().subarray(0, 47), Buffer.concat([packet(), Buffer.alloc(1)]), Buffer.alloc(40), Buffer.alloc(65536)])
    assert.equal(ipv6PacketAllowed(p, 'client', 'out'), false);
  const multicast = Buffer.alloc(16); multicast[0] = 255;
  assert.equal(ipv6PacketAllowed(packet(client, multicast), 'client', 'out'), false);
  assert.equal(ipv6PacketAllowed(packet(multicast, client), 'exit', 'out'), false);
  assert.equal(ipv6PacketAllowed(packet(), null, 'out'), false);
});
test('opt-in restricted before networking; existing modes unchanged', () => {
  const good = { ipv6: 'auto', role: 'client', type: 'tls', splitDefault: true, server: '192.0.2.1:443' };
  validateIpv6Options(good); validateIpv6Options({}); validateIpv6Options({ ...good, role: 'exit', splitDefault: false });
  for (const patch of [{ ipv6: 'yes' }, { type: 'combo-tls' }, { tlsRaw: true }, { splitDefault: false }, { fromTun: 'wg0' }, { clientLanSubnet: '10.0.0.0/24' }, { server: '[::1]:443' }])
    assert.throws(() => validateIpv6Options({ ...good, ...patch }));
});
test('guard fully populated before hook, hook before routing; no global forwarding changes', () => {
  const plan = ipv6Plan(config('client'));
  assert.equal(plan[0].kind, 'chain');
  const hook = plan.findIndex(p => p.args.includes('OUTPUT'));
  assert.ok(plan[hook - 1].args.includes('REJECT')); assert.ok(hook < plan.findIndex(p => p.kind === 'addr'));
  for (const role of ['client', 'exit']) for (const op of ipv6Plan(config(role))) {
    assert.ok(op.remove); assert.ok(!op.args.some(a => a.includes('/all/') || a.includes('/default/')));
  }
  assert.throws(() => ipv6Plan({ ...config('exit'), tunForward: '1;sh' }));
});
test('journal rejects executable payloads, invalid cursor and interfaces', () => {
  const state = { schema: 1, scope: { boot: 'a'.repeat(36), net: 'net:[1]', user: 'user:[2]' }, config: config('client'),
    links: { tun0: { ifindex: 2, address: '', type: 'none' } }, backend: 'legacy', count: 0, dynamic: false, stage: 'installing' };
  validateIpv6State(state);
  for (const patch of [{ argv: ['sh'] }, { count: 999 }, { stage: 'anything' }, { config: { ...state.config, tun: '../all' } }, { stage: 'released', count: 1 }])
    assert.throws(() => validateIpv6State({ ...state, ...patch }));
});
test('recovery defaults to audit and always releases lock', () => {
  let applied = 0, closed = 0, audited = 0;
  const open = () => ({ state: { stage: 'active', count: 11, dynamic: true }, audit() { audited++; }, restore() { applied++; }, release() { closed++; } });
  assert.equal(recoverIpv6([], open).mode, 'dry-run'); assert.equal(applied, 0);
  recoverIpv6(['--apply'], open); assert.equal(applied, 1); assert.equal(closed, 2); assert.equal(audited, 2);
  assert.throws(() => recoverIpv6(['--apply', '--apply'], open));
});
test('both bridges apply IPv6 ingress and egress validation', () => {
  const src = readFileSync(new URL('./clean-vpn.js', import.meta.url), 'utf8');
  assert.equal(src.split("ipv6PacketAllowed(pkt, bridgeOpts.ipv6Role, 'in')").length - 1, 2);
  assert.equal(src.split("ipv6PacketAllowed(pkt, bridgeOpts.ipv6Role, 'out')").length - 1, 2);
});
