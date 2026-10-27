import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gatewayPlan, validateGatewayConfig, canonicalGatewayRule } from './lib/native-runtime-gateway-plan.mjs';
const config = () => ({ schema: 1, ingress: { interface: 'wg0', subnet: '10.20.0.0/24' },
  bridge: { interface: 'vpnbr0', subnet: '192.168.88.0/24', host: '192.168.88.1', client: '192.168.88.2' },
  table: 19998, priority: 10998, bypass: ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'], dnsUid: 61453 });
test('selected interface and resolver only; guard precedes routes/NAT and no sysctl/default/resolver edits', () => {
  const p = gatewayPlan(config(), '123456789012345678901234'), words = p.operations.map(o => o.add[1].join(' '));
  assert.ok(p.operations.every(o => ['ip','iptables-nft','ip6tables-nft'].includes(o.add[0])));
  assert.ok(words.some(w => w.includes('iif wg0 lookup 19998')));
  assert.ok(words.indexOf('-w 5 -t filter -I FORWARD 1 -i wg0 -m comment --comment '+p.tag+' -j CVPN_GW') < p.operations.findIndex(o => o.kind === 'route'));
  assert.ok(words.some(w => w.includes('unreachable default')));
  const output = words.filter(w => / -[IA] OUTPUT /.test(w));
  assert.ok(output.length === 4 && output.every(w => w.includes('--uid-owner 61453') && w.includes('--dport 53')));
  for (const op of p.operations.filter(o => o.kind === 'route')) assert.ok(op.add[1].includes('19998'));
  assert.ok(words.filter(w => w.includes('-A CVPN_GW') || w.includes('-I CVPN_GW')).filter(w => /ACCEPT|RETURN/.test(w)).every(w => w.includes('-s 10.20.0.0/24')));
});
test('ambiguous/unsafe address scopes or DNS owner are refused', () => {
  for (const change of [c => c.dnsUid=0, c => c.ingress.subnet='0.0.0.0/1', c => c.ingress.subnet='10.99.0.0/24',
    c => c.ingress.subnet='192.168.88.0/24', c => c.bridge.host='192.168.88.0', c => c.bridge.client=c.bridge.host,
    c => c.priority=0, c => c.bypass=['0.0.0.0/1'], c => c.bridge.interface=c.ingress.interface, c => c.ingress.interface='wg0;id']) {
    const c=config();change(c);assert.throws(()=>validateGatewayConfig(c));
  }
  const c=config();c.dnsUid=null;assert.ok(gatewayPlan(c,'123456789012345678901234').operations.every(o=>!o.add[1].includes('OUTPUT')));
});
test('kernel rendering of owner/protocol/CIDR options preserves semantic rule identity', () => {
  assert.equal(canonicalGatewayRule('-A OUTPUT -m owner --uid-owner 61453 -p udp -d 192.168.88.2 -j ACCEPT'),
    canonicalGatewayRule('-A OUTPUT -d 192.168.88.2/32 -p udp -m udp -m owner --uid-owner 61453 -j ACCEPT'));
  assert.notEqual(canonicalGatewayRule('-A OUTPUT -d 192.168.88.2 -j DROP'),canonicalGatewayRule('-A OUTPUT -d 192.168.88.3 -j DROP'));
});
