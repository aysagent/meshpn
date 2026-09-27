import assert from 'node:assert/strict';
import test from 'node:test';
import { compileTunnelDnsPlan, TUNNEL_DNS_TABLE } from './lib/dns-tunnel-plan.mjs';

const text = (plan) => plan.operations.map((o) => `${o.file} ${o.args.join(' ')}`);
test('default host plan pins both DNS sources/routes, keeps stub loopback and avoids its own DNS loop', () => {
  const plan = compileTunnelDnsPlan({ tun: 'tun7' }), lines = text(plan);
  assert.deepEqual(plan.servers, ['1.1.1.1', '8.8.8.8']);
  assert.ok(lines.some((l) => l.includes(`unreachable default metric 32767 table ${TUNNEL_DNS_TABLE}`)));
  for (const [i, ip] of plan.servers.entries()) {
    assert.ok(lines.some((l) => l.includes(`route add ${ip}/32 dev tun7 src 10.99.0.2 table ${TUNNEL_DNS_TABLE}`)));
    assert.ok(lines.some((l) => l.includes(`priority ${10996 + i} from 10.99.0.2/32 to ${ip}/32 lookup ${TUNNEL_DNS_TABLE}`)));
    assert.ok(lines.some((l) => l.includes(`-s 10.99.0.2 -o tun7 -d ${ip} -j RETURN`)));
  }
  for (const protocol of ['udp', 'tcp']) {
    assert.ok(lines.some((l) => l.includes(`! -s 10.99.0.2 ! -d 127.0.0.0/8 -p ${protocol} --dport 53 -j CVPN-DNS-NAT`)));
    assert.ok(lines.some((l) => l.startsWith('ip6tables') && l.includes(`! -d ::1/128 -p ${protocol} --dport 53 -j REJECT`)));
    assert.ok(lines.some((l) => l.includes(`-d 10.99.0.2 -m addrtype ! --dst-type LOCAL -p ${protocol} --dport 1053 -j REJECT`)));
  }
  assert.ok(!lines.some((l) => l.includes('PREROUTING') || /sysctl|systemctl|resolv|route replace/.test(l)));
});
test('ingress DNS captures only requested interface, not gateway DNS, blocks local/IPv6 bypass', () => {
  const plan = compileTunnelDnsPlan({ tun: 'tun7', fromTun: 'wg0', primary: '9.9.9.9' }), lines = text(plan);
  assert.deepEqual(plan.servers, ['9.9.9.9', '8.8.8.8']);
  assert.ok(!lines.some((l) => l.includes('-t nat -I OUTPUT') || l.includes('ip6tables -w 5 -t filter -I OUTPUT')));
  for (const protocol of ['udp', 'tcp']) {
    assert.ok(lines.some((l) => l.includes(`PREROUTING 1 -m comment --comment clean-vpn-dns-tunnel -i wg0 -p ${protocol} --dport 53`)));
    assert.ok(lines.some((l) => l.includes(`OUTPUT 1 -m comment --comment clean-vpn-dns-tunnel -s 10.99.0.2 -p ${protocol} --dport 53`)));
    for (const hook of ['INPUT', 'FORWARD']) for (const tool of ['iptables', 'ip6tables'])
      assert.ok(lines.some((l) => l.startsWith(`${tool} `) && l.includes(`${hook} 1 -m comment --comment clean-vpn-dns-tunnel -i wg0 -p ${protocol} --dport 53 -j REJECT`)));
    assert.ok(lines.some((l) => l.includes(`-i wg0 -p ${protocol} -m conntrack --ctstate DNAT --ctorigdstport 53 -j ACCEPT`)));
  }
});
test('LAN selection requires an interface to guard IPv6 without inferring IPv6 from IPv4 subnet', () => {
  assert.throws(() => compileTunnelDnsPlan({ tun: 'tun7', lanSubnet: '192.168.7.0/24' }));
  const lines = text(compileTunnelDnsPlan({ tun: 'tun7', lanSubnet: '192.168.7.0/24', lanInterface: 'usb0' }));
  assert.ok(lines.some((l) => l.includes('-i usb0 -s 192.168.7.0/24 -p udp --dport 53 -j CVPN-DNS-NAT')));
  assert.ok(lines.some((l) => l.startsWith('ip6tables') && l.includes('-i usb0 -p udp --dport 53 -j REJECT')));
});
test('plan is deterministic, staged guard/route/activation and has exact inverses without flush/replace', () => {
  const plan = compileTunnelDnsPlan({ tun: 'tun7' });
  assert.deepEqual(plan, compileTunnelDnsPlan({ tun: 'tun7' }));
  assert.deepEqual(plan.operations.map((o) => o.stage), [...plan.operations.map((o) => o.stage)].sort((a, b) =>
    ['guard', 'route', 'activate'].indexOf(a) - ['guard', 'route', 'activate'].indexOf(b)));
  for (const op of plan.operations) {
    assert.ok(['ip', 'iptables', 'ip6tables'].includes(op.file));
    assert.ok(!op.args.some((v) => ['-F', '--flush', 'replace', 'flush'].includes(v)));
    assert.ok(op.remove.includes('-D') || op.remove.includes('-X') || op.remove.includes('del'));
  }
  assert.equal(compileTunnelDnsPlan({ tun: 'tun7', primary: '8.8.8.8' }).operations.filter((o) => o.file === 'ip' && o.args.includes('rule')).length, 1);
});
test('malformed scopes and server overrides are refused before producing a command plan', () => {
  for (const options of [{ tun: 'lo' }, { tun: 'bad name' }, { tun: 'tun7', fromTun: 'tun7' },
    { tun: 'tun7', fromTun: 'wg0', lanSubnet: '192.168.7.0/24', lanInterface: 'usb0' },
    { tun: 'tun7', primary: 'dns.example.com' }, { tun: 'tun7', lanSubnet: '192.168.7.1/24', lanInterface: 'usb0' },
    { tun: 'tun7', lanSubnet: '0.0.0.0/0', lanInterface: 'usb0' }]) assert.throws(() => compileTunnelDnsPlan(options));
});
