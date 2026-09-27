import assert from 'node:assert/strict';
import test from 'node:test';
import { parseTunnelDnsConntrack, resetTunnelDnsConntrack } from './lib/dns-tunnel-conntrack.mjs';

const line = ({ protocol = 'udp', src = '10.44.0.2', dst = '1.1.1.1', sport = 50001,
  replySrc = dst, replySport = 53, replyDst = src, replyDport = sport, zone = 0 } = {}) =>
  `ipv4 2 ${protocol} ${protocol === 'udp' ? 17 : 6} 30 src=${src} dst=${dst} sport=${sport} dport=53 src=${replySrc} dst=${replyDst} sport=${replySport} dport=${replyDport} [ASSURED] mark=0 zone=${zone} use=1`;
function fixture(input, { returnInterface = 'wg0', failDelete = false, expires = false } = {}) {
  const entries = [...input], mutations = [];
  const run = (file, args) => {
    if (file === 'ip') {
      if (args.includes('addr')) return JSON.stringify([{ addr_info: [{ family: 'inet', local: '192.0.2.1' }, { family: 'inet', local: '10.99.0.2' }] }]);
      return JSON.stringify([{ dst: args.at(-1), dev: returnInterface }]);
    }
    assert.equal(file, 'conntrack');
    if (args[0] === '-L') return entries.filter((s) => s.includes(` ${args[args.indexOf('-p') + 1]} `)).join('\n');
    assert.equal(args[0], '-D'); assert.ok(!args.includes('-F')); mutations.push(args);
    const match = (s) => {
      if (!s.includes(` ${args[args.indexOf('-p') + 1]} `)) return false;
      const e = parseTunnelDnsConntrack(s, args[args.indexOf('-p') + 1])[0];
      return args[args.indexOf('--orig-src') + 1] === e.src && Number(args[args.indexOf('--orig-port-src') + 1]) === e.sport;
    };
    if (!failDelete || expires) entries.splice(entries.findIndex(match), 1);
    if (failDelete) throw Object.assign(new Error('delete failed'), { status: 1 });
    return '';
  };
  return { entries, mutations, run };
}
test('parser validates both tuples, ports, protocol, bounded size and zone before mutation', () => {
  assert.equal(parseTunnelDnsConntrack(line(), 'udp')[0].sport, 50001);
  for (const text of [line({ zone: 2 }), line({ src: 'host.example' }), line({ sport: 70000 }),
    line().replace('dport=53', 'dport=443'), line().replace('udp 17', 'tcp 6'), `${line()} src=1.2.3.4`, ' '.repeat(262145),
    Array(129).fill(line()).join('\n')]) assert.throws(() => parseTunnelDnsConntrack(text, 'udp'));
});
test('enable deletes only stale DNS for selected ingress, not gateway DNS or correct DNAT', () => {
  const f = fixture([line(), line({ src: '192.0.2.1' }), line({ replySrc: '10.99.0.2', replySport: 1053, sport: 50002 })]);
  const r = resetTunnelDnsConntrack({ tun: 'tun0', fromTun: 'wg0' }, 'enable', f.run);
  assert.equal(r.deleted, 1); assert.equal(f.entries.length, 2);
  const args = f.mutations[0];
  for (const flag of ['--orig-src', '--orig-dst', '--orig-port-src', '--orig-port-dst', '--reply-src', '--reply-dst', '--reply-port-src', '--reply-port-dst', '-w']) assert.ok(args.includes(flag));
});
test('host scope leaves forwarded DNS untouched and excludes loopback and forwarder exchanges', () => {
  const f = fixture([line({ src: '192.0.2.1' }), line(), line({ src: '10.99.0.2' }), line({ src: '192.0.2.1', dst: '127.0.0.53' })]);
  assert.equal(resetTunnelDnsConntrack({ tun: 'tun0' }, 'enable', f.run).deleted, 1);
  assert.equal(f.entries.length, 3);
});
test('LAN requires both source subnet and matching return interface; asymmetric sources are not guessed', () => {
  const config = { tun: 'tun0', lanSubnet: '10.44.0.0/24', lanInterface: 'usb0' };
  const f = fixture([line(), line({ src: '10.45.0.2' })], { returnInterface: 'usb0' });
  assert.equal(resetTunnelDnsConntrack(config, 'enable', f.run).deleted, 1);
  const other = fixture([line()], { returnInterface: 'eth0' });
  assert.equal(resetTunnelDnsConntrack(config, 'enable', other.run).deleted, 0);
});
test('disable removes only captured DNS, never old baseline or unrelated listener tuples', () => {
  const f = fixture([line(), line({ replySrc: '10.99.0.2', replySport: 1053, sport: 50002 }),
    line({ replySrc: '10.99.0.2', replySport: 8053, sport: 50003 })]);
  assert.equal(resetTunnelDnsConntrack({ tun: 'tun0', fromTun: 'wg0' }, 'disable', f.run).deleted, 1);
  assert.equal(f.entries.length, 2);
});
test('delete failure must prove tuple absent; only natural expiry is accepted', () => {
  for (const expires of [false, true]) {
    const f = fixture([line()], { failDelete: true, expires });
    const action = () => resetTunnelDnsConntrack({ tun: 'tun0', fromTun: 'wg0' }, 'enable', f.run);
    if (expires) assert.equal(action().deleted, 1); else assert.throws(action, /remains/);
  }
});
test('preflight only reads; unsupported zone fails before any deletion', () => {
  const f = fixture([line()]); assert.equal(resetTunnelDnsConntrack({ tun: 'tun0' }, 'preflight', f.run).deleted, 0);
  assert.equal(f.mutations.length, 0);
  const bad = fixture([line({ zone: 1 })]); assert.throws(() => resetTunnelDnsConntrack({ tun: 'tun0' }, 'enable', bad.run));
  assert.equal(bad.mutations.length, 0);
});
test('TCP DNS uses the same exact tuple scope; unrelated UDP DNS remains untouched', () => {
  const f = fixture([line({ protocol: 'tcp' }), line({ src: '192.0.2.1' })]);
  assert.equal(resetTunnelDnsConntrack({ tun: 'tun0', fromTun: 'wg0' }, 'enable', f.run).deleted, 1);
  assert.equal(f.mutations[0][f.mutations[0].indexOf('-p') + 1], 'tcp'); assert.equal(f.entries.length, 1);
});
