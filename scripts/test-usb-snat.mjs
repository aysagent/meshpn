import test from 'node:test';
import assert from 'node:assert/strict';
import { changeUsbSnat, usbSnatLine, usbSnatRule, usbMssLines, usbMssRules } from './clean-vpn-usb-snat.mjs';

function fixture() {
  const state = { rules: ['-P POSTROUTING ACCEPT', '-A POSTROUTING -o wlan0 -j MASQUERADE'], writes: [],
    mangle: ['-P FORWARD ACCEPT'],
    forward: ['-P FORWARD ACCEPT', '-A FORWARD -m comment --comment cvks2-hook -j CLEANVPN_KS_FWD'],
    forwarding: '1', active: 'active', guard: [4, 6].map(f => `[clean-vpn-killswitch] IPv${f}: cvks4:both:block:tun0:154.62.226.216:22`).join('\n'),
    route: 'tun0', exitRoute: 'wlan0', addresses: [{ ifname: 'usb0', flags: ['UP'], address: '02:00:00:00:00:02', addr_info: [{ family: 'inet', local: '192.168.7.1', prefixlen: 24 }] },
      { ifname: 'tun0', mtu: 1400, flags: ['UP'], addr_info: [{ family: 'inet', local: '10.99.0.2' }] }] };
  state.run = (tool, args) => {
    if (tool === 'guard') return state.guard;
    if (tool === 'systemctl') return state.active;
    if (tool === 'sysctl') { assert.deepEqual(args, ['-n', 'net.ipv4.ip_forward']); return state.forwarding; }
    if (tool === 'ip') return JSON.stringify(args.includes('addr') ? state.addresses
      : args.includes('154.62.226.216') ? [{ dev: state.exitRoute, gateway: '192.168.1.1' }] : [{ dev: state.route }]);
    assert.equal(tool, 'iptables');
    if (args.includes('-S')) return (args.includes('nat') ? state.rules : args.includes('mangle') ? state.mangle : state.forward).join('\n');
    if (args.includes('mangle')) {
      state.writes.push(args);
      const op = args.findIndex(a => a === '-A' || a === '-D');
      const line = '-A ' + args.slice(op + 1).join(' ');
      if (args[op] === '-A') state.mangle.push(line);
      else state.mangle = state.mangle.filter(l => l !== line);
      return '';
    }
    assert.ok(args.includes('nat'));
    state.writes.push(args);
    if (args.includes('-I')) state.rules.splice(1, 0, usbSnatLine);
    else { assert.ok(args.includes('-D')); state.rules = state.rules.filter(l => l !== usbSnatLine); }
    return '';
  };
  return state;
}
test('runtime-only SNAT is planned, applied once, and removed without touching other rules', () => {
  const f = fixture(), before = [...f.rules];
  assert.equal(changeUsbSnat({ run: f.run }).status, 'planned'); assert.equal(f.writes.length, 0);
  assert.equal(changeUsbSnat({ run: f.run, apply: true }).status, 'applied');
  assert.deepEqual(f.writes.slice(0, 2), usbMssRules.map(rule => ['-w', '5', '-t', 'mangle', '-A', 'FORWARD', ...rule]));
  assert.deepEqual(f.writes[2], ['-w', '5', '-t', 'nat', '-I', 'POSTROUTING', '1', ...usbSnatRule]);
  assert.equal(changeUsbSnat({ run: f.run, apply: true }).status, 'already-present'); assert.equal(f.writes.length, 3);
  // Removal remains possible after VPN is stopped; does not enable a direct path.
  f.active = 'inactive'; f.addresses = [];
  assert.equal(changeUsbSnat({ run: f.run, apply: true, remove: true }).status, 'removed');
  assert.deepEqual(f.rules, before);
  assert.deepEqual(f.mangle, ['-P FORWARD ACCEPT']);
  assert.equal(changeUsbSnat({ run: f.run, apply: true, remove: true }).status, 'absent');
});
test('canonical deny-only USB DNS prefixes coexist with the audited guard', () => {
  const f = fixture(), prefix = '-A FORWARD -s 192.168.7.0/24 -d 10.99.0.2/32 -i usb0 -p udp -m comment --comment clean-vpn-dns-tunnel-' + 'a'.repeat(24) + ' -m udp --dport 1053 -j REJECT --reject-with icmp-port-unreachable';
  f.forward.splice(1, 0, prefix);
  assert.equal(changeUsbSnat({ run: f.run }).status, 'planned');
  f.forward[1] = prefix.replace('REJECT --reject-with icmp-port-unreachable', 'ACCEPT');
  assert.throws(() => changeUsbSnat({ run: f.run, apply: true })); assert.equal(f.writes.length, 0);
});
for (const [name, mutate] of Object.entries({
  forwarding: f => { f.forwarding = '0'; }, inactive: f => { f.active = 'inactive'; },
  guard: f => { f.guard = ''; }, route: f => { f.route = 'wlan0'; },
  oldGuardWithoutUsbDnsProtection: f => { f.guard = f.guard.replaceAll('cvks4:', 'cvks2:'); },
  exitLoop: f => { f.exitRoute = 'tun0'; },
  usb: f => { f.addresses[0].address = '00:00:00:00:00:00'; }, tun: f => { f.addresses.pop(); },
  foreignNat: f => { f.rules.push('-A POSTROUTING -o tun0 -j MASQUERADE'); },
  duplicate: f => { f.rules.push(usbSnatLine, usbSnatLine); },
  wrongMtu: f => { f.addresses[1].mtu = 1500; },
  foreignMangle: f => { f.mangle.push('-A FORWARD -j ACCEPT'); },
  duplicateMss: f => { f.mangle.push(usbMssLines[0], usbMssLines[0]); },
  wrongMss: f => { f.mangle.push(usbMssLines[0].replace('1360', '1460')); },
  shadowedGuard: f => { f.forward.splice(1, 0, '-A FORWARD -j ACCEPT'); },
  unknownForward: f => { f.forward.push('-A FORWARD -j DROP'); },
})) test(`refuses ${name} without writes`, () => {
  const f = fixture(); mutate(f);
  assert.throws(() => changeUsbSnat({ run: f.run, apply: true })); assert.equal(f.writes.length, 0);
});
test('upgrades existing SNAT and repairs either partially installed MSS rule', () => {
  for (const present of [[], [usbMssLines[0]], [usbMssLines[1]]]) {
    const f = fixture(); f.rules.splice(1, 0, usbSnatLine); f.mangle.push(...present);
    const nat = [...f.rules];
    assert.equal(changeUsbSnat({ run: f.run }).mss.present, present.length);
    assert.equal(changeUsbSnat({ run: f.run, apply: true }).status, 'applied');
    assert.deepEqual(f.rules, nat);
    assert.ok(usbMssLines.every(l => f.mangle.includes(l)));
    assert.equal(f.writes.length, 2 - present.length);
  }
});
test('removes partial MSS even when SNAT is absent and VPN is down', () => {
  const f = fixture(); f.mangle.push(usbMssLines[1]); f.active = 'inactive';
  assert.equal(changeUsbSnat({ run: f.run, remove: true, apply: true }).status, 'removed');
  assert.deepEqual(f.mangle, ['-P FORWARD ACCEPT']);
});
test('NAT race before mutation refuses without installing MSS', () => {
  const f = fixture(); let reads = 0;
  const run = (tool, args) => {
    if (tool === 'iptables' && args.includes('nat') && args.includes('-S') && ++reads === 2) f.rules.push('-A POSTROUTING -j ACCEPT');
    return f.run(tool, args);
  };
  assert.throws(() => changeUsbSnat({ run, apply: true }), /NAT changed/);
  assert.equal(f.writes.length, 0);
});
test('failed second MSS write leaves recoverable own rule and does not add SNAT', () => {
  const f = fixture(); let writes = 0;
  const run = (tool, args) => {
    if (args.includes('mangle') && args.includes('-A') && ++writes === 2) throw Error('injected MSS failure');
    return f.run(tool, args);
  };
  assert.throws(() => changeUsbSnat({ run, apply: true }), /injected/);
  assert.ok(!f.rules.includes(usbSnatLine));
  assert.deepEqual(f.mangle, ['-P FORWARD ACCEPT', usbMssLines[0]]);
  assert.equal(changeUsbSnat({ run: f.run, apply: true }).status, 'applied');
  assert.equal(changeUsbSnat({ run: f.run }).status, 'already-present');
});
test('MSS race refuses before any writes; foreign rules are never removed', () => {
  const f = fixture(); let reads = 0;
  const run = (tool, args) => {
    if (args.includes('mangle') && args.includes('-S') && ++reads === 2) f.mangle.push('-A FORWARD -j ACCEPT');
    return f.run(tool, args);
  };
  assert.throws(() => changeUsbSnat({ run, apply: true }), /MSS changed/);
  assert.equal(f.writes.length, 0);
  assert.throws(() => changeUsbSnat({ run: f.run, apply: true, remove: true }), /unknown mangle/);
  assert.equal(f.writes.length, 0);
});
