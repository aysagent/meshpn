import test from 'node:test';
import assert from 'node:assert/strict';
import { changeUsbSnat, usbSnatLine, usbSnatRule } from './clean-vpn-usb-snat.mjs';

function fixture() {
  const state = { rules: ['-P POSTROUTING ACCEPT', '-A POSTROUTING -o wlan0 -j MASQUERADE'], writes: [],
    forward: ['-P FORWARD ACCEPT', '-A FORWARD -m comment --comment cvks2-hook -j CLEANVPN_KS_FWD'],
    forwarding: '1', active: 'active', guard: [4, 6].map(f => `[clean-vpn-killswitch] IPv${f}: cvks2:both:block:tun0:154.62.226.216:22`).join('\n'),
    route: 'tun0', exitRoute: 'wlan0', addresses: [{ ifname: 'usb0', flags: ['UP'], address: '02:00:00:00:00:02', addr_info: [{ family: 'inet', local: '192.168.7.1', prefixlen: 24 }] },
      { ifname: 'tun0', flags: ['UP'], addr_info: [{ family: 'inet', local: '10.99.0.2' }] }] };
  state.run = (tool, args) => {
    if (tool === 'guard') return state.guard;
    if (tool === 'systemctl') return state.active;
    if (tool === 'sysctl') { assert.deepEqual(args, ['-n', 'net.ipv4.ip_forward']); return state.forwarding; }
    if (tool === 'ip') return JSON.stringify(args.includes('addr') ? state.addresses
      : args.includes('154.62.226.216') ? [{ dev: state.exitRoute, gateway: '192.168.1.1' }] : [{ dev: state.route }]);
    assert.equal(tool, 'iptables');
    if (args.includes('-S')) return (args.includes('nat') ? state.rules : state.forward).join('\n');
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
  assert.deepEqual(f.writes[0], ['-w', '5', '-t', 'nat', '-I', 'POSTROUTING', '1', ...usbSnatRule]);
  assert.equal(changeUsbSnat({ run: f.run, apply: true }).status, 'already-present'); assert.equal(f.writes.length, 1);
  // Removal remains possible after VPN is stopped; does not enable a direct path.
  f.active = 'inactive'; f.addresses = [];
  assert.equal(changeUsbSnat({ run: f.run, apply: true, remove: true }).status, 'removed');
  assert.deepEqual(f.rules, before);
  assert.equal(changeUsbSnat({ run: f.run, apply: true, remove: true }).status, 'absent');
});
for (const [name, mutate] of Object.entries({
  forwarding: f => { f.forwarding = '0'; }, inactive: f => { f.active = 'inactive'; },
  guard: f => { f.guard = ''; }, route: f => { f.route = 'wlan0'; },
  exitLoop: f => { f.exitRoute = 'tun0'; },
  usb: f => { f.addresses[0].address = '00:00:00:00:00:00'; }, tun: f => { f.addresses.pop(); },
  foreignNat: f => { f.rules.push('-A POSTROUTING -o tun0 -j MASQUERADE'); },
  duplicate: f => { f.rules.push(usbSnatLine, usbSnatLine); },
  shadowedGuard: f => { f.forward.splice(1, 0, '-A FORWARD -j ACCEPT'); },
  unknownForward: f => { f.forward.push('-A FORWARD -j DROP'); },
})) test(`refuses ${name} without writes`, () => {
  const f = fixture(); mutate(f);
  assert.throws(() => changeUsbSnat({ run: f.run, apply: true })); assert.equal(f.writes.length, 0);
});
