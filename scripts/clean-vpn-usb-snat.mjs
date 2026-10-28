#!/usr/bin/env node
/** Narrow, runtime-only SNAT + TCP MSS for the reviewed Radxa host-client profile.
 * No service, route, forwarding sysctl, filter, USB or IPv6 changes.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const usbSnatRule = ['-s', '192.168.7.0/24', '-o', 'tun0', '-m', 'comment',
  '--comment', 'clean-vpn-usb-snat-v1', '-j', 'SNAT', '--to-source', '10.99.0.2'];
export const usbSnatLine = '-A POSTROUTING ' + usbSnatRule.join(' ');
// IPv4 MTU 1400 minus the base IP/TCP headers. TCP timestamp/options are
// accounted for by the endpoints. Both SYN and SYN/ACK must be constrained:
// the peer's advertised MSS limits downloads, the return MSS limits uploads.
export const usbMssRules = [
  ['-s', '192.168.7.0/24', '-i', 'usb0', '-o', 'tun0'],
  ['-d', '192.168.7.0/24', '-i', 'tun0', '-o', 'usb0'],
].map(scope => [...scope, '-p', 'tcp', '-m', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN',
  '-m', 'comment', '--comment', 'clean-vpn-usb-mss-v1', '-j', 'TCPMSS', '--set-mss', '1360']);
export const usbMssLines = usbMssRules.map(rule => '-A FORWARD ' + rule.join(' '));
const binaries = { ip: '/usr/sbin/ip', iptables: '/usr/sbin/iptables', sysctl: '/usr/sbin/sysctl',
  systemctl: '/usr/bin/systemctl', guard: '/usr/local/bin/clean-vpn-killswitch.sh' };
const execute = (name, args) => execFileSync(binaries[name], args, { encoding: 'utf8', timeout: 10000,
  maxBuffer: 128 * 1024, env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' } });

export function changeUsbSnat({ apply = false, remove = false, nativeUnit = null, run = execute } = {}) {
  assert.ok(nativeUnit === null || /^native-[a-z][a-z0-9-]{0,31}\.service$/.test(nativeUnit), 'invalid native unit');
  const nat = (...args) => run('iptables', ['-w', '5', '-t', 'nat', ...args]);
  const snapshot = () => nat('-S', 'POSTROUTING').trim().split('\n');
  const before = snapshot();
  const mangle = (...args) => run('iptables', ['-w', '5', '-t', 'mangle', ...args]);
  const mssSnapshot = () => mangle('-S', 'FORWARD').trim().split('\n');
  let mssBefore = mssSnapshot();
  assert.equal(mssBefore[0], '-P FORWARD ACCEPT', 'unexpected mangle FORWARD policy');
  assert.ok(mssBefore.slice(1).every(line => usbMssLines.includes(line)),
    'unknown mangle FORWARD rules: manual review required (remove temporary MSS test first)');
  for (const line of usbMssLines) assert.ok(mssBefore.filter(l => l === line).length <= 1,
    'duplicate owned MSS rules: no changes');
  const mssPresent = usbMssLines.filter(line => mssBefore.includes(line)).length;
  assert.equal(before[0], '-P POSTROUTING ACCEPT', 'unexpected NAT policy');
  assert.ok(before.every(line => ['-P POSTROUTING ACCEPT', '-A POSTROUTING -o wlan0 -j MASQUERADE',
    usbSnatLine].includes(line)), 'unknown POSTROUTING rules: manual review required');
  const matches = before.filter(line => line === usbSnatLine).length;
  assert.ok(matches <= 1, 'duplicate owned SNAT rules: no changes');
  if (!remove) {
    for (const unit of [nativeUnit ?? 'clean-vpn.service', 'clean-vpn-killswitch.service',
      'clean-vpn-usb-rescue.socket', 'clean-vpn-usb-rescue-address.service']) {
      assert.equal(run('systemctl', ['is-active', unit]).trim(), 'active', `${unit} must be active`);
    }
    if (nativeUnit) {
      const prop=(u,k)=>run('systemctl',['show',u,'-p',k,'--value']).trim();
      assert.ok(['inactive','failed'].includes(prop('clean-vpn.service','ActiveState')) && prop('clean-vpn.service','MainPID')==='0','legacy must be quiesced');
      assert.equal(prop(nativeUnit,'Type'),'notify','native notify service required');
      assert.match(prop(nativeUnit,'MainPID'),/^[1-9][0-9]*$/,'native process required');
      assert.ok(['ready','idle_wait'].includes(prop(nativeUnit,'StatusText')),'native tunnel not authenticated');
      const bound=prop(nativeUnit,'BindsTo').split(/\s+/);
      assert.ok(bound.includes('clean-vpn-killswitch.service')&&bound.some(u=>u!== 'clean-vpn-killswitch.service'),'native lifecycle dependencies required');
      for(const u of bound)assert.equal(prop(u,'ActiveState'),'active','native dependency inactive');
    }
    const guard = run('guard', ['status']).trim().split('\n');
    for (const family of [4, 6]) assert.ok(guard.includes(
      `[clean-vpn-killswitch] IPv${family}: cvks4:both:block:tun0:154.62.226.216:22`), 'unexpected guard profile');
    assert.equal(run('sysctl', ['-n', 'net.ipv4.ip_forward']).trim(), '1', 'IPv4 forwarding must already be enabled');
    const addresses = JSON.parse(run('ip', ['-j', 'addr', 'show']));
    const usb = addresses.find(i => i.ifname === 'usb0'), tun = addresses.find(i => i.ifname === 'tun0');
    assert.ok(usb?.flags.includes('UP') && usb.address === '02:00:00:00:00:02'
      && usb.addr_info.some(a => a.family === 'inet' && a.local === '192.168.7.1' && a.prefixlen === 24), 'unexpected USB interface');
    assert.ok(tun?.flags.includes('UP') && tun.addr_info.some(a => a.family === 'inet' && a.local === '10.99.0.2'), 'TUN not ready');
    assert.equal(tun.mtu, 1400, 'reviewed TCP MSS profile requires TUN MTU 1400');
    const exitRoute = JSON.parse(run('ip', ['-j', '-4', 'route', 'get', '154.62.226.216']))[0];
    assert.ok(exitRoute?.dev === 'wlan0' && exitRoute.gateway, 'exit bypass not ready; restore host VPN first');
    for (const destination of ['1.1.1.1', '34.160.111.145']) {
      const routes = JSON.parse(run('ip', ['-j', '-4', 'route', 'get', destination, 'from', '192.168.7.19', 'iif', 'usb0']));
      assert.equal(routes[0]?.dev, 'tun0', 'forwarded route must use TUN');
    }
    const forward = run('iptables', ['-w', '5', '-t', 'filter', '-S', 'FORWARD']).trim().split('\n');
    assert.equal(forward[0], '-P FORWARD ACCEPT', 'unexpected FORWARD policy');
    // status above already audits canonical guard chains and their prefixes.
    // USB tunnel-DNS installs only scoped REJECTs ahead of the guard hook.
    const hook = forward.indexOf('-A FORWARD -m comment --comment cvks2-hook -j CLEANVPN_KS_FWD');
    assert.ok(hook >= 1 && forward.slice(1, hook).every(line => /^-A FORWARD -s 192\.168\.7\.0\/24 (?:-d 10\.99\.0\.2\/32 )?-i usb0 -p (tcp|udp) -m comment --comment clean-vpn-dns-tunnel(?:-[a-f0-9]{24})? -m \1 --dport (53|1053) -j REJECT --reject-with icmp-port-unreachable$/.test(line)), 'guard must precede forwarding');
    assert.ok(forward.slice(hook + 1).every(line => ['-A FORWARD -i usb0 -o wlan0 -j ACCEPT',
      '-A FORWARD -i wlan0 -o usb0 -j ACCEPT'].includes(line)), 'unknown FORWARD rules');
  }
  const needed = remove ? matches === 1 || mssPresent > 0 : matches === 0 || mssPresent !== 2;
  // Repair a partial own installation idempotently. Never flush foreign rules.
  // Failures retain the guard; re-running completes a partially applied bundle.
  const updateMss = () => {
    for (const [i, line] of usbMssLines.entries()) {
      if (mssBefore.includes(line) === !remove) continue;
      assert.deepEqual(mssSnapshot(), mssBefore, 'MSS changed during application');
      mangle(remove ? '-D' : '-A', 'FORWARD', ...usbMssRules[i]);
      mssBefore = remove ? mssBefore.filter(l => l !== line) : [...mssBefore, line];
      assert.deepEqual(mssSnapshot(), mssBefore, 'unexpected MSS after change; inspect rules');
    }
  };
  if (apply && needed) {
    assert.deepEqual(snapshot(), before, 'NAT changed during preflight');
    assert.deepEqual(mssSnapshot(), mssBefore, 'MSS changed during preflight');
    if (!remove) updateMss(); // constrain new connections before enabling SNAT
    assert.deepEqual(snapshot(), before, 'NAT changed during MSS application');
    if (remove ? matches === 1 : matches === 0) {
      nat(...(remove ? ['-D', 'POSTROUTING'] : ['-I', 'POSTROUTING', '1']), ...usbSnatRule);
      assert.deepEqual(snapshot(), remove ? before.filter(line => line !== usbSnatLine)
        : [before[0], usbSnatLine, ...before.slice(1)], 'unexpected NAT after change; inspect rules, no automatic rollback');
    }
    if (remove) updateMss();
  }
  return { status: !needed ? (remove ? 'absent' : 'already-present') : !apply ? 'planned' : remove ? 'removed' : 'applied',
    persistent: false, rule: usbSnatLine, changed: apply && needed,
    mss: { value: 1360, tunMtu: 1400, rules: usbMssLines,
      present: apply ? (remove ? 0 : 2) : mssPresent },
    untouched: ['services', 'USB/SSH', 'routes', 'forwarding sysctl', 'filter/kill-switch', 'IPv6'],
    limitations: ['reviewed-Radxa-profile-only', 'no-concurrent-firewall-administrators',
      'runtime-only-lost-on-reboot', 'TCP-MSS-only-not-UDP-PMTU-repair', 'not-forwarded-client-leak-acceptance'] };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    let args = process.argv.slice(2);
    const selected=args.filter(a=>a.startsWith('--native-unit='));assert.ok(selected.length<=1,'duplicate native unit');
    const nativeUnit=selected[0]?.slice('--native-unit='.length)??null;
    args=args.filter(a=>!a.startsWith('--native-unit='));
    assert.ok(args.every(a => ['--apply', '--remove', '--status'].includes(a)) && new Set(args).size === args.length, 'use [--remove] [--apply] or --status');
    assert.ok(!args.includes('--status') || args.length === 1, '--status is read-only');
    assert.equal(process.getuid?.(), 0, 'root required');
    assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd', 'systemd host required');
    assert.equal(fs.readlinkSync('/proc/self/ns/net'), fs.readlinkSync('/proc/1/ns/net'), 'host network namespace required');
    const result = changeUsbSnat({ apply: args.includes('--apply'), remove: args.includes('--remove'), nativeUnit });
    if (args.includes('--status')) {
      result.status = result.status === 'already-present' ? 'ready' : 'incomplete';
      if (result.status !== 'ready') process.exitCode = 1;
    }
    console.log(JSON.stringify(result, null, 2));
  } catch (error) { console.error(JSON.stringify({ status: 'refused-or-incomplete', error: error.message })); process.exitCode = 1; }
}
