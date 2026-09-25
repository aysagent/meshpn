import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { inspectIngress, installIngressRouting, validateFromTun, INGRESS_BYPASS } from './lib/ingress-routing.mjs';

const base = { fromTun: 'wg0', role: 'client', type: 'tls' };
const ingress = { name: 'wg0', bypass: [...INGRESS_BYPASS] };

test('from-tun validation is transport-independent; conflicting scope/test flags rejected', () => {
  for (const type of ['tls', 'boring-tls', 'combo-tls', 'transparent-tls', 'udp', 'quic', 'webrtc', 'ws-chrome']) validateFromTun({ ...base, type });
  for (const fromTun of ['', 'lo', '-wg', 'wg+', 'a/b', 'a b', 'a'.repeat(16)]) assert.throws(() => validateFromTun({ ...base, fromTun }));
  for (const override of [{ role: 'exit' }, { splitDefault: true }, { clientLanSubnet: '10.0.0.0/24' },
    { transparentTlsLanBind: '10.0.0.1' }, { type: 'combo-tls', tunnelPeer: '1.1.1.1' }]) {
    assert.throws(() => validateFromTun({ ...base, ...override }));
  }
});

function inspector(overrides = {}) {
  return (file, args) => {
    if (file === 'sysctl') return overrides.forward ?? '1';
    if (file === 'iptables' || file === 'ip6tables') return overrides.firewall ?? '';
    if (args.includes('link')) return JSON.stringify([{ flags: ['UP'] }]);
    if (args.includes('rule')) return JSON.stringify(overrides.rules ?? [{ priority: 0, table: 'local' }, { priority: 32766, table: 'main' }]);
    return JSON.stringify(overrides.routes ?? [{ dst: '93.184.216.0/24', dev: 'lan0', scope: 'link', protocol: 'kernel' }]);
  };
}

test('read-only preflight includes connected public LAN and rejects unmanaged policy/stale state', () => {
  assert.ok(inspectIngress('wg0', { run: inspector() }).bypass.includes('93.184.216.0/24'));
  assert.ok(!inspectIngress('wg0', { run: inspector({ routes: [{ dst: '0.0.0.0/1', dev: 'otherVpn', scope: 'link' }] }) }).bypass.includes('0.0.0.0/1'));
  for (const overrides of [{ forward: '0' }, { firewall: '-N CVPN-INGRESS' }, { routes: [{ table: 19999 }] },
    { rules: [{ priority: 0, table: 'local' }, { priority: 10, table: 22 }] }, { rules: [] }]) {
    assert.throws(() => inspectIngress('wg0', { run: inspector(overrides) }));
  }
});

function recorder(failAt = -1) {
  const calls = []; let count = 0;
  const sysctls = new Map();
  return { calls, run(file, args) {
    calls.push([file, ...args]);
    if (count++ === failAt) throw new Error('injected command failure');
    if (file === 'sysctl' && args[0] === '-w') {
      const [key, value] = args[1].split('='); sysctls.set(key, value);
    }
    return file === 'sysctl' && args[0] === '-n' ? sysctls.get(args[1]) ?? '1' : '';
  } };
}

test('install/HTTPS/cleanup select only ingress; no host OUTPUT/default/sysctl forwarding changes', () => {
  const mock = recorder();
  const route = installIngressRouting({ ingress, tun: 'tun7' }, mock);
  route.installHttpsRedirect(19443);
  const installed = mock.calls.map((c) => c.join(' '));
  assert.ok(installed.some((c) => c.includes('iif wg0 lookup 19999')));
  assert.ok(installed.some((c) => c.includes('unreachable default metric 32767 table 19999')));
  assert.ok(installed.some((c) => c.includes('PREROUTING 1 -i wg0')));
  assert.ok(installed.some((c) => c.includes('--to-destination 10.99.0.2:19443')));
  assert.ok(installed.some((c) => c.startsWith('ip6tables') && c.endsWith('CVPN-INGRESS -j DROP')));
  assert.ok(!installed.some((c) => /OUTPUT|route replace|conf\.all|ip_forward=/.test(c)));
  for (const cmd of installed.filter((c) => c.startsWith('ip -4 route'))) assert.ok(cmd.includes('table 19999'));
  route.close(); const after = mock.calls.length; route.close(); assert.equal(mock.calls.length, after);
  assert.throws(() => route.installHttpsRedirect(19443));
  const removed = mock.calls.slice(installed.length).map((c) => c.join(' '));
  assert.ok(removed.findIndex((c) => c.includes('rule del')) < removed.findIndex((c) => c.includes('-D FORWARD -i wg0')));
  assert.ok(removed.at(-1).includes('-X CVPN-INGRESS'));
});

test('every setup command failure rolls back only completed operations', () => {
  const success = recorder(); installIngressRouting({ ingress, tun: 'tun7' }, success);
  for (let at = 0; at < success.calls.length; at++) {
    const mock = recorder(at);
    assert.throws(() => installIngressRouting({ ingress, tun: 'tun7' }, mock), /injected/);
    assert.ok(!mock.calls.slice(at + 1).some((c) => c.includes('-F')), 'never flush foreign chains/tables');
    for (const command of mock.calls.slice(at + 1)) {
      assert.ok(command.includes('-D') || command.includes('-X') || command.includes('del') || command.includes('sysctl'));
    }
  }
});

test('cleanup failure stops before removing safety guard, and can be retried', () => {
  let fail = false;
  const mock = recorder();
  const route = installIngressRouting({ ingress, tun: 'tun7' }, { run(file, args) {
    if (fail) { fail = false; throw new Error('cleanup failure'); }
    return mock.run(file, args);
  } });
  const start = mock.calls.length; fail = true;
  assert.throws(() => route.close(), /cleanup failed/);
  assert.equal(mock.calls.length, start);
  route.close();
  assert.ok(mock.calls.at(-1).includes('-X'));
});

test('HTTPS partial-install failure is cleaned by the routing owner', () => {
  const baseline = recorder();
  const route = installIngressRouting({ ingress, tun: 'tun7' }, baseline);
  const start = baseline.calls.length; route.installHttpsRedirect(19443);
  const end = baseline.calls.length;
  for (let at = start; at < end; at++) {
    const mock = recorder(at);
    const owner = installIngressRouting({ ingress, tun: 'tun7' }, mock);
    assert.throws(() => owner.installHttpsRedirect(19443), /injected/);
    owner.close();
    assert.ok(mock.calls.at(-1).includes('-X'));
  }
});

test('CLI rejects bad ingress flags before opening TUN or changing routing', () => {
  for (const flags of [['--from-tun='], ['--from-tun=lo'], ['--from-tun=wg0', '--split-default'],
    ['--from-tun-restart-safe'], ['--from-tun=wg0', '--from-tun-restart-safe', '--from-tun-restart-safe'],
    ['--from-tun=wg0', '--from-tun=wg1'], ['--from-tun=wg0', '--client-lan-subnet=10.0.0.0/24']]) {
    const result = spawnSync(process.execPath, ['scripts/clean-vpn.js', '--role=client', '--type=tls', '--server=127.0.0.1:443', ...flags],
      { encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /--from-tun/);
    assert.doesNotMatch(result.stderr, /\/dev\/net\/tun|ip route|Cannot find module/);
  }
});

test('CLI rejects the form-tun typo as an unknown option', () => {
  const result = spawnSync(process.execPath, ['scripts/clean-vpn.js', '--role=client', '--type=tls',
    '--server=127.0.0.1:443', '--form-tun=wg0'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /Неизвестный параметр clean-vpn: --form-tun=wg0/);
});
