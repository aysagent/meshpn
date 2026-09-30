import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { hostNetworkdDropIn, hostNetworkdConfig, runHostNetworkdChecks } from './lib/vpn-host-networkd-lab.mjs';
import { assertManagedNetworkStopped } from './lib/vpn-host-network-release.mjs';
import { HOST_NETWORKD_CHECKS, assertHostSystemdEvidence } from './lib/vpn-host-systemd-vm.mjs';

test('networkd scenario refuses mutations on development host', async () => {
  await assert.rejects(runHostNetworkdChecks({}), /meshpn\.host-systemd/);
});
test('host networkd image includes daemon plus its required user and group', () => {
  const source = readFileSync(new URL('./lib/dns-vm-image.mjs', import.meta.url), 'utf8');
  assert.match(source, /if \(coupled \|\| hostNetworkd\) await elf\('\/usr\/lib\/systemd\/systemd-networkd'\)/);
  assert.match(source, /coupled \|\| hostNetworkd \? 'systemd-network:x:192:192:/);
  assert.match(source, /coupled \|\| hostNetworkd \? 'systemd-network:x:192:/);
  assert.match(source, /await copy\('\/usr\/lib\/systemd\/system\/systemd-networkd.service'\)/);
  assert.match(source, /await elf\('\/bin\/false'\)/);
  assert.match(source, /symlink\('\/dev\/null', destination\('\/etc\/systemd\/system\/systemd-networkd.socket'\)\)/);
});
test('networkd drop-in preserves vendor commands and sandbox with explicit link teardown', () => {
  assert.match(hostNetworkdDropIn, /^Requires=.*clean-vpn-killswitch.service$/m);
  assert.match(hostNetworkdDropIn, /^After=.*clean-vpn-killswitch.service$/m);
  assert.match(hostNetworkdDropIn, /^ExecStopPost=\/usr\/bin\/ip link set eth0 down$/m);
  assert.match(hostNetworkdDropIn, /^NetworkNamespacePath=\/run\/netns\/client$/m);
  assert.doesNotMatch(hostNetworkdDropIn, /^(?:ExecStart|ExecStartPre|User|Type|Protect\w+|Restrict\w+|NoNewPrivileges|MemoryDenyWriteExecute|FileDescriptorStoreMax)=/m);
  assert.doesNotMatch(hostNetworkdDropIn, /^(?:Wants|Requires|After)=\s*$/m);
  assert.match(hostNetworkdConfig, /^Name=eth0$/m);
  assert.match(hostNetworkdConfig, /^DHCP=no$/m);
  assert.doesNotMatch(hostNetworkdConfig, /ConfigureWithoutCarrier=yes/);
});
test('networkd evidence requires all checks and cannot claim cold boot or deployment', () => {
  const report = { status: 'passed', actualTransportTested: 'tls-ipv6', hostNetworkChanged: false, checks: [...HOST_NETWORKD_CHECKS],
    hostSystemd: { networkd: true, actualNetworkd: true, vendorNetworkd: true, guardedRelease: true, systemdPid1: true, actualInstaller: true, acceptance: 'not-ready-for-deployment',
      limitations: ['fixture-network-namespace-dropins', 'no-early-boot-or-reboot', 'explicit-recovery-not-auto-restart',
        'vendor-unit-with-fixture-dropins', 'no-networkd-socket-activation', 'container-marker-no-udev', 'static-addresses-late-carrier-not-DHCP'] } };
  assertHostSystemdEvidence(report, { networkd: true });
  assert.throws(() => assertHostSystemdEvidence(report));
  assert.throws(() => assertHostSystemdEvidence(report, { networkd: true, networkGate: true }));
  for (let i = 0; i < report.checks.length; i++) assert.throws(() => assertHostSystemdEvidence({ ...report, checks: report.checks.filter((_, j) => i !== j) }, { networkd: true }));
  for (const change of [{ actualNetworkd: false }, { vendorNetworkd: false }, { guardedRelease: false }, { limitations: [] }, { acceptance: 'ready' }])
    assert.throws(() => assertHostSystemdEvidence({ ...report, hostSystemd: { ...report.hostSystemd, ...change } }, { networkd: true }));
});
test('release worker cannot mutate the development host', () => {
  const p = spawnSync(process.execPath, ['scripts/lib/vpn-host-network-release-worker.mjs'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(p.status, 1); assert.match(p.stderr, /meshpn\.host-networkd/);
});
test('networkd stop fault checks failed unit and traffic, not systemctl stop exit status', () => {
  const source = readFileSync(new URL('./lib/vpn-host-networkd-lab.mjs', import.meta.url), 'utf8');
  assert.match(source, /check\('networkd stop fault guard failed', await property\(guard, 'ActiveState'\), 'failed'\)/);
  assert.match(source, /check\('networkd stop fault guard result', await property\(guard, 'Result'\), 'exit-code'\)/);
  assert.match(source, /check\('networkd stop fault rules retained'/);
  for (const name of ['IPv4', 'IPv6', 'DNS']) assert.ok(HOST_NETWORKD_CHECKS.includes(`networkd stop fault blocks ${name}`));
  assert.doesNotMatch(source, /!!refused/);
});
test('release predicate requires stopped manager, pinned link down, and no other active uplink', () => {
  const identity = { ifname: 'eth0', ifindex: 2, address: '00:01:02:03:04:05' };
  const rows = [{ ifname: 'lo', flags: ['UP'] }, { ...identity, flags: ['BROADCAST'] }];
  for (const state of ['inactive', 'failed']) assertManagedNetworkStopped(identity, rows, { state, pid: '0' });
  for (const state of ['active', 'activating', 'deactivating', 'unknown'])
    assert.throws(() => assertManagedNetworkStopped(identity, rows, { state, pid: '0' }));
  assert.throws(() => assertManagedNetworkStopped(identity, rows, { state: 'inactive', pid: '12' }));
  for (const bad of [[], rows.slice(0, 1), [...rows, rows[1]], [...rows, { ifname: 'wlan0', flags: ['UP'] }],
    [rows[0], { ...rows[1], flags: ['UP'] }], [rows[0], { ...rows[1], ifindex: 3 }],
    [rows[0], { ...rows[1], address: '00:00:00:00:00:00' }], [rows[0], { ...rows[1], flags: null }]])
    assert.throws(() => assertManagedNetworkStopped(identity, bad, { state: 'inactive', pid: '0' }));
});
test('networkd CLI rejects mixed scopes before image construction', () => {
  for (const flags of [[], ...['--host-stop-faults', '--host-boot-order', '--host-network-gate'].map(f => ['--host-systemd', '--ipv6', '--dns-conntrack=/unused', f])]) {
    const p = spawnSync(process.execPath, ['scripts/ingress-vm-lab.mjs', '--tools=/unused', '--kernel=/unused', '--resolved=/unused', '--host-networkd', ...flags], { encoding: 'utf8', timeout: 5000 });
    assert.equal(p.status, 1); assert.match(p.stderr, /--host-networkd requires/); assert.doesNotMatch(p.stderr, /Ingress VM artifacts/);
  }
});
