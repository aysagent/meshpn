/** Candidate dependency contract; never installed on a real network manager. */
import assert from 'node:assert/strict';
import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { assertHostSystemdVm } from './vpn-host-systemd-vm.mjs';
import { bootObserverUnit } from './vpn-host-boot-order-lab.mjs';

export function gatedNetworkUnit(directory) {
  return bootObserverUnit(directory)
    .replace('After=network-pre.target', 'Requires=clean-vpn-killswitch.service\nAfter=network-pre.target clean-vpn-killswitch.service')
    .replace('ExecStart=/usr/bin/node', `ExecStartPre=/usr/bin/ip link set eth0 up
ExecStartPre=/usr/bin/ip -4 route replace default via 192.0.2.1 dev eth0
ExecStartPre=/usr/bin/ip -6 addr replace 2001:db8:1::2/64 dev eth0 nodad
ExecStartPre=/usr/bin/ip -6 route replace default via 2001:db8:1::1 dev eth0
ExecStop=/usr/bin/ip link set eth0 down
ExecStart=/usr/bin/node`);
}

export async function runHostNetworkGateChecks({ directory, check, query, dns, ready, logs, property, ctl, exec, at }) {
  assertHostSystemdVm();
  assert.match(readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.host-network-gate=1(?:\s|$)/);
  const main = 'clean-vpn.service', guard = 'clean-vpn-killswitch.service', network = 'host-vm-network-observer.service';
  const result = '/run/host-boot-observer.json';
  const fault = '/etc/systemd/system/clean-vpn-killswitch.service.d/network-gate-fault.conf';
  const linkUp = () => JSON.parse(at('client', 'ip', '-j', 'link', 'show', 'eth0'))[0].flags.includes('UP');
  writeFileSync(`/etc/systemd/system/${network}`, gatedNetworkUnit(directory), { flag: 'wx', mode: 0o644 });
  await ctl('daemon-reload');
  await ctl('stop', main);
  await ctl('stop', guard, 'network.target', 'network-pre.target');
  for (const [name, probe, expected] of [['IPv4', () => query('1.0.0.1'), '192.0.2.2'],
    ['IPv6', () => query('2606:4700:4700::1111'), '2001:db8:1::2'], ['DNS', dns, '192.0.2.10']])
    check(`network gate initial direct ${name}`, await probe(), expected);
  at('client', 'ip', 'link', 'set', 'eth0', 'down');
  for (const phase of ['healthy', 'failed', 'repair']) {
    check(`${phase} network gate link initially down`, linkUp(), false);
    if (existsSync(result)) unlinkSync(result);
    if (phase === 'failed') {
      writeFileSync(fault, '[Service]\nExecStartPre=/bin/false\n', { flag: 'wx', mode: 0o644 });
      await ctl('daemon-reload');
    }
    if (phase === 'repair') {
      unlinkSync(fault); await ctl('daemon-reload'); await ctl('reset-failed', guard);
      // Passive targets can still have become active after a failed job.
      // Rebuild the whole ordering transaction, not just the failed service.
      await ctl('stop', 'network.target', 'network-pre.target');
    }
    const offset = logs().length;
    let error;
    try { await ctl('start', main, network); } catch (e) { error = e; }
    check(`${phase} network gate start result`, !!error, phase === 'failed');
    if (phase === 'failed') {
      check('failed network gate guard failed', await property(guard, 'ActiveState'), 'failed');
      check('failed network gate VPN absent', await property(main, 'MainPID'), '0');
      check('failed network gate consumer absent', await property(network, 'MainPID'), '0');
      check('failed network gate consumer never executed', existsSync(result), false);
      check('failed network gate link stays down', linkUp(), false);
      for (const [name, probe] of [['IPv4', () => query('1.0.0.1')], ['IPv6', () => query('2606:4700:4700::1111')], ['DNS', dns]])
        check(`failed network gate blocks ${name}`, await probe(), 'BLOCKED');
      continue;
    }
    check(`${phase} network gate link raised`, linkUp(), true);
    check(`${phase} network gate guard active`, await property(guard, 'ActiveState'), 'active');
    const guardDone = BigInt(await property(guard, 'ExecMainExitTimestampMonotonic'));
    const networkStart = BigInt(await property(network, 'ExecMainStartTimestampMonotonic'));
    check(`${phase} network gate guard precedes consumer`, guardDone > 0n && networkStart >= guardDone, true);
    const probes = JSON.parse(readFileSync(result, 'utf8'));
    for (const name of ['ipv4', 'ipv6', 'dns']) check(`${phase} network gate pre-VPN ${name}`, probes[name], 'BLOCKED');
    await ready(offset);
    check(`${phase} network gate VPN IPv4`, await query('1.0.0.1'), '198.51.100.2');
    check(`${phase} network gate VPN IPv6`, await query('2606:4700:4700::1111'), '2001:db8:2::2');
    check(`${phase} network gate VPN DNS`, await dns(), '192.0.2.10');
    await ctl('stop', main);
    await ctl('stop', network); // Link must go down before guard may be removed.
    check(`${phase} network gate stop lowers link`, linkUp(), false);
    await ctl('stop', guard, 'network.target', 'network-pre.target');
  }
  // The candidate network unit must be removed before testing legacy uninstall.
  // No claim that production uninstall understands such a dependency yet.
  unlinkSync(`/etc/systemd/system/${network}`); await ctl('daemon-reload');
  await exec('ip', ['netns', 'exec', 'client', '/bin/bash', 'scripts/autostart/uninstall.sh']);
  at('client', 'ip', 'link', 'set', 'eth0', 'up');
  at('client', 'ip', '-4', 'route', 'replace', 'default', 'via', '192.0.2.1', 'dev', 'eth0');
  at('client', 'ip', '-6', 'addr', 'replace', '2001:db8:1::2/64', 'dev', 'eth0', 'nodad');
  at('client', 'ip', '-6', 'route', 'replace', 'default', 'via', '2001:db8:1::1', 'dev', 'eth0');
  check('network gate fixture teardown restores IPv4', await query('1.0.0.1'), '192.0.2.2');
  return { systemdPid1: true, actualInstaller: true, networkGate: true, managedLinkFailClosed: true,
    acceptance: 'not-ready-for-deployment', limitations: [
      'fixture-network-namespace-dropins', 'no-early-boot-or-reboot', 'explicit-recovery-not-auto-restart',
      'synthetic-network-manager-not-networkd', 'candidate-not-installed-by-production-installer',
      'managed-link-initially-down-only', 'failed-guard-also-prevents-SSH',
      'no-runtime-guard-rule-loss-test', 'production-update-uninstall-integration-pending',
    ] };
}
