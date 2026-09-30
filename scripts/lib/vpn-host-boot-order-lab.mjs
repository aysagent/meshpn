/** Boot-job ordering audit, not a reboot. Only inside the marked NIC-less VM. */
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { assertHostSystemdVm } from './vpn-host-systemd-vm.mjs';

// A synthetic network consumer with ordinary ordering, deliberately not a
// Requires= dependency on the VPN guard. Real network managers vary.
export function bootObserverUnit(directory) {
  assert.match(directory, /^\/tmp\/host-systemd-[A-Za-z0-9]+$/);
  return `[Unit]
DefaultDependencies=no
Wants=network-pre.target network.target
After=network-pre.target
Before=network.target
[Service]
Type=oneshot
RemainAfterExit=yes
NetworkNamespacePath=/run/netns/client
WorkingDirectory=/project
Environment=PATH=/usr/bin:/usr/sbin:/bin:/sbin
ExecStart=/usr/bin/node /project/scripts/lib/vpn-host-boot-observer.mjs ${directory}
TimeoutStartSec=60s
`;
}

export async function runHostBootOrderChecks({ directory, check, query, dns, ready, logs, property, ctl, exec }) {
  assertHostSystemdVm();
  assert.match(readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.host-boot-order=1(?:\s|$)/);
  const main = 'clean-vpn.service', guard = 'clean-vpn-killswitch.service', observer = 'host-vm-network-observer.service';
  const result = '/run/host-boot-observer.json';
  const fault = '/etc/systemd/system/clean-vpn-killswitch.service.d/boot-fault.conf';
  writeFileSync(`/etc/systemd/system/${observer}`, bootObserverUnit(directory), { flag: 'wx', mode: 0o644 });
  await ctl('daemon-reload');
  for (const phase of ['healthy', 'failed']) {
    await ctl('stop', main);
    await ctl('stop', observer, guard, 'network.target', 'network-pre.target');
    check(`${phase} boot ordering baseline IPv4`, await query('1.0.0.1'), '192.0.2.2');
    check(`${phase} boot ordering baseline IPv6`, await query('2606:4700:4700::1111'), '2001:db8:1::2');
    check(`${phase} boot ordering baseline DNS`, await dns(), '192.0.2.10');
    if (existsSync(result)) unlinkSync(result);
    if (phase === 'failed') {
      // Failure before rule installation: no foreign or partly owned rules.
      writeFileSync(fault, '[Service]\nExecStartPre=/bin/false\n', { flag: 'wx', mode: 0o644 });
      await ctl('daemon-reload');
    }
    // Clean inactive units may already be garbage-collected by PID1. There is
    // no failed state to reset before these two start transactions.
    const offset = logs().length;
    let startError;
    try { await ctl('start', main, observer); } catch (error) { startError = error; }
    check(`${phase} boot ordering start result`, !!startError, phase === 'failed');
    check(`${phase} boot ordering observer active`, await property(observer, 'ActiveState'), 'active');
    const probes = JSON.parse(readFileSync(result, 'utf8'));
    check(`${phase} boot ordering observer IPv4`, probes.ipv4, phase === 'healthy' ? 'BLOCKED' : '192.0.2.2');
    check(`${phase} boot ordering observer IPv6`, probes.ipv6, phase === 'healthy' ? 'BLOCKED' : '2001:db8:1::2');
    check(`${phase} boot ordering observer DNS`, probes.dns, phase === 'healthy' ? 'BLOCKED' : '192.0.2.10');
    check(`${phase} boot ordering guard result`, await property(guard, 'Result'), phase === 'healthy' ? 'success' : 'exit-code');
    if (phase === 'healthy') {
      await ready(offset);
      check('healthy boot ordering VPN follows observer', await query('1.0.0.1'), '198.51.100.2');
    } else {
      check('failed boot ordering VPN never started', await property(main, 'MainPID'), '0');
      check('failed boot ordering guard failed', await property(guard, 'ActiveState'), 'failed');
    }
  }
  unlinkSync(fault); await ctl('daemon-reload');
  await ctl('reset-failed', guard); await ctl('start', guard);
  for (const [label, probe] of [['IPv4', () => query('1.0.0.1')], ['IPv6', () => query('2606:4700:4700::1111')], ['DNS', dns]])
    check(`boot ordering explicit guard repair blocks ${label}`, await probe(), 'BLOCKED');
  await ctl('stop', observer);
  await exec('ip', ['netns', 'exec', 'client', '/bin/bash', 'scripts/autostart/uninstall.sh']);
  check('boot ordering clean uninstall IPv4', await query('1.0.0.1'), '192.0.2.2');
  return { systemdPid1: true, actualInstaller: true, bootOrder: true,
    finding: 'network-consumer-ran-after-guard-failure', failClosed: false,
    acceptance: 'not-ready-for-deployment', limitations: [
      'fixture-network-namespace-dropins', 'no-early-boot-or-reboot', 'explicit-recovery-not-auto-restart',
      'synthetic-network-consumer-not-distribution-manager', 'warm-start-job-transaction',
      'guard-failure-before-rule-installation', 'persist-mode-only', 'iptables-legacy-only',
    ] };
}
