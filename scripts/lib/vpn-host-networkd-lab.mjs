/** Real networkd, but only a minimal NIC-less VM unit, not a production drop-in. */
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { assertHostSystemdVm } from './vpn-host-systemd-vm.mjs';

export const hostNetworkdUnit = `[Unit]
Description=VM-only real networkd behind persistent VPN guard
DefaultDependencies=no
Requires=dbus.service clean-vpn-killswitch.service
After=dbus.service network-pre.target clean-vpn-killswitch.service
Before=network.target
[Service]
Type=notify
NetworkNamespacePath=/run/netns/client
ExecStart=/usr/lib/systemd/systemd-networkd
ExecStopPost=/usr/bin/ip link set eth0 down
Environment=PATH=/usr/bin:/usr/sbin:/bin:/sbin SYSTEMD_LOG_TARGET=console
TimeoutStartSec=60
TimeoutStopSec=30
StandardOutput=append:/run/host-networkd.log
StandardError=append:/run/host-networkd.log
`;
export const hostNetworkdConfig = `[Match]
Name=eth0
[Link]
ActivationPolicy=up
[Network]
DHCP=no
IPv6AcceptRA=no
LinkLocalAddressing=no
LLMNR=no
MulticastDNS=no
Address=192.0.2.2/24
Address=2001:db8:1::2/64
Gateway=192.0.2.1
Gateway=2001:db8:1::1
`;

export async function runHostNetworkdChecks({ check, query, dns, ready, logs, property, ctl, exec, at, ip }) {
  assertHostSystemdVm();
  assert.match(readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.host-networkd=1(?:\s|$)/);
  const main = 'clean-vpn.service', guard = 'clean-vpn-killswitch.service', manager = 'systemd-networkd.service';
  const unit = `/etc/systemd/system/${manager}`, config = '/etc/systemd/network/10-host-vm.network';
  const fault = `/etc/systemd/system/${guard}.d/networkd-fault.conf`;
  const link = () => JSON.parse(at('client', 'ip', '-j', 'address', 'show', 'eth0'))[0];
  const routes = () => JSON.parse(at('client', 'ip', '-j', '-4', 'route', 'show', 'default'));
  const until = async (test, detail, budget = 90000) => {
    const deadline = Date.now() + budget;
    while (!await test()) { assert.ok(Date.now() < deadline, detail + '\n' + readFileSync('/run/host-networkd.log', 'utf8')); await delay(250); }
  };
  const netns = at('client', 'readlink', '/proc/self/ns/net').match(/\d+/)[0];
  const journal = `/run/clean-vpn-host-routes-${netns}/journal.json`;
  mkdirSync('/etc/systemd/network', { recursive: true });
  // Like the existing networkd lab: no udev in this minimal initramfs.
  writeFileSync('/run/systemd/container', 'other\n', { flag: 'wx', mode: 0o644 });
  writeFileSync(unit, hostNetworkdUnit, { flag: 'wx', mode: 0o644 });
  writeFileSync(config, hostNetworkdConfig, { flag: 'wx', mode: 0o644 });
  writeFileSync('/run/host-networkd.log', '', { flag: 'wx', mode: 0o600 });
  await ctl('daemon-reload'); await ctl('stop', main); await ctl('stop', guard);
  try {
    for (const phase of ['healthy', 'failed', 'late-carrier']) {
      at('client', 'ip', 'link', 'set', 'eth0', 'down');
      // Exact laboratory interface only; force networkd to create addresses/routes.
      at('client', 'ip', '-4', 'addr', 'flush', 'dev', 'eth0');
      at('client', 'ip', '-6', 'addr', 'flush', 'dev', 'eth0');
      check(`${phase} networkd starts without link or addresses`, !link().flags.includes('UP') && link().addr_info.length === 0, true);
      if (phase === 'failed') {
        writeFileSync(fault, '[Service]\nExecStartPre=/bin/false\n', { flag: 'wx', mode: 0o644 }); await ctl('daemon-reload');
      }
      if (phase === 'late-carrier') {
        unlinkSync(fault); await ctl('daemon-reload'); await ctl('reset-failed', guard);
        ip('link', 'set', 'client0', 'down');
      }
      let error;
      try { await ctl('start', manager); } catch (e) { error = e; }
      check(`${phase} networkd start result`, !!error, phase === 'failed');
      if (phase === 'failed') {
        check('failed networkd guard failed', await property(guard, 'ActiveState'), 'failed');
        check('failed networkd daemon absent', await property(manager, 'MainPID'), '0');
        check('failed networkd link stays down', link().flags.includes('UP'), false);
        check('failed networkd routes absent', routes().length, 0);
        for (const [name, probe] of [['IPv4', () => query('1.0.0.1')], ['IPv6', () => query('2606:4700:4700::1111')], ['DNS', dns]])
          check(`failed networkd blocks ${name}`, await probe(), 'BLOCKED');
        continue;
      }
      check(`${phase} networkd daemon active`, await property(manager, 'ActiveState'), 'active');
      const guardDone = BigInt(await property(guard, 'ExecMainExitTimestampMonotonic'));
      check(`${phase} networkd guard precedes daemon`, guardDone > 0n && BigInt(await property(manager, 'ExecMainStartTimestampMonotonic')) >= guardDone, true);
      const offset = logs().length;
      if (phase === 'late-carrier') {
        await until(() => link().flags.includes('UP'), 'networkd failed to raise link without carrier');
        check('late-carrier networkd no default before carrier', routes().length, 0);
        const released = readFileSync(journal, 'utf8'); assert.equal(JSON.parse(released).stage, 'released');
        await ctl('start', main);
        await until(() => (logs().slice(offset).match(/Не найден default route/g) ?? []).length >= 2, 'client did not retry before carrier', 180000);
        check('late-carrier networkd client retried', Number(await property(main, 'NRestarts')) >= 1, true);
        check('late-carrier networkd journal unchanged', readFileSync(journal, 'utf8'), released);
        ip('link', 'set', 'client0', 'up');
      }
      await until(() => routes().some(r => r.gateway === '192.0.2.1') && link().addr_info.some(a => a.local === '2001:db8:1::2' && !a.tentative), 'networkd addresses/default route not ready');
      check(`${phase} networkd configured IPv4 and IPv6`, link().addr_info.some(a => a.local === '192.0.2.2') && link().addr_info.some(a => a.local === '2001:db8:1::2'), true);
      if (phase === 'healthy') {
        for (const [name, probe] of [['IPv4', () => query('1.0.0.1')], ['IPv6', () => query('2606:4700:4700::1111')], ['DNS', dns]])
          check(`healthy networkd pre-VPN blocks ${name}`, await probe(), 'BLOCKED');
        await ctl('start', main);
      }
      await ready(offset);
      check(`${phase} networkd VPN IPv4`, await query('1.0.0.1'), '198.51.100.2');
      check(`${phase} networkd VPN IPv6`, await query('2606:4700:4700::1111'), '2001:db8:2::2');
      check(`${phase} networkd VPN DNS`, await dns(), '192.0.2.10');
      await ctl('stop', main);
      check(`${phase} networkd stop releases host journal`, JSON.parse(readFileSync(journal, 'utf8')).stage, 'released');
      await ctl('stop', guard); // Requires propagates stop; After reverses ordering.
      check(`${phase} networkd guard stop stops daemon`, await property(manager, 'ActiveState'), 'inactive');
      check(`${phase} networkd stop lowers link`, link().flags.includes('UP'), false);
      check(`${phase} networkd guard released`, await property(guard, 'ActiveState'), 'inactive');
    }
    unlinkSync(unit); unlinkSync(config); await ctl('daemon-reload');
    await exec('ip', ['netns', 'exec', 'client', '/bin/bash', 'scripts/autostart/uninstall.sh']);
    at('client', 'ip', 'link', 'set', 'eth0', 'up');
    at('client', 'ip', '-4', 'addr', 'replace', '192.0.2.2/24', 'dev', 'eth0');
    at('client', 'ip', '-4', 'route', 'replace', 'default', 'via', '192.0.2.1', 'dev', 'eth0');
    check('networkd fixture teardown restores direct IPv4', await query('1.0.0.1'), '192.0.2.2');
    return { systemdPid1: true, actualInstaller: true, networkd: true, actualNetworkd: true,
      acceptance: 'not-ready-for-deployment', limitations: [
        'fixture-network-namespace-dropins', 'no-early-boot-or-reboot', 'explicit-recovery-not-auto-restart',
        'minimal-root-networkd-unit-not-vendor-sandbox', 'container-marker-no-udev',
        'static-addresses-late-carrier-not-DHCP', 'failed-guard-also-prevents-SSH',
        'candidate-not-installed-by-production-installer', 'production-update-uninstall-integration-pending',
        'no-runtime-guard-rule-loss-test',
        'link-teardown-command-failure-not-tested',
      ] };
  } catch (error) { console.error('HOST_NETWORKD_LOG', readFileSync('/run/host-networkd.log', 'utf8')); throw error; }
}
