/** Invoked only by the guarded, NIC-less USB E2E guest. No host entry point. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';

export async function runUsbFaultScenarios(c) {
  assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.usb-faults=1(?:\s|$)/);
  assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
  assert.equal(process.getuid(), 0);
  const { check, event, ctl, property, sync, ip, at, link, until, ready, matrix, login, hits } = c;
  const unit = 'clean-vpn.service', exitIp = '154.62.226.216';
  const managerPid = await property('systemd-networkd.service', 'MainPID');
  const guardStart = await property('clean-vpn-killswitch.service', 'ActiveEnterTimestampMonotonic');
  const rescueStart = await property('clean-vpn-usb-rescue.socket', 'ActiveEnterTimestampMonotonic');
  const offsets = Object.fromEntries(['http', 'raw', 'dns'].map(k => [k, hits(`/run/e2e-${k}-hits`).length]));
  const monitor = spawn('/usr/bin/ip', ['netns', 'exec', 'peer', '/usr/bin/node', '/project/scripts/lib/usb-e2e-vm.mjs', 'fault-monitor'], { stdio: ['ignore', 'ignore', 'inherit'] });
  const monitorEnd = once(monitor, 'close');
  const samples = () => hits('/run/e2e-monitor-results');
  const preserved = async label => {
    check(label + ' guard retained', await property('clean-vpn-killswitch.service', 'ActiveState'), 'active');
    check(label + ' guard not restarted', await property('clean-vpn-killswitch.service', 'ActiveEnterTimestampMonotonic'), guardStart);
    check(label + ' networkd not restarted', await property('systemd-networkd.service', 'MainPID'), managerPid);
    check(label + ' rescue not restarted', await property('clean-vpn-usb-rescue.socket', 'ActiveEnterTimestampMonotonic'), rescueStart);
    check(label + ' SSH 22 authenticated', await login('22'));
    check(label + ' SSH 2222 authenticated', await login());
  };
  const noBypass = label => {
    for (const kind of ['http', 'raw', 'dns']) {
      const seen = hits(`/run/e2e-${kind}-hits`).slice(offsets[kind]);
      const unexpected = seen.filter(h => h.peer !== exitIp || ['192.168.1.1', 'fd00:1::1'].includes(h.host));
      if (unexpected.length) event({ event: 'diagnostic', phase: 0, label, kind,
        unexpectedCount: unexpected.length, unexpectedSamples: unexpected.slice(0, 8) });
      check(`${label} ${kind} no direct or LAN receiver hits`, seen.length > 0 && seen.every(h => h.peer === exitIp && !['192.168.1.1', 'fd00:1::1'].includes(h.host)));
    }
  };
  try {
    await until(() => samples().filter(s => s.ok).length >= 10, 'continuous monitor baseline');
    check('continuous traffic positive baseline', samples().some(s => s.kind === 'https' && s.peer === exitIp) && samples().some(s => s.kind === 'raw' && s.peer === exitIp) && samples().some(s => s.kind === 'dns' && s.ok) && ['http', 'raw', 'dns'].every(k => hits(`/run/e2e-${k}-hits`).length > offsets[k]));
    if (!fs.readFileSync('/proc/cmdline', 'utf8').includes('meshpn.usb-network-faults=1')) {
      const oldPid = await property(unit, 'MainPID'), oldRestarts = Number(await property(unit, 'NRestarts'));
      event({ event: 'fault', phase: 0, scenario: 'sigkill', action: 'begin' });
      await ctl('kill', '--kill-whom=main', '--signal=SIGKILL', unit);
      await until(async () => Number(await property(unit, 'NRestarts')) > oldRestarts && await property(unit, 'MainPID') !== oldPid && await property(unit, 'MainPID') !== '0', 'automatic crash restart');
      check('SIGKILL automatically changes VPN PID', await property(unit, 'MainPID') !== oldPid);
      check('SIGKILL increments restart counter', Number(await property(unit, 'NRestarts')) > oldRestarts);
      // TCG performs audited journal rollback AND a fresh DNS installation.
      // Give crash recovery the same 420s budget as service cleanup. Network
      // outages below still retain their original 180s readiness deadline.
      try { await ready(420000); } catch (error) {
        // Collect safety evidence without repairing or stopping the failed VPN.
        // The VPN may recover while collecting diagnostics: do not assume it
        // stays down and obscure the original timeout with a "stopped" test.
        event({ event: 'diagnostic', phase: 0, recoveryFailure: error.message });
        await preserved('crash-failed');
        for (const kind of ['http', 'raw', 'dns']) check(`crash-failed ${kind} no bypass`, hits(`/run/e2e-${kind}-hits`).slice(offsets[kind]).every(h => h.peer === exitIp && !['192.168.1.1', 'fd00:1::1'].includes(h.host)));
        const directory = fs.readdirSync('/run').find(n => /^clean-vpn-host-routes-\d+$/.test(n));
        if (directory) {
          const state = JSON.parse(fs.readFileSync(`/run/${directory}/journal.json`, 'utf8'));
          event({ event: 'diagnostic', phase: 0, hostRouteStage: state.stage, pendingRoutes: state.routes.length, rpFilterPending: state.rp !== null });
        }
        throw error; // Safety evidence must never turn a recovery failure into PASS.
      }
      await preserved('crash'); await matrix(true); noBypass('crash');
      event({ event: 'fault', phase: 0, scenario: 'sigkill', action: 'recovered' });
    }
    const recoveryPid = await property(unit, 'MainPID'), recoveryRestarts = await property(unit, 'NRestarts');

    for (const scenario of ['exit-blackhole', 'carrier-loss']) {
      const start = performance.now(), before = samples().length;
      event({ event: 'fault', phase: 0, scenario, action: 'begin' });
      if (scenario === 'exit-blackhole') {
        // Internet origins are local to router; only exit forwarding is cut.
        // Thus a faulty direct path remains reachable and will be recorded.
        for (const direction of ['-s', '-d']) at('router', 'iptables', '-I', 'FORWARD', '1', direction, exitIp, '-j', 'DROP');
        check('blackhole leaves uplink carrier and default route', link().flags.includes('LOWER_UP') && ip('-4', 'route', 'show', 'default').includes('192.168.1.1'));
      } else {
        at('router', 'ip', 'link', 'set', 'client0', 'down');
        await until(() => !link().flags.includes('LOWER_UP') && !ip('-4', 'route', 'show', 'default'), 'carrier/DHCP route withdrawal');
        check('carrier loss withdraws DHCP default', !ip('-4', 'route', 'show', 'default'));
        check('carrier loss withdraws exit bypass', !ip('-4', 'route', 'show', exitIp + '/32'));
      }
      await matrix(false); await preserved(scenario);
      await delay(Math.max(0, 120000 - (performance.now() - start)));
      const elapsedMs = performance.now() - start;
      check(scenario + ' held at least 120 seconds', elapsedMs >= 120000);
      check(scenario + ' continuous traffic observes failure', samples().slice(before).some(s => !s.ok));
      noBypass(scenario);
      event({ event: 'fault', phase: 0, scenario, action: 'restore', elapsedMs });
      if (scenario === 'exit-blackhole') {
        for (const direction of ['-s', '-d']) at('router', 'iptables', '-D', 'FORWARD', direction, exitIp, '-j', 'DROP');
      } else {
        at('router', 'ip', 'link', 'set', 'client0', 'up');
        // Linux flushes the fixture's static IPv6 addresses on link-down.
        // Restore the test router, not the client or its protection.
        for (const address of ['2001:db8:1::1/64', 'fd00:1::1/64']) at('router', 'ip', '-6', 'addr', 'replace', address, 'dev', 'client0', 'nodad');
        for (const subnet of ['2001:db8:7::/64', 'fd00:7::/64']) at('router', 'ip', '-6', 'route', 'replace', subnet, 'via', 'fe80::ff:fe00:102', 'dev', 'client0');
        at('router', 'ip', '-6', 'neigh', 'replace', 'fe80::ff:fe00:102', 'lladdr', '02:00:00:00:01:02', 'nud', 'permanent', 'dev', 'client0');
        await until(() => link().addr_info.some(a => a.family === 'inet' && a.dynamic) && ip('-4', 'route', 'show', 'default').includes('192.168.1.1'), 'DHCP return');
        check('carrier DHCP returns automatically', link().addr_info.some(a => a.family === 'inet' && a.dynamic));
      }
      await ready();
      check(scenario + ' recovers without VPN restart', await property(unit, 'MainPID'), recoveryPid);
      check(scenario + ' restart counter unchanged', await property(unit, 'NRestarts'), recoveryRestarts);
      check(scenario + ' exit route restored via wlan0', JSON.parse(ip('-j', '-4', 'route', 'get', exitIp))[0].dev, 'wlan0');
      await matrix(true); await preserved(scenario + '-recovered'); noBypass(scenario + '-recovered');
      event({ event: 'fault', phase: 0, scenario, action: 'recovered' });
    }
    fs.writeFileSync('/run/e2e-monitor-stop', 'yes');
    const end = await Promise.race([monitorEnd, delay(15000).then(() => { throw Error('monitor stop timeout'); })]);
    check('continuous monitor exits successfully', end, [0, null]);
    check('continuous monitor final traffic successful', samples().slice(-5).every(s => s.ok));
    noBypass('final');
  } finally { if (monitor.exitCode === null) monitor.kill('SIGKILL'); }
}
