/** Actual installer/unit lifecycle, exclusively in the marked NIC-less VM. */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import dgram from 'node:dgram';
import { assertHostSystemdVm } from './vpn-host-systemd-vm.mjs';
import { tunnelDnsFixtureAnswer } from './dns-tunnel-cli-lab.mjs';
const exec = (file, args, env = process.env) => promisify(execFile)(file, args, { env, encoding: 'utf8', timeout: 500000, maxBuffer: 1024 * 1024 });
const ctl = (...args) => exec('/usr/bin/systemctl', ['--no-pager', ...args]);

export async function runHostSystemdChecks({ directory, start, wait, stop, startExit, query, check, at, ip }) {
  assertHostSystemdVm();
  const main = 'clean-vpn.service', guard = 'clean-vpn-killswitch.service', logfile = '/run/host-vm-client.log';
  const logs = () => existsSync(logfile) ? readFileSync(logfile, 'utf8') : '';
  const property = async (unit, key) => (await ctl('show', unit, `--property=${key}`, '--value')).stdout.trim();
  const snapshot = () => JSON.stringify({ routes: at('client', 'ip', '-N', '-j', '-4', 'route', 'show', 'table', 'main'),
    rp: at('client', 'sysctl', '-n', 'net.ipv4.conf.all.rp_filter') });
  const ready = async offset => {
    const end = Date.now() + 180000;
    while (!logs().slice(offset).includes('IPv6 client: tunnel')) {
      assert.notEqual(await property(guard, 'ActiveState'), 'failed', logs().slice(offset));
      assert.ok(Date.now() < end, logs().slice(offset)); await delay(250);
    }
    assert.equal(await property(main, 'ActiveState'), 'active');
  };
  const recover = async (script, apply = false) => {
    const p = await start('client', [`scripts/${script}`, ...(apply ? ['--apply'] : [])]);
    const timer = setTimeout(() => p.kill('SIGKILL'), 150000);
    try { await once(p, 'exit'); assert.equal(p.exitCode, 0, p.log); return JSON.parse(p.stdoutText); }
    finally { clearTimeout(timer); }
  };
  const sockets = [], dnsPeers = [];
  try {
    for (const address of ['1.1.1.1', '8.8.8.8']) {
      ip('addr', 'add', `${address}/32`, 'dev', 'lo');
      const s = dgram.createSocket('udp4'); sockets.push(s);
      s.on('message', (b, p) => { dnsPeers.push(p.address); s.send(tunnelDnsFixtureAnswer(b, 10), p.port, p.address); });
      s.bind(53, address); await once(s, 'listening');
    }
    const dns = async () => {
      const p = await start('client', ['--input-type=module', '-e', `
        import {exchangePlainDns} from './scripts/lib/dns-tunnel-forwarder.mjs';
        import {makeDnsQuery,parseDns} from './scripts/lib/lab-dns-wire.mjs';
        try { const b=await exchangePlainDns({server:'1.1.1.1',localAddress:'0.0.0.0',query:makeDnsQuery('systemd.test'),timeoutMs:5000});
          const r=parseDns(b).records.find(r=>r.type===1); console.log(r?[...b.subarray(r.offset,r.offset+4)].join('.'):'NOANSWER');
        } catch { console.log('BLOCKED'); }
      `]);
      await once(p, 'exit'); assert.equal(p.exitCode, 0, p.log); return p.stdoutText.trim();
    };
    check('PID1 is real systemd', readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
    check('systemd lab DNS baseline positive control', await dns(), '192.0.2.10');
    const baseline = snapshot();
    // Only laboratory topology/log destinations differ. Service body, restart,
    // dependencies, KillMode and stop deadline come from the real installer.
    for (const name of [main, guard]) {
      mkdirSync(`/etc/systemd/system/${name}.d`, { recursive: true });
      writeFileSync(`/etc/systemd/system/${name}.d/lab.conf`, `[Service]\nNetworkNamespacePath=/run/netns/client\nStandardOutput=append:${logfile}\nStandardError=append:${logfile}\n`);
    }
    const exit = await startExit(true); await wait(exit, 'exit TLS');
    const args = ['scripts/autostart/install.sh', '--role=client', '--type=tls', '--server=198.51.100.2:443', '--split-default', '--ipv6=auto',
      `--tls-cert-dir=${directory}`, `--shared-hmac-key=${directory}/secret.key`, '--tls-server-name=vpn.test', '--tls-public-name=vpn.test'];
    const installed = await exec('/bin/bash', args, { ...process.env, NODE_BIN: '/usr/bin/node', KILLSWITCH: '1', KILLSWITCH_PERSIST: '1' });
    assert.match(installed.stdout, /Готово/); await ready(0);
    check('installed service KillMode', await property(main, 'KillMode'), 'mixed');
    check('installed service stop budget', await property(main, 'TimeoutStopUSec'), '7min');
    check('installed guard active', await property(guard, 'ActiveState'), 'active');
    check('installed service IPv4 HTTPS', await query('1.0.0.1'), '198.51.100.2');
    check('installed service IPv6 HTTPS', await query('2606:4700:4700::1111'), '2001:db8:2::2');
    check('installed service DNS', await dns(), '192.0.2.10');
    check('installed service DNS peer is exit', dnsPeers.at(-1), '198.51.100.2');
    const oldPid = await property(main, 'MainPID'), offset = logs().length;
    await ctl('restart', main); await ready(offset);
    check('systemctl restart replaces main PID', await property(main, 'MainPID') !== oldPid, true);
    check('systemctl restart IPv4 HTTPS', await query('1.0.0.1'), '198.51.100.2');
    await ctl('stop', main);
    check('systemctl stop releases original IPv4 network', snapshot(), baseline);
    for (const script of ['clean-vpn-dns-recover.mjs', 'clean-vpn-ipv6-recover.mjs', 'clean-vpn-host-recover.mjs'])
      check(`systemctl stop ${script} released`, (await recover(script)).stage, 'released');
    check('persist guard survives systemctl stop IPv4', await query('1.0.0.1'), 'BLOCKED');
    check('persist guard survives systemctl stop IPv6', await query('2606:4700:4700::1111'), 'BLOCKED');
    check('persist guard survives systemctl stop DNS', await dns(), 'BLOCKED');
    const again = logs().length; await ctl('start', main); await ready(again);
    await ctl('kill', '--kill-whom=main', '--signal=SIGKILL', main);
    const end = Date.now() + 60000;
    while (Number(await property(main, 'NRestarts')) < 1 || !/recovery required/.test(logs().slice(again))) {
      assert.ok(Date.now() < end, logs().slice(again)); await delay(250);
    }
    await ctl('stop', main);
    check('SIGKILL restart refuses stale ownership', /recovery required/.test(logs().slice(again)), true);
    check('SIGKILL persists IPv4 guard', await query('1.0.0.1'), 'BLOCKED');
    check('SIGKILL persists IPv6 guard', await query('2606:4700:4700::1111'), 'BLOCKED');
    check('SIGKILL persists DNS guard', await dns(), 'BLOCKED');
    let refused;
    try { await exec('ip', ['netns', 'exec', 'client', '/bin/bash', 'scripts/autostart/uninstall.sh']); }
    catch (error) { refused = error; }
    check('uninstall after SIGKILL refuses unfinished journals', !!refused && /unfinished VPN journal/.test(refused.stderr), true);
    check('refused uninstall retains installed files', [
      `/etc/systemd/system/${main}`, `/etc/systemd/system/${guard}`,
      '/usr/local/bin/clean-vpn-run.sh', '/usr/local/bin/clean-vpn-killswitch.sh',
    ].every(existsSync), true);
    check('refused uninstall retains active guard unit', await property(guard, 'ActiveState'), 'active');
    check('refused uninstall blocks IPv4', await query('1.0.0.1'), 'BLOCKED');
    check('refused uninstall blocks IPv6', await query('2606:4700:4700::1111'), 'BLOCKED');
    check('refused uninstall blocks DNS', await dns(), 'BLOCKED');
    for (const script of ['clean-vpn-dns-recover.mjs', 'clean-vpn-ipv6-recover.mjs', 'clean-vpn-host-recover.mjs']) await recover(script, true);
    check('explicit recovery restores original routes under systemd', snapshot(), baseline);
    check('explicit recovery leaves persist guard', await query('1.0.0.1'), 'BLOCKED');
    const restored = logs().length; await ctl('start', main); await ready(restored);
    check('systemd starts after explicit recovery', await query('1.0.0.1'), '198.51.100.2');
    await ctl('stop', main);
    await exec('ip', ['netns', 'exec', 'client', '/bin/bash', 'scripts/autostart/uninstall.sh']);
    check('clean uninstall removes installed main unit', existsSync(`/etc/systemd/system/${main}`), false);
    check('clean uninstall removes installed wrapper', existsSync('/usr/local/bin/clean-vpn-run.sh'), false);
    check('clean uninstall restores baseline IPv4', await query('1.0.0.1'), '192.0.2.2');
    check('clean uninstall restores baseline IPv6', await query('2606:4700:4700::1111'), '2001:db8:1::2');
    check('clean uninstall restores baseline DNS', await dns(), '192.0.2.10');
    await stop(exit);
    return { systemdPid1: true, actualInstaller: true, acceptance: 'not-ready-for-deployment', limitations: [
      'fixture-network-namespace-dropins', 'persist-mode-only', 'no-early-boot-or-reboot', 'explicit-recovery-not-auto-restart',
      'no-stop-timeout-or-update-test', 'no-crash-during-uninstall-test', 'iptables-legacy-only', 'H2-only-systemd-cycle'] };
  } catch (error) { console.error('HOST_SYSTEMD_LOG', logs()); throw error; }
  finally { for (const s of sockets) s.close(); }
}
