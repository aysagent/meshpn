/** Called only by the marked NIC-less rescue VM after its guard/SSH checks. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { gatewayFiles, gatewayUnit, installUsbGateway, removeUsbGateway } from './host-usb-gateway.mjs';
import { usbSnatLine } from '../clean-vpn-usb-snat.mjs';

function assertLab() {
  assert.ok(fs.readFileSync('/proc/cmdline', 'utf8').split(/\s+/).includes('meshpn.usb-rescue-lab=1'));
  assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
}
export function prepareGateway({ put }) {
  assertLab();
  for (const [p, s] of Object.entries(gatewayFiles('/usr/bin/node'))) put(p, s);
  const dir = '/etc/systemd/system/multi-user.target.wants'; fs.mkdirSync(dir, { recursive: true });
  fs.symlinkSync('../' + gatewayUnit, dir + '/' + gatewayUnit);
}
export async function testGateway({ command, ip, ctl, put, check, until, state, login }) {
  assertLab();
  const nat = () => command('iptables', ['-t', 'nat', '-S', 'POSTROUTING']);
  const filter = () => command('iptables', ['-S']) + command('ip6tables', ['-S']);
  const guardBefore = filter();
  check('SNAT not present with failed guard and absent VPN', !nat().includes(usbSnatLine));
  if (process.env.USB_RESCUE_BOOT === 'installed') {
    check('SNAT enabled at second boot', ctl('is-enabled', gatewayUnit).trim() === 'enabled');
    check('SNAT retried during boot without ready VPN', Number(ctl('show', gatewayUnit, '--property=NRestarts', '--value')) > 0);
    check('USB rescue login while SNAT waits at boot', await login());
  }
  command('sysctl', ['-w', 'net.ipv4.ip_forward=1']);
  // Real units, artificial readiness only. Existing real guard rules stay intact.
  put('/usr/local/bin/clean-vpn-killswitch.sh', fs.readFileSync('/project/scripts/autostart/killswitch.sh'), 0o755);
  for (const name of ['clean-vpn.service', 'clean-vpn-killswitch.service'])
    put('/etc/systemd/system/' + name, '[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n');
  ctl('daemon-reload'); ctl('reset-failed', 'clean-vpn-killswitch.service');
  ctl('start', 'clean-vpn.service', 'clean-vpn-killswitch.service');
  const beforePid = ctl('show', 'primary-ssh.service', '--property=MainPID', '--value');
  installUsbGateway({ apply: true, node: '/usr/bin/node' });
  installUsbGateway({ apply: true, node: '/usr/bin/node' });
  check('repeat installation leaves filter rules unchanged', filter() === guardBefore);
  check('repeat installation preserves primary SSH process', ctl('show', 'primary-ssh.service', '--property=MainPID', '--value') === beforePid);
  const restarts = Number(ctl('show', gatewayUnit, '--property=NRestarts', '--value'));
  await until(() => Number(ctl('show', gatewayUnit, '--property=NRestarts', '--value')) > restarts, 'SNAT retry missing');
  check('SNAT retries without TUN and publishes no NAT', !nat().includes(usbSnatLine));
  check('USB rescue login with retrying SNAT', await login());
  ip('link', 'add', 'wlan0', 'type', 'dummy'); ip('addr', 'add', '192.168.1.7/24', 'dev', 'wlan0'); ip('link', 'set', 'wlan0', 'up');
  ip('route', 'add', 'default', 'via', '192.168.1.1', 'dev', 'wlan0');
  ip('route', 'add', '154.62.226.216/32', 'via', '192.168.1.1', 'dev', 'wlan0');
  ip('link', 'add', 'tun0', 'type', 'dummy'); ip('addr', 'add', '10.99.0.2/24', 'dev', 'tun0'); ip('link', 'set', 'tun0', 'up');
  ip('route', 'add', '0.0.0.0/1', 'dev', 'tun0'); ip('route', 'add', '128.0.0.0/1', 'dev', 'tun0');
  try { await until(() => state(gatewayUnit) === 'active', 'SNAT did not recover automatically'); }
  catch (e) { console.error(command('journalctl', ['-u', gatewayUnit, '--no-pager', '-n', '15'])); throw e; }
  check('SNAT automatically installed after delayed TUN readiness', nat().split('\n').filter(l => l === usbSnatLine).length === 1);
  check('guard unchanged after SNAT activation', filter() === guardBefore);
  const pid = ctl('show', 'clean-vpn-usb-rescue.socket', '--property=ActiveEnterTimestampMonotonic', '--value');
  ctl('restart', 'clean-vpn.service');
  check('main VPN restart retains single SNAT rule', nat().split('\n').filter(l => l === usbSnatLine).length === 1);
  check('main VPN restart leaves rescue socket untouched', ctl('show', 'clean-vpn-usb-rescue.socket', '--property=ActiveEnterTimestampMonotonic', '--value') === pid);
  ip('link', 'delete', 'tun0'); ctl('stop', 'clean-vpn.service');
  check('rescue SSH still works without TUN/VPN', await login());
  removeUsbGateway({ apply: true });
  await delay(5500);
  check('removal stops retries and removes own NAT while retaining guard', !nat().includes(usbSnatLine) && filter() === guardBefore);
  check('rescue SSH survives gateway removal', await login());
}
