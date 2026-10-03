/** Destructive fixtures only inside an explicitly marked, NIC-less VM. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { execFileSync, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { installUsbRescue, rescueFiles } from './host-usb-rescue.mjs';
const command = (file, args = []) => execFileSync(file, args, { encoding: 'utf8', timeout: 30000 });
const ip = (...args) => command('ip', args);
const ctl = (...args) => command('/usr/bin/systemctl', args);
const put = (path, value, mode = 0o644) => { fs.mkdirSync(path.slice(0, path.lastIndexOf('/')), { recursive: true }); fs.writeFileSync(path, value, { mode }); };
const check = (name, value) => { assert.ok(value, name); console.log('USB_RESCUE_CHECK ' + name); };
const until = async (fn, label) => { const end = Date.now() + 30000; while (!fn()) { assert.ok(Date.now() < end, label); await delay(200); } };
const state = unit => ctl('show', unit, '--property=ActiveState', '--value').trim();
function usb() {
  ip('link', 'add', 'usb0', 'address', '02:00:00:00:00:02', 'type', 'veth', 'peer', 'name', 'peer0', 'netns', 'peer');
  ip('-n', 'peer', 'addr', 'add', '192.168.7.19/24', 'dev', 'peer0');
  ip('-n', 'peer', 'link', 'set', 'peer0', 'up');
}
async function login(ns = 'peer', port = '2222') {
  const result = await promisify(execFile)('ip', ['netns', 'exec', ns, '/usr/bin/ssh', '-F', '/dev/null', '-i', '/root/test-key',
    '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/root/known_hosts',
    '-o', 'ConnectTimeout=3', '-p', port, 'root@192.168.7.1', 'printf rescue-login-ok'], { timeout: 15000 });
  return result.stdout === 'rescue-login-ok';
}
export function prepare() {
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(x => x.ifname), ['lo']);
  ip('link', 'set', 'lo', 'up'); ip('netns', 'add', 'peer'); ip('netns', 'add', 'uplink');
  ip('-n', 'peer', 'link', 'set', 'lo', 'up'); ip('-n', 'uplink', 'link', 'set', 'lo', 'up');
  put('/etc/udev/rules.d/99-usb-test.rules', 'SUBSYSTEM=="net", ACTION=="add", TAG+="systemd", ENV{SYSTEMD_ALIAS}="/sys/subsystem/net/devices/$name"\n');
  put('/etc/ssh/sshd_config', 'HostKey /root/host-key\nPasswordAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin yes\nUsePAM no\nUseDNS no\nListenAddress 192.168.7.1\n');
  fs.mkdirSync('/root/.ssh', { recursive: true, mode: 0o700 });
  for (const path of ['/root/host-key', '/root/test-key']) command('/usr/bin/ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', path]);
  put('/root/.ssh/authorized_keys', fs.readFileSync('/root/test-key.pub'), 0o600);
  const pub = fs.readFileSync('/root/host-key.pub', 'utf8').trim().split(' ').slice(0, 2).join(' ');
  put('/root/known_hosts', `192.168.7.1 ${pub}\n[192.168.7.1]:2222 ${pub}\n`, 0o600);
  put('/etc/shadow', 'root::20000:0:99999:7:::\n', 0o600);
  fs.appendFileSync('/etc/passwd', 'sshd:x:74:74:sshd:/run/sshd:/bin/false\n');
  fs.appendFileSync('/etc/group', 'sshd:x:74:\n');
  if (process.env.USB_RESCUE_BOOT === 'installed') {
    for (const [path, contents] of Object.entries(rescueFiles)) put(path, contents, path.endsWith('.sh') ? 0o755 : 0o644);
    for (const target of ['multi-user.target', 'sys-subsystem-net-devices-usb0.device']) {
      fs.mkdirSync(`/etc/systemd/system/${target}.wants`, { recursive: true });
      fs.symlinkSync('../clean-vpn-usb-rescue.socket', `/etc/systemd/system/${target}.wants/clean-vpn-usb-rescue.socket`);
    }
  }
}
async function test() {
  const socket = 'clean-vpn-usb-rescue.socket', address = 'clean-vpn-usb-rescue-address.service';
  try { ctl('start', 'systemd-networkd.service'); } catch { /* intentional guard failure */ }
  check('guard failure leaves networkd stopped', state('clean-vpn-killswitch.service') === 'failed' && state('systemd-networkd.service') !== 'active');
  check('USB absent initially', !fs.existsSync('/sys/class/net/usb0'));
  usb();
  if (process.env.USB_RESCUE_BOOT !== 'installed') {
    ip('addr', 'add', '192.168.7.1/24', 'dev', 'usb0'); ip('link', 'set', 'usb0', 'up');
    await until(() => state('sys-subsystem-net-devices-usb0.device') === 'active', 'udev USB alias missing');
    ctl('start', 'primary-ssh.service');
    const pid = ctl('show', 'primary-ssh.service', '--property=MainPID', '--value');
    const network = () => JSON.stringify([ip('-4', 'route', 'show', 'table', 'all'),
      command('iptables', ['-S']), command('ip6tables', ['-S'])]);
    const before = network();
    installUsbRescue();
    check('plan publishes no rescue files', Object.keys(rescueFiles).every(p => !fs.existsSync(p)));
    installUsbRescue({ apply: true });
    check('installation preserves firewall and IPv4 routes', before === network());
    check('primary SSH process unchanged by installation', pid === ctl('show', 'primary-ssh.service', '--property=MainPID', '--value'));
    check('primary port 22 still accepts authenticated login', await login('peer', '22'));
    assert.throws(() => installUsbRescue({ apply: true }));
    check('reinstallation refuses without changing published files', Object.entries(rescueFiles).every(([p, text]) => fs.readFileSync(p, 'utf8') === text));
  }
  await until(() => state(socket) === 'active', 'socket did not activate for late USB');
  check('late USB rescue login with failed guard/networkd', await login());
  check('fallback supplies USB address', JSON.parse(ip('-j', 'addr', 'show', 'usb0'))[0].addr_info.some(a => a.local === '192.168.7.1'));
  ip('addr', 'add', '192.168.7.2/24', 'dev', 'usb0');
  const unexpected = ip('-4', '-o', 'addr', 'show', 'usb0');
  assert.throws(() => command('/bin/bash', ['/usr/local/bin/clean-vpn-usb-rescue-address.sh']));
  check('unexpected USB address refused without mutation', ip('-4', '-o', 'addr', 'show', 'usb0') === unexpected);
  ip('addr', 'del', '192.168.7.2/24', 'dev', 'usb0');
  ip('link', 'add', 'test-wan', 'type', 'veth', 'peer', 'name', 'peer1', 'netns', 'uplink');
  ip('addr', 'add', '198.18.0.1/24', 'dev', 'test-wan'); ip('link', 'set', 'test-wan', 'up');
  ip('-n', 'uplink', 'addr', 'add', '198.18.0.2/24', 'dev', 'peer1'); ip('-n', 'uplink', 'link', 'set', 'peer1', 'up');
  ip('-n', 'uplink', 'route', 'add', '192.168.7.1/32', 'via', '198.18.0.1');
  let blocked = false; try { await login('uplink'); } catch { blocked = true; }
  check('uplink cannot reach rescue address even before guard rules', blocked);
  command('/bin/bash', ['/project/scripts/autostart/killswitch.sh', 'up', '--scope=both', '--ipv6=block', '--server=154.62.226.216', '--ssh-port=22', '--tun=tun0']);
  check('USB authenticated login with real persistent guard', await login());
  command('/bin/bash', ['/project/scripts/autostart/killswitch.sh', 'status']);
  ip('link', 'delete', 'usb0');
  await until(() => state(socket) === 'inactive' && state(address) === 'inactive', 'device removal did not stop rescue');
  usb();
  await until(() => state(socket) === 'active', 'device reappearance did not activate rescue');
  check('USB recreation restores address and authenticated login', await login());
  check('networkd remains stopped throughout rescue test', state('systemd-networkd.service') !== 'active');
  if (process.env.USB_GATEWAY_LAB === '1') {
    const { testGateway } = await import('./host-usb-gateway-vm.mjs');
    await testGateway({ command, ip, ctl, put, check, until, state, login });
  }
  console.log('USB_RESCUE_PASS');
}
if (process.argv[1]?.endsWith('/host-usb-rescue-vm.mjs')) {
  assert.ok(fs.readFileSync('/proc/cmdline', 'utf8').trim().split(/\s+/).includes('meshpn.usb-rescue-lab=1'));
  assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
  if (process.argv[2] === 'prepare') {
    prepare();
    if (process.env.USB_GATEWAY_LAB === '1' && process.env.USB_RESCUE_BOOT === 'installed') {
      const { prepareGateway } = await import('./host-usb-gateway-vm.mjs'); prepareGateway({ put });
    }
  }
  else try { await test(); } catch (e) { console.error('USB_RESCUE_FAIL', e.stack); }
  finally { command('/usr/bin/systemctl', ['poweroff', '--no-block']); }
}
