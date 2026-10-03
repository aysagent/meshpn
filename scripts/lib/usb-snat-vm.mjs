/** Destructive network fixtures ONLY inside the marked NIC-less disposable VM. */
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { changeUsbSnat, usbMssRules, usbMssLines } from '../clean-vpn-usb-snat.mjs';
import { openHostRoutes } from './vpn-host-routes.mjs';
assert.ok(fs.readFileSync('/proc/cmdline', 'utf8').split(/\s+/).includes('meshpn.usb-snat-lab=1'));
assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
const cmd = (name, args) => execFileSync(name, args, { encoding: 'utf8', timeout: 12000 });
const ip = (...args) => cmd('ip', args);
assert.deepEqual(JSON.parse(ip('-j', 'link')).map(i => i.ifname), ['lo']);
const check = (name, ok) => { assert.ok(ok, name); console.log('USB_SNAT_CHECK ' + name); };
const children = [];
const serverCode = `
const http = require('node:http'), dgram = require('node:dgram');
http.createServer((q,s) => {
  if (q.url !== '/bulk') return s.end(q.socket.remoteAddress);
  let received = 0;
  q.on('data', b => { received += b.length; });
  q.on('end', () => { s.setHeader('x-upload-bytes', String(received)); s.end(Buffer.alloc(131072, 97)); });
}).listen(8443, '::', () => console.log('READY'));
const udp = dgram.createSocket('udp4');
udp.on('message', (b,r) => udp.send(Buffer.from(r.address), r.port, r.address)); udp.bind(53, process.env.PROBE_DNS_BIND || '1.1.1.1');
`;
async function server(ns) {
  const p = spawn('ip', ['netns', 'exec', ns, 'node', '-e', serverCode], { stdio: ['ignore', 'pipe', 'inherit'] });
  children.push(p);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('server not ready')), 5000);
    p.once('error', reject); p.once('exit', code => reject(Error(`server exited ${code}`)));
    p.stdout.once('data', () => { clearTimeout(timer); resolve(); });
  });
}
function tcp(host) {
  const script = `const h=require('node:http'); const q=h.get({host:${JSON.stringify(host)},port:8443,path:'/'},r=>{let b='';r.on('data',c=>b+=c);r.on('end',()=>{process.stdout.write(b);process.exit(0)})});q.on('error',()=>process.exit(2));setTimeout(()=>process.exit(3),1400);`;
  try { return cmd('ip', ['netns', 'exec', 'mac', 'node', '-e', script]); } catch { return null; }
}
function udp() {
  const script = `const s=require('node:dgram').createSocket('udp4');s.on('message',b=>{process.stdout.write(b);process.exit(0)});s.send(Buffer.from('synthetic-DNS-port-probe'),53,'1.1.1.1');setTimeout(()=>process.exit(3),1400);`;
  try { return cmd('ip', ['netns', 'exec', 'mac', 'node', '-e', script]); } catch { return null; }
}
function bulk(upload = false) {
  const script = `const h=require('node:http'),c=require('node:crypto');
const payload=Buffer.alloc(131072,97);
const q=h.request({host:'1.1.1.1',port:8443,path:'/bulk',method:'POST',headers:{'content-length':${upload ? 131072 : 1}}},r=>{
  const chunks=[];r.on('data',b=>chunks.push(b));r.on('end',()=>{
    const body=Buffer.concat(chunks);if(r.headers['x-upload-bytes']!=='${upload ? 131072 : 1}'||!body.equals(payload))process.exit(2);
    process.stdout.write('bulk-ok');process.exit(0);
  });
});q.on('error',e=>{console.error(e.message);process.exit(2)});q.end(payload.subarray(0,${upload ? 131072 : 1}));setTimeout(()=>{console.error('bulk timeout');process.exit(3)},8000);`;
  try { return cmd('ip', ['netns', 'exec', 'mac', 'node', '-e', script]); } catch (e) { console.error('BULK_DIAGNOSTIC', e.status, String(e.stderr || '').trim()); return null; }
}
const guard = (...args) => cmd('bash', ['/project/scripts/autostart/killswitch.sh', ...args]);
// Systemd/rescue state is a fixture here; actual kernel addresses/routes/NAT/filter
// and the production kill-switch are used. tun0 is a veth model, not VPN/TLS.
const run = (name, args) => name === 'systemctl' ? 'active\n' : name === 'guard' ? guard(...args) : cmd(name, args);
try {
  ip('link', 'set', 'lo', 'up');
  for (const [ns, device, local, peer] of [
    ['mac', 'usb0', '192.168.7.1', '192.168.7.19'],
    ['exit', 'tun0', '10.99.0.2', '10.99.0.1'],
    ['router', 'wlan0', '192.168.1.10', '192.168.1.1'],
  ]) {
    ip('netns', 'add', ns); ip('link', 'add', device, 'type', 'veth', 'peer', 'name', 'peer0', 'netns', ns);
    if (device === 'usb0') ip('link', 'set', device, 'address', '02:00:00:00:00:02');
    ip('addr', 'add', local + '/24', 'dev', device); ip('link', 'set', device, 'up');
    ip('-n', ns, 'link', 'set', 'lo', 'up'); ip('-n', ns, 'addr', 'add', peer + '/24', 'dev', 'peer0');
    ip('-n', ns, 'link', 'set', 'peer0', 'up');
  }
  ip('-n', 'mac', 'route', 'add', 'default', 'via', '192.168.7.1');
  ip('link', 'set', 'tun0', 'mtu', '1400');
  // The size-drop fixture must see wire-sized packets, not a 64 KiB GSO skb.
  for (const ns of ['mac', 'exit']) ip('netns', 'exec', ns, '/usr/sbin/ethtool', '-K', 'peer0', 'tso', 'off', 'gso', 'off', 'gro', 'off');
  for (const dev of ['usb0', 'tun0']) cmd('/usr/sbin/ethtool', ['-K', dev, 'tso', 'off', 'gso', 'off', 'gro', 'off']);
  ip('-n', 'exit', 'route', 'add', '192.168.7.0/24', 'via', '10.99.0.2');
  ip('route', 'add', 'default', 'via', '192.168.1.1');
  ip('route', 'add', '154.62.226.216/32', 'via', '192.168.1.1', 'dev', 'wlan0');
  ip('route', 'add', '0.0.0.0/1', 'dev', 'tun0'); ip('route', 'add', '128.0.0.0/1', 'dev', 'tun0');
  for (const ns of ['exit', 'router']) ip('-n', ns, 'addr', 'add', '1.1.1.1/32', 'dev', 'lo');
  ip('-n', 'mac', '-6', 'addr', 'add', 'fd42:7::19/64', 'dev', 'peer0', 'nodad');
  ip('-6', 'addr', 'add', 'fd42:7::1/64', 'dev', 'usb0', 'nodad');
  ip('-6', 'addr', 'add', '2001:db8:1::2/64', 'dev', 'wlan0', 'nodad');
  ip('-n', 'router', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'peer0', 'nodad');
  ip('-n', 'router', '-6', 'addr', 'add', '2001:db8:99::1/128', 'dev', 'lo', 'nodad');
  ip('-n', 'mac', '-6', 'route', 'add', 'default', 'via', 'fd42:7::1');
  ip('-6', 'route', 'add', 'default', 'via', '2001:db8:1::1');
  ip('-n', 'router', '-6', 'route', 'add', 'fd42:7::/64', 'via', '2001:db8:1::2');
  cmd('sysctl', ['-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1']);
  cmd('iptables', ['-t', 'nat', '-A', 'POSTROUTING', '-o', 'wlan0', '-j', 'MASQUERADE']);
  cmd('iptables', ['-A', 'FORWARD', '-i', 'usb0', '-o', 'wlan0', '-j', 'ACCEPT']);
  cmd('iptables', ['-A', 'FORWARD', '-i', 'wlan0', '-o', 'usb0', '-j', 'ACCEPT']);
  ip('netns', 'exec', 'exit', 'iptables', '-A', 'INPUT', '-d', '1.1.1.1', '!', '-s', '10.99.0.2', '-j', 'DROP');
  await server('exit'); await server('router');
  // Root HTTP service models USB management reachability, not SSH authentication.
  const local = spawn('node', ['-e', serverCode], { env: { ...process.env, PROBE_DNS_BIND: '192.168.7.1' }, stdio: ['ignore', 'pipe', 'inherit'] }); children.push(local);
  await new Promise(resolve => local.stdout.once('data', resolve));
  check('positive control external IPv6 works before guard', tcp('2001:db8:99::1') === 'fd42:7::19');
  guard('up', '--scope=both', '--ipv6=block', '--tun=tun0', '--server=154.62.226.216', '--ssh-port=22', '--usb-dns=1', '--usb-strict=1');
  const filter4 = cmd('iptables', ['-S']), filter6 = cmd('ip6tables', ['-S']);
  check('missing SNAT reproduces forwarded TCP failure', tcp('1.1.1.1') === null);
  check('dry run changes nothing', changeUsbSnat({ run }).status === 'planned');
  check('apply production SNAT repair', changeUsbSnat({ run, apply: true }).status === 'applied');
  check('forwarded TCP reaches exit with tunnel source', tcp('1.1.1.1') === '::ffff:10.99.0.2');
  check('forwarded UDP53 roundtrip uses tunnel source', udp() === '10.99.0.2');
  check('repeat application is idempotent', changeUsbSnat({ run, apply: true }).status === 'already-present');
  check('both canonical MSS rules installed', usbMssLines.every(l => cmd('iptables', ['-t', 'mangle', '-S', 'FORWARD']).includes(l)));
  // The veth endpoints have asymmetric MTUs, 1500 at origin vs 1400 on
  // tun0. Oversized responses cannot cross the receiving veth. No host changes.
  ip('netns', 'exec', 'exit', 'sysctl', '-w', 'net.ipv4.tcp_no_metrics_save=1');
  check('128 KiB download baseline with MSS', bulk() === 'bulk-ok');
  for (const rule of usbMssRules) cmd('iptables', ['-t', 'mangle', '-D', 'FORWARD', ...rule]);
  check('large TCP reproduces MTU black hole without MSS', bulk() === null);
  changeUsbSnat({ run, apply: true });
  check('128 KiB download recovers with production MSS', bulk() === 'bulk-ok');
  check('128 KiB TCP upload and download pass with production MSS', bulk(true) === 'bulk-ok');
  check('MSS application remains idempotent after bulk TCP', changeUsbSnat({ run, apply: true }).status === 'already-present');
  check('IPv4 filter unchanged', cmd('iptables', ['-S']) === filter4);
  check('IPv6 filter unchanged', cmd('ip6tables', ['-S']) === filter6);
  check('USB management remains reachable', tcp('192.168.7.1') === '::ffff:192.168.7.19');
  check('external forwarded IPv6 blocked', tcp('2001:db8:99::1') === null);
  // Reproduce carrier/DHCP churn: the same NIC returns with a new lease,
  // but networkd's deleted bypass routes do not return with its default route.
  const routes = openHostRoutes();
  try {
    ip('route', 'del', '154.62.226.216/32', 'via', '192.168.1.1', 'dev', 'wlan0');
    routes.begin('tun0');
    routes.add('154.62.226.216/32', 'wlan0', '192.168.1.1');
    routes.add('192.168.0.0/16', 'wlan0', '192.168.1.1');
    const journalBefore = JSON.stringify(routes.state);
    ip('link', 'set', 'wlan0', 'down');
    ip('addr', 'del', '192.168.1.10/24', 'dev', 'wlan0');
    ip('-4', 'route', 'flush', 'dev', 'wlan0');
    assert.throws(() => routes.repairUplink('wlan0', '192.168.1.1', '154.62.226.216'));
    check('reconnect waits while uplink default is absent', !JSON.parse(ip('-j', '-4', 'route', 'show', 'default')).length);
    ip('link', 'set', 'wlan0', 'up'); ip('addr', 'add', '192.168.1.7/24', 'dev', 'wlan0');
    ip('route', 'add', 'default', 'via', '192.168.1.1');
    check('DHCP return alone reproduces exit routed into TUN', JSON.parse(ip('-j', '-4', 'route', 'get', '154.62.226.216'))[0].dev === 'tun0');
    check('same-process repair restores two owned uplink routes', routes.repairUplink('wlan0', '192.168.1.1', '154.62.226.216') === 2);
    const exitRoute = JSON.parse(ip('-j', '-4', 'route', 'get', '154.62.226.216'))[0];
    check('exit bypass uses restored wlan0 gateway and new DHCP source', exitRoute.dev === 'wlan0' && exitRoute.gateway === '192.168.1.1' && exitRoute.prefsrc === '192.168.1.7');
    check('route repair leaves ownership intent unchanged', JSON.stringify(routes.state) === journalBefore);
    check('route repair is idempotent', routes.repairUplink('wlan0', '192.168.1.1', '154.62.226.216') === 0);
    check('route repair leaves IPv4 and IPv6 guards unchanged', cmd('iptables', ['-S']) === filter4 && cmd('ip6tables', ['-S']) === filter6);
    check('USB remains reachable after DHCP churn', tcp('192.168.7.1') === '::ffff:192.168.7.19');
    routes.restore();
    check('repair remains compatible with journal cleanup', routes.state.stage === 'released');
    ip('route', 'add', '154.62.226.216/32', 'via', '192.168.1.1', 'dev', 'wlan0');
  } finally { routes.release(); }
  check('remove only own SNAT', changeUsbSnat({ run, apply: true, remove: true }).status === 'removed');
  check('removal also removes both MSS rules', cmd('iptables', ['-t', 'mangle', '-S', 'FORWARD']).trim() === '-P FORWARD ACCEPT');
  check('removed SNAT reproduces failure again', tcp('1.1.1.1') === null);
  changeUsbSnat({ run, apply: true });
  ip('link', 'del', 'tun0');
  check('with tunnel gone direct IPv4 TCP blocked', tcp('1.1.1.1') === null);
  check('with tunnel gone direct UDP53 blocked', udp() === null);
  check('with tunnel gone IPv6 still blocked', tcp('2001:db8:99::1') === null);
  check('with tunnel gone USB management still reachable', tcp('192.168.7.1') === '::ffff:192.168.7.19');
  check('removal works without TUN', changeUsbSnat({ run, apply: true, remove: true }).status === 'removed');
  guard('down', '--tun=tun0');
  check('positive control direct IPv4 works only after removing guard', tcp('1.1.1.1') === '::ffff:192.168.1.7');
  check('positive control direct UDP53 works after removing guard', udp() === '192.168.1.7');
  console.log('USB_SNAT_PASS');
} catch (error) { console.error('USB_SNAT_FAIL ' + error.stack); process.exitCode = 1; }
finally { for (const p of children) p.kill('SIGKILL'); }
