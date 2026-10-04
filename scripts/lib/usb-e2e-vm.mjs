/** Real installer/TLS/TUN with synthetic peers. Destructive only in marked QEMU. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { dirname } from 'node:path';
import { execFileSync, execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import https from 'node:https';
import net from 'node:net';
import dgram from 'node:dgram';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { hostBootVmUnits, BOOT_FILES } from './vpn-host-boot-vm.mjs';
import { rescueFiles } from './host-usb-rescue.mjs';
import { gatewayFiles, gatewayUnit } from './host-usb-gateway.mjs';
import { usbSnatLine } from '../clean-vpn-usb-snat.mjs';
import { makeDnsQuery, validateDnsResponse, parseDnsQuery } from './lab-dns-wire.mjs';
import { tunnelDnsFixtureAnswer } from './dns-tunnel-cli-lab.mjs';
import { exchangePlainDns } from './dns-tunnel-forwarder.mjs';
import { runUsbFaultScenarios } from './usb-fault-vm.mjs';
import { runUsbSoak, runLongTcpPeer, startLongTcpOrigin } from './usb-soak-vm.mjs';
import { runUsbPmtu } from './usb-pmtu-vm.mjs';

const script = '/project/scripts/lib/usb-e2e-vm.mjs', exitIp = '154.62.226.216';
const snapshotFiles = [...BOOT_FILES.map(p => '/' + p), ...Object.keys(rescueFiles), ...Object.keys(gatewayFiles('/usr/bin/node'))];
const links = ['multi-user.target.wants/clean-vpn.service', 'multi-user.target.wants/clean-vpn-killswitch.service',
  'multi-user.target.wants/clean-vpn-usb-snat.service', 'multi-user.target.wants/clean-vpn-usb-rescue.socket',
  'sys-subsystem-net-devices-usb0.device.wants/clean-vpn-usb-rescue.socket'];
export function usbE2eUnits() {
  const base = hostBootVmUnits();
  base['systemd-journald.socket'] = '[Unit]\nDefaultDependencies=no\nBefore=sockets.target\n[Socket]\nListenDatagram=/run/systemd/journal/socket\nListenStream=/run/systemd/journal/stdout\nPassCredentials=yes\nSocketMode=0666\n';
  base['systemd-journald.service'] = '[Unit]\nDefaultDependencies=no\nRequires=systemd-journald.socket\nAfter=systemd-journald.socket\n[Service]\nType=notify\nExecStart=/usr/lib/systemd/systemd-journald\nStandardOutput=null\nRuntimeDirectory=systemd/journal\nRuntimeDirectoryPreserve=yes\n';
  for (const name of ['host-boot-driver.service', 'host-boot-exit.service', 'host-boot-fixture.service']) delete base[name];
  base['default.target'] = '[Unit]\nDefaultDependencies=no\nWants=usb-e2e-driver.service usb-e2e-fixture.service usb-e2e-exit.service systemd-networkd.service systemd-udev-trigger.service multi-user.target\n';
  base['usb-e2e-driver.service'] = `[Unit]\nDefaultDependencies=no\nWants=dbus.service\nAfter=dbus.service systemd-networkd.service usb-e2e-fixture.service usb-e2e-exit.service\n[Service]\nType=oneshot\nWorkingDirectory=/project\nEnvironment=PATH=/usr/bin:/usr/sbin:/bin:/sbin OPENSSL_CONF=/dev/null\nExecStart=/usr/bin/node ${script} run\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTimeoutStartSec=24min\nSuccessExitStatus=SIGTERM\n`;
  base['usb-e2e-fixture.service'] = `[Unit]\nDefaultDependencies=no\n[Service]\nType=simple\nNetworkNamespacePath=/run/netns/router\nWorkingDirectory=/project\nExecStart=/usr/bin/node ${script} fixture\nStandardOutput=append:/run/usb-e2e-fixture.log\nStandardError=append:/run/usb-e2e-fixture.log\n`;
  base['usb-e2e-exit.service'] = '[Unit]\nDefaultDependencies=no\n[Service]\nType=simple\nNetworkNamespacePath=/run/netns/exit\nWorkingDirectory=/project\nEnvironment=PATH=/usr/bin:/usr/sbin:/bin:/sbin OPENSSL_CONF=/dev/null\nExecStart=/usr/bin/node /project/scripts/clean-vpn.js --role=exit --type=tls --server=0.0.0.0:443 --ext=eth0 --ipv6=off --tls-cert-dir=/state/cert --shared-hmac-key=/state/cert/secret.key --tls-server-name=vpn.test --tls-public-name=vpn.test\nStandardOutput=append:/run/usb-e2e-exit.log\nStandardError=append:/run/usb-e2e-exit.log\nTimeoutStopSec=150\nKillMode=mixed\n';
  base['usb-e2e-dns-relay.service'] = '[Unit]\nDefaultDependencies=no\n[Service]\nType=simple\nExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/dev/null --no-resolv --server=192.168.1.1 --listen-address=192.168.7.1 --bind-interfaces --user=root --group=root --cache-size=0 --pid-file=/run/usb-e2e-relay.pid\nStandardOutput=append:/run/usb-e2e-relay.log\nStandardError=append:/run/usb-e2e-relay.log\n';
  base['usb-e2e-ssh.service'] = '[Unit]\nDefaultDependencies=no\n[Service]\nType=simple\nExecStart=/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config\n';
  return base;
}
export function assertUsbE2eVm(mode) {
  assert.ok(['prepare', 'fixture', 'probe', 'probe-worker', 'fault-monitor', 'long-tcp', 'run'].includes(mode));
  assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.usb-e2e=1(?:\s|$)/);
  assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
  assert.equal(process.getuid(), 0);
  if (mode !== 'prepare') assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
}
const sync = (file, args = []) => execFileSync(file, args, { encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024 }).trim();
const exec = (file, args, options = {}) => promisify(execFile)(file, args, { encoding: 'utf8', timeout: 450000, maxBuffer: 2 * 1024 * 1024, ...options });
const ip = (...args) => sync('/usr/bin/ip', args);
const at = (ns, ...args) => ip('netns', 'exec', ns, ...args);
const ctl = (...args) => exec('/usr/bin/systemctl', ['--no-pager', ...args]);
const property = async (unit, p) => (await ctl('show', unit, `--property=${p}`, '--value')).stdout.trim();
const put = (path, bytes, mode = 0o644) => { fs.mkdirSync(dirname(path), { recursive: true }); fs.writeFileSync(path, bytes); fs.chmodSync(path, mode); };
const phase = () => fs.existsSync('/state/phase') ? Number(fs.readFileSync('/state/phase', 'utf8')) : 0;
const hash = b => createHash('sha256').update(b).digest('hex');
const event = e => console.log('USB_E2E_EVENT ' + JSON.stringify(e));
const until = async (f, message, ms = 180000) => { const end = Date.now() + ms; while (!await f()) { assert.ok(Date.now() < end, message); await delay(700); } };

function prepare() {
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(x => x.ifname), ['lo']);
  assert.match(fs.readFileSync('/proc/mounts', 'utf8'), /^\/dev\/vda \/state ext4 /m);
  // Capture client diagnostics without introducing production-unit overrides
  // (the installer intentionally rejects those). All output stays in this VM.
  put('/etc/systemd/system.conf', '[Manager]\nDefaultStandardOutput=tty\nDefaultStandardError=inherit\n');
  const p = phase(); assert.ok([0, 1].includes(p));
  ip('link', 'set', 'lo', 'up');
  for (const ns of ['router', 'exit', 'peer']) { ip('netns', 'add', ns); at(ns, 'ip', 'link', 'set', 'lo', 'up'); }
  ip('link', 'add', 'wlan0', 'address', '02:00:00:00:01:02', 'type', 'veth', 'peer', 'name', 'client0', 'netns', 'router');
  at('router', 'ip', 'link', 'add', 'exit0', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'exit');
  ip('link', 'add', 'usb0', 'address', '02:00:00:00:00:02', 'type', 'veth', 'peer', 'name', 'usbpeer', 'netns', 'peer');
  ip('addr', 'add', '192.168.7.1/24', 'dev', 'usb0'); ip('-6', 'addr', 'add', '2001:db8:7::1/64', 'dev', 'usb0', 'nodad'); ip('link', 'set', 'usb0', 'up');
  ip('-6', 'addr', 'add', 'fd00:7::1/64', 'dev', 'usb0', 'nodad');
  for (const [ns, dev, v4, v6] of [['router', 'client0', '192.168.1.1', '2001:db8:1::1'], ['router', 'exit0', '154.62.226.1', '2001:db8:2::1'], ['exit', 'eth0', exitIp, '2001:db8:2::2'], ['peer', 'usbpeer', '192.168.7.19', '2001:db8:7::19']]) {
    at(ns, 'ip', 'addr', 'add', v4 + '/24', 'dev', dev); at(ns, 'ip', '-6', 'addr', 'add', v6 + '/64', 'dev', dev, 'nodad'); at(ns, 'ip', 'link', 'set', dev, 'up');
  }
  sync('sysctl', ['-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1']);
  at('router', 'sysctl', '-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1');
  at('router', 'ip', '-6', 'route', 'add', '2001:db8:7::/64', 'via', 'fe80::ff:fe00:102', 'dev', 'client0');
  at('router', 'ip', '-6', 'addr', 'add', 'fd00:1::1/64', 'dev', 'client0', 'nodad');
  at('peer', 'ip', '-6', 'addr', 'add', 'fd00:7::19/64', 'dev', 'usbpeer', 'nodad');
  at('router', 'ip', '-6', 'route', 'add', 'fd00:7::/64', 'via', 'fe80::ff:fe00:102', 'dev', 'client0');
  for (const [ns, v4, v6] of [['exit', '154.62.226.1', '2001:db8:2::1'], ['peer', '192.168.7.1', '2001:db8:7::1']]) {
    at(ns, 'ip', 'route', 'add', 'default', 'via', v4);
    // Link-local next hops, as with RA. A GUA/ULA next hop would require a
    // unicast NA to that scope, denied by the existing host-only IPv6 guard;
    // a pre-install neighbour cache must not hide that fixture dependency.
    at(ns, 'ip', '-6', 'route', 'add', 'default', 'via', ns === 'peer' ? 'fe80::ff:fe00:2' : v6,
      'dev', ns === 'peer' ? 'usbpeer' : 'eth0');
  }
  // Isolate IPv6 FORWARD/DNS policy from the existing host-only IPv6 runtime
  // guard, which rejects unicast NAs to ULA/GUA. Linux may source an NS from
  // the triggering packet even for a link-local next hop. Permanent synthetic
  // neighbours make positive controls meaningful on BOTH boots; this lab does
  // not accept dynamic NDP/RA or a general-purpose IPv6 router deployment.
  const routerMac = JSON.parse(at('router', 'ip', '-j', 'link', 'show', 'client0'))[0].address;
  const peerMac = JSON.parse(at('peer', 'ip', '-j', 'link', 'show', 'usbpeer'))[0].address;
  at('peer', 'ip', '-6', 'neigh', 'replace', 'fe80::ff:fe00:2', 'lladdr', '02:00:00:00:00:02', 'nud', 'permanent', 'dev', 'usbpeer');
  at('router', 'ip', '-6', 'neigh', 'replace', 'fe80::ff:fe00:102', 'lladdr', '02:00:00:00:01:02', 'nud', 'permanent', 'dev', 'client0');
  for (const addr of ['fd00:1::1', '2001:db8:1::1']) ip('-6', 'neigh', 'replace', addr, 'lladdr', routerMac, 'nud', 'permanent', 'dev', 'wlan0');
  for (const addr of ['fd00:7::19', '2001:db8:7::19']) ip('-6', 'neigh', 'replace', addr, 'lladdr', peerMac, 'nud', 'permanent', 'dev', 'usb0');
  for (const addr of ['1.0.0.1', '1.1.1.1', '8.8.8.8']) at('router', 'ip', 'addr', 'add', addr + '/32', 'dev', 'lo');
  at('router', 'ip', '-6', 'addr', 'add', '2606:4700:4700::1111/128', 'dev', 'lo', 'nodad');
  sync('iptables', ['-t', 'nat', '-A', 'POSTROUTING', '-o', 'wlan0', '-j', 'MASQUERADE']); // existing reviewed gadget prerequisite
  put('/etc/systemd/network/10-usb-e2e.network', '[Match]\nName=wlan0\n[Network]\nDHCP=ipv4\nIPForward=yes\nIPv6AcceptRA=no\nLinkLocalAddressing=ipv6\nAddress=2001:db8:1::2/64\nAddress=fd00:1::2/64\nGateway=2001:db8:1::1\n[DHCPv4]\nUseDNS=no\nClientIdentifier=mac\n');
  put('/etc/systemd/system/systemd-networkd.service.d/e2e.conf', '[Unit]\nRequires=dbus.service systemd-udev-trigger.service\nAfter=dbus.service systemd-udev-trigger.service\n');
  put('/etc/udev/rules.d/99-usb-e2e.rules', 'SUBSYSTEM=="net", ACTION=="add", TAG+="systemd", ENV{SYSTEMD_ALIAS}="/sys/subsystem/net/devices/$name"\n');
  if (!p) {
    fs.mkdirSync('/state/cert', { recursive: true, mode: 0o700 });
    sync('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-x509', '-days', '2', '-subj', '/CN=vpn.test', '-addext', 'subjectAltName=DNS:vpn.test,DNS:origin.test', '-keyout', '/state/cert/privkey.pem', '-out', '/state/cert/fullchain.pem']);
    sync('openssl', ['rand', '-out', '/state/cert/secret.key', '32']);
    for (const path of ['/state/host-key', '/state/test-key']) sync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', path]);
  } else {
    const manifest = JSON.parse(fs.readFileSync('/state/installed.json', 'utf8'));
    for (const path of snapshotFiles) { const b = fs.readFileSync('/state/installed' + path); assert.equal(hash(b), manifest.files[path]); put(path, b, path.endsWith('.sh') ? 0o755 : 0o644); }
    for (const name of links) { const path = '/etc/systemd/system/' + name; fs.mkdirSync(dirname(path), { recursive: true }); fs.symlinkSync(manifest.links[name], path); }
  }
  put('/etc/ssh/sshd_config', 'HostKey /state/host-key\nPasswordAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin yes\nUsePAM no\nUseDNS no\nListenAddress 192.168.7.1\n');
  fs.mkdirSync('/run/sshd', { recursive: true, mode: 0o755 });
  put('/root/.ssh/authorized_keys', fs.readFileSync('/state/test-key.pub'), 0o600);
  const publicKey = fs.readFileSync('/state/host-key.pub', 'utf8').trim().split(' ').slice(0, 2).join(' ');
  put('/root/known_hosts', `[192.168.7.1]:2222 ${publicKey}\n192.168.7.1 ${publicKey}\n`, 0o600);
  put('/etc/shadow', 'root::20000:0:99999:7:::\n', 0o600);
  fs.appendFileSync('/etc/passwd', 'sshd:x:74:74:sshd:/run/sshd:/bin/false\n'); fs.appendFileSync('/etc/group', 'sshd:x:74:\n');
  event({ event: 'prepared', phase: p, restored: p === 1, uplinkDown: !JSON.parse(ip('-j', 'link', 'show', 'wlan0'))[0].flags.includes('UP') });
}

async function fixture() {
  if (fs.readFileSync('/proc/cmdline', 'utf8').includes('meshpn.usb-pmtu=1')) {
    const log = fs.openSync('/run/e2e-pmtu-hits', 'a', 0o600);
    const child = spawn('/usr/bin/usb-pmtu-probe', ['server', '1.0.0.1'], { stdio: ['ignore', log, log] });
    fs.closeSync(log);
    child.on('exit', () => process.exit(1));
    await until(() => hits('/run/e2e-pmtu-hits').some(r => r.event === 'ready'), 'PMTU origin ready');
  }
  if (fs.readFileSync('/proc/cmdline', 'utf8').includes('meshpn.usb-soak=1')) await startLongTcpOrigin();
  for (const host of ['1.0.0.1', '2606:4700:4700::1111', '192.168.1.1', 'fd00:1::1']) {
    const server = https.createServer({ key: fs.readFileSync('/state/cert/privkey.pem'), cert: fs.readFileSync('/state/cert/fullchain.pem') }, (q, r) => {
      fs.appendFileSync('/run/e2e-http-hits', JSON.stringify({ host, peer: q.socket.remoteAddress }) + '\n'); r.end(q.socket.remoteAddress);
    }); server.listen(18443, host); await once(server, 'listening');
    const record = (data, peer, protocol) => {
      if (data.length > 512) return null;
      const token = data.toString();
      fs.appendFileSync('/run/e2e-raw-hits', JSON.stringify({ host, peer, protocol, token }) + '\n');
      return Buffer.from(JSON.stringify({ peer, token }));
    };
    const tcp = net.createServer(s => { const peer = s.remoteAddress; let data = Buffer.alloc(0); s.on('error', () => {});
      s.on('data', b => { data = Buffer.concat([data, b]); if (data.length > 512) s.destroy(); });
      s.on('end', () => { const reply = record(data, peer, 'tcp'); if (reply) s.end(reply); });
    }); tcp.listen(38471, host); await once(tcp, 'listening');
    const udp = dgram.createSocket(host.includes(':') ? 'udp6' : 'udp4');
    udp.on('message', (b, r) => { const reply = record(b, r.address, 'udp'); if (reply) udp.send(reply, r.port, r.address); });
    udp.bind(38472, host); await once(udp, 'listening');
  }
  for (const host of ['1.1.1.1', '8.8.8.8', '192.168.1.1', 'fd00:1::1']) {
    const answer = (b, peer, transport) => {
      const q = parseDnsQuery(b); fs.appendFileSync('/run/e2e-dns-hits', JSON.stringify({ host, peer, transport, name: q.name, type: q.type }) + '\n');
      return tunnelDnsFixtureAnswer(b, ['192.168.1.1', 'fd00:1::1'].includes(host) ? 30 : 10);
    };
    const udp = dgram.createSocket(host.includes(':') ? 'udp6' : 'udp4'); udp.on('message', (b, r) => { try { udp.send(answer(b, r.address, 'udp'), r.port, r.address); } catch {} }); udp.bind(53, host); await once(udp, 'listening');
    const tcp = net.createServer(s => { let b = Buffer.alloc(0); s.on('error', () => {}); s.on('data', x => { b = Buffer.concat([b, x]); if (b.length < 2 || b.length < b.readUInt16BE(0) + 2) return;
      try { const r = answer(b.subarray(2, 2 + b.readUInt16BE(0)), s.remoteAddress, 'tcp'), prefix = Buffer.alloc(2); prefix.writeUInt16BE(r.length); s.end(Buffer.concat([prefix, r])); } catch { s.destroy(); }
    }); }); tcp.listen(53, host); await once(tcp, 'listening');
  }
  put('/run/e2e-origin-ready', 'yes');
  // Real late DHCP, released by the boot driver after it has verified rescue.
  if (phase()) await until(() => fs.existsSync('/run/e2e-release-dhcp'), 'release late DHCP');
  let address = '192.168.1.10';
  const startDhcp = () => {
    const child = spawn('/usr/sbin/dnsmasq', ['--keep-in-foreground', '--conf-file=/dev/null', '--port=0', '--interface=client0', '--bind-interfaces', '--user=root', '--group=root', '--dhcp-authoritative',
      `--dhcp-range=${address},${address},255.255.255.0,10m`, `--dhcp-host=02:00:00:00:01:02,${address}`,
      '--dhcp-option=3,192.168.1.1', '--dhcp-option=6,192.168.1.1', `--dhcp-leasefile=/run/e2e-${address}.leases`, '--pid-file=/run/e2e-dhcp.pid'], { stdio: 'inherit' });
    child.on('exit', code => { if (code) process.exit(code); }); return child;
  };
  let dhcp = startDhcp();
  if (fs.readFileSync('/proc/cmdline', 'utf8').includes('meshpn.usb-soak=1')) {
    for (;;) {
      await delay(300);
      if (!fs.existsSync('/run/e2e-dhcp-next')) continue;
      const next = fs.readFileSync('/run/e2e-dhcp-next', 'utf8');
      assert.match(next, /^192\.168\.1\.1[123]$/);
      if (next === address) continue;
      const ended = once(dhcp, 'close'); dhcp.kill('SIGTERM'); await ended;
      address = next; dhcp = startDhcp();
      await delay(300); assert.equal(dhcp.exitCode, null); put('/run/e2e-dhcp-ack', address);
    }
  }
}

async function exchangeV6Dns(server, query, tcp) {
  const socket = tcp ? new net.Socket() : dgram.createSocket('udp6');
  let timer;
  try {
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(Error('DNS6 deadline')), 3000);
      socket.on('error', reject);
      if (tcp) {
        let b = Buffer.alloc(0);
        socket.on('data', x => { b = Buffer.concat([b, x]); if (b.length > 65537) return reject(Error('DNS6 size'));
          if (b.length >= 2 && b.length === b.readUInt16BE(0) + 2) resolve(b.subarray(2)); });
        socket.on('end', () => reject(Error('DNS6 EOF')));
        socket.connect({ host: server, port: 53, localAddress: 'fd00:7::19', family: 6 }, () => {
          const h = Buffer.alloc(2); h.writeUInt16BE(query.length); socket.write(Buffer.concat([h, query]));
        });
      } else {
        socket.on('message', resolve);
        socket.bind(0, 'fd00:7::19', () => socket.connect(53, server, () => socket.send(query)));
      }
    });
  } finally { clearTimeout(timer); if (tcp) socket.destroy(); else { try { socket.close(); } catch {} } }
}
async function probe(options) {
  try {
    if (options.kind === 'raw') {
      const tcp = options.protocol === 'tcp', v6 = options.host.includes(':');
      const socket = tcp ? new net.Socket() : dgram.createSocket(v6 ? 'udp6' : 'udp4');
      let timer;
      try { return await new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(Error('raw deadline')), 3000);
        socket.on('error', reject);
        const answer = b => { try { const r = JSON.parse(b.toString()); assert.equal(r.token, options.token); resolve({ ok: true, peer: r.peer }); } catch (e) { reject(e); } };
        if (tcp) {
          let b = Buffer.alloc(0); socket.on('data', x => { b = Buffer.concat([b, x]); if (b.length > 1024) reject(Error('raw oversize')); });
          socket.on('end', () => answer(b));
          socket.connect({ host: options.host, port: 38471, localAddress: options.localAddress }, () => socket.end(options.token));
        } else {
          socket.on('message', answer);
          socket.bind(0, options.localAddress ?? (v6 ? '::' : '0.0.0.0'), () => socket.connect(38472, options.host, () => socket.send(options.token)));
        }
      }); } finally { clearTimeout(timer); if (tcp) socket.destroy(); else { try { socket.close(); } catch {} } }
    }
    if (options.kind === 'dns') {
      const q = makeDnsQuery(options.name, options.type), b = options.server.includes(':') ? await exchangeV6Dns(options.server, q, options.tcp)
        : await exchangePlainDns({ server: options.server, localAddress: '0.0.0.0', query: q, tcp: options.tcp, timeoutMs: 3000 });
      const r = validateDnsResponse(b, q), a = r.records.find(a => a.type === options.type);
      return { ok: r.rcode === 0 && !!a, rcode: r.rcode, answer: a ? b.subarray(a.offset, a.offset + a.length).toString('hex') : null };
    }
    return await new Promise((resolve, reject) => {
      const request = https.get({ host: options.host, localAddress: options.localAddress, port: 18443, servername: 'origin.test', ca: fs.readFileSync('/state/cert/fullchain.pem'), agent: false }, r => {
        let text = ''; r.on('data', x => { text += x; if (text.length > 1024) request.destroy(Error('oversize')); }); r.on('end', () => resolve({ ok: r.statusCode === 200, peer: text }));
      }); const timer = setTimeout(() => request.destroy(Error('deadline')), 4000); request.on('close', () => clearTimeout(timer)); request.on('error', reject);
    });
  } catch (e) { return { ok: false, error: e.code || e.message }; }
}
let sequence = 0;
let probeWorker, probeReplies;
const peerProbe = async options => {
  // Reuse only the probe interpreter, not sockets or DNS results. On TCG,
  // repeatedly importing the entire helper dwarfs the actual packet tests.
  if (!probeWorker) {
    probeWorker = spawn('/usr/bin/ip', ['netns', 'exec', 'peer', '/usr/bin/node', script, 'probe-worker'], { stdio: ['pipe', 'pipe', 'inherit'] });
    probeWorker.on('error', () => {}); probeWorker.stdin.on('error', () => {});
    probeReplies = createInterface({ input: probeWorker.stdout })[Symbol.asyncIterator]();
  }
  probeWorker.stdin.write(JSON.stringify(options) + '\n');
  let timer;
  try {
    const reply = await Promise.race([probeReplies.next(), new Promise((_, reject) => { timer = setTimeout(() => reject(Error('probe worker deadline')), 20000); })]);
    assert.ok(!reply.done && reply.value.length < 4096, 'probe worker closed or oversized reply');
    return JSON.parse(reply.value);
  } finally { clearTimeout(timer); }
};
const dnsProbe = (server, tcp, type) => ({ kind: 'dns', server, tcp, type, name: `usb-e2e-${phase()}-${++sequence}.test` });
const hits = path => fs.existsSync(path) ? fs.readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map(s => JSON.parse(s)) : [];
const login = async (port = '2222') => (await exec('ip', ['netns', 'exec', 'peer', '/usr/bin/ssh', '-F', '/dev/null', '-i', '/state/test-key', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/root/known_hosts', '-o', 'ConnectTimeout=5', '-p', port, 'root@192.168.7.1', 'printf usb-e2e-login-ok'], { timeout: 20000 })).stdout === 'usb-e2e-login-ok';

async function run() {
  const faults = fs.readFileSync('/proc/cmdline', 'utf8').includes('meshpn.usb-faults=1');
  const p = phase(), bootId = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
  const check = (name, actual, expected = true) => { assert.deepEqual(actual, expected, name); event({ event: 'check', phase: p, name }); };
  const nat = () => sync('iptables', ['-w', '5', '-t', 'nat', '-S', 'POSTROUTING']);
  const link = () => JSON.parse(ip('-j', 'addr', 'show', 'wlan0'))[0];
  const privateDns = async (label, blocked, intercept = false) => {
    for (const server of ['192.168.1.1', 'fd00:1::1']) for (const tcp of [false, true]) for (const type of [1, 28]) {
      const q = dnsProbe(server, tcp, type), r = await peerProbe(q), seen = hits('/run/e2e-dns-hits').filter(h => h.name === q.name);
      const tunneled = intercept && !server.includes(':');
      check(`${label} private DNS ${server}/${tcp}/${type}`, r.ok, !blocked || tunneled);
      if (tunneled) check(`${label} private DNS tunnel source ${server}/${tcp}/${type}`, seen.length > 0 && seen.every(h => h.peer === exitIp && ['1.1.1.1', '8.8.8.8'].includes(h.host)));
      else if (blocked) check(`${label} private DNS no upstream ${server}/${tcp}/${type}`, seen.length, 0);
      else check(`${label} private DNS direct source ${server}/${tcp}/${type}`, seen[0]?.peer, server.includes(':') ? 'fd00:7::19' : '192.168.1.10');
    }
  };
  const rawTraffic = async (label, protectedState = null) => {
    for (const host of ['1.0.0.1', '192.168.1.1', '2606:4700:4700::1111', 'fd00:1::1']) for (const protocol of ['tcp', 'udp']) {
      const q = { kind: 'raw', host, protocol, token: `raw-${p}-${++sequence}`, ...(host === 'fd00:1::1' ? { localAddress: 'fd00:7::19' } : {}) };
      const r = await peerProbe(q), seen = hits('/run/e2e-raw-hits').filter(h => h.token === q.token);
      const allowed = protectedState === null || protectedState && host === '1.0.0.1';
      check(`${label} raw ${host}/${protocol}`, r.ok, allowed);
      const source = protectedState ? exitIp : host === 'fd00:1::1' ? 'fd00:7::19' : host.includes(':') ? '2001:db8:7::19' : '192.168.1.10';
      check(`${label} raw source-or-no-hit ${host}/${protocol}`, allowed ? seen.length > 0 && seen.every(h => h.peer === source) : seen.length === 0);
    }
  };
  const install = async () => exec('/bin/bash', ['scripts/autostart/install.sh', '--role=client', '--type=tls', `--server=${exitIp}:443`,
    ...(fs.readFileSync('/proc/cmdline', 'utf8').includes('meshpn.usb-pmtu=1') ? ['--keep-alive=5'] : []),
    '--split-default', '--ipv6=auto', '--tls-cert-dir=/state/cert', '--shared-hmac-key=/state/cert/secret.key',
    '--tls-server-name=vpn.test', '--tls-public-name=vpn.test'], { env: { ...process.env, NODE_BIN: '/usr/bin/node',
      SERVICE_NAME: 'clean-vpn', KILLSWITCH: '1', KILLSWITCH_PERSIST: '1', NETWORKD_GUARD: '1', USB_GATEWAY: '1' } });
  const baseline = async label => {
    check(label + ' direct IPv4 positive control', (await peerProbe({ host: '1.0.0.1' })).peer, '192.168.1.10');
    const ipv6 = await peerProbe({ host: '2606:4700:4700::1111' });
    check(label + ' direct IPv6 positive control', ipv6, { ok: true, peer: '2001:db8:7::19' });
    for (const tcp of [false, true]) for (const type of [1, 28]) {
      const q = dnsProbe('1.1.1.1', tcp, type), r = await peerProbe(q);
      check(`${label} public DNS ${tcp ? 'TCP' : 'UDP'}/${type} positive control`, r.ok);
      check(`${label} direct DNS source ${tcp}/${type}`, hits('/run/e2e-dns-hits').find(h => h.name === q.name)?.peer, '192.168.1.10');
    }
    await privateDns(label, false);
    await rawTraffic(label);
  };
  const ready = async (timeoutMs = 180000) => {
    await until(async () => {
      if (faults && fs.existsSync('/run/host-boot-client.log')) {
        assert.ok(!fs.readFileSync('/run/host-boot-client.log', 'utf8').includes('Host IPv4 recovery required'), 'VPN refuses stale IPv4 journal: Host IPv4 recovery required');
      }
      return await property(gatewayUnit, 'ActiveState') === 'active' && (await peerProbe({ host: '1.0.0.1' })).peer === exitIp;
    }, 'real VPN/USB not ready', timeoutMs);
    check('real TUN device', JSON.parse(ip('-j', '-d', 'link', 'show', 'tun0'))[0].linkinfo.info_kind, 'tun');
    check('single SNAT rule', nat().split('\n').filter(l => l === usbSnatLine).length, 1);
    const guard = sync('/usr/local/bin/clean-vpn-killswitch.sh', ['status']);
    check('both guard families audited', [4, 6].every(f => guard.includes(`IPv${f}: cvks4:both:block:tun0:${exitIp}:22`)));
  };
  await until(() => fs.existsSync('/run/e2e-origin-ready'), 'origins not ready');
  check('systemd PID1', fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  await until(async () => await property('sys-subsystem-net-devices-usb0.device', 'ActiveState') === 'active', 'USB udev device');
  if (faults) {
    await until(() => link().addr_info.some(a => a.local === '192.168.1.10' && a.dynamic), 'DHCP baseline');
    await baseline('pre-install');
    await install(); await ready();
    check('fresh v4 installer rescue authenticated', await login());
  } else if (!p) {
    await until(() => link().addr_info.some(a => a.local === '192.168.1.10' && a.dynamic), 'DHCP baseline');
    await baseline('pre-install');
    const manager = await property('systemd-networkd.service', 'MainPID');
    // Install the exact previously deployed guard/helper to reproduce the old
    // hole, then restore current repository sources before invoking the upgrade.
    const saved = ['/project/scripts/autostart/killswitch.sh', '/project/scripts/clean-vpn-usb-snat.mjs', '/project/scripts/autostart/install.sh'].map(path => [path, fs.readFileSync(path)]);
    try {
      put(saved[0][0], fs.readFileSync('/legacy/guard'), 0o755); put(saved[1][0], fs.readFileSync('/legacy/snat'));
      put(saved[2][0], fs.readFileSync('/legacy/installer'), 0o755);
      await install();
    } finally { for (const [path, bytes] of saved) put(path, bytes, path.endsWith('.sh') ? 0o755 : 0o644); }
    check('legacy actual installer preserves networkd PID', await property('systemd-networkd.service', 'MainPID'), manager);
    await until(async () => await property(gatewayUnit, 'ActiveState') === 'active' && (await peerProbe({ host: '1.0.0.1' })).peer === exitIp, 'legacy VPN ready');
    check('legacy guard v2 active', [4, 6].every(f => sync('/usr/local/bin/clean-vpn-killswitch.sh', ['status']).includes(`IPv${f}: cvks2:both:block:tun0:${exitIp}:22`)));
    check('legacy rescue authenticated', await login());
    await privateDns('legacy', false);
    const beforeUpgradePid = await property('clean-vpn.service', 'MainPID');
    const planned = JSON.parse((await exec('/usr/bin/node', ['scripts/clean-vpn-usb-dns-upgrade.mjs'])).stdout);
    check('DNS upgrade readonly plan', planned.status, 'planned');
    check('DNS upgrade plan preserves VPN PID', await property('clean-vpn.service', 'MainPID'), beforeUpgradePid);
    const upgraded = JSON.parse((await exec('/bin/bash', ['scripts/autostart/install.sh', '--upgrade-usb-dns'])).stdout);
    check('actual installer upgrades DNS guard', upgraded.status, 'upgraded-stopped');
    check('DNS upgrade leaves VPN stopped', await property('clean-vpn.service', 'ActiveState'), 'inactive');
    check('DNS upgrade leaves guard active', await property('clean-vpn-killswitch.service', 'ActiveState'), 'active');
    check('DNS upgrade preserves networkd PID', await property('systemd-networkd.service', 'MainPID'), manager);
    check('DNS upgrade retains authenticated rescue', await login());
    await privateDns('upgraded-stopped', true);
    await ctl('start', '--no-block', 'clean-vpn.service', gatewayUnit);
    await ready();
    const repeatedPid = await property('clean-vpn.service', 'MainPID');
    check('DNS upgrade idempotent', JSON.parse((await exec('/bin/bash', ['scripts/autostart/install.sh', '--upgrade-usb-dns'])).stdout).status, 'already-protected');
    check('repeated DNS upgrade preserves VPN PID', await property('clean-vpn.service', 'MainPID'), repeatedPid);
    const vpnPid = await property('clean-vpn.service', 'MainPID'), rescueStart = await property('clean-vpn-usb-rescue.socket', 'ActiveEnterTimestampMonotonic');
    await exec('/usr/bin/node', ['scripts/clean-vpn-usb-gateway.mjs', '--remove', '--apply']);
    check('gateway removal leaves actual VPN running', await property('clean-vpn.service', 'MainPID'), vpnPid);
    check('gateway removal leaves rescue authenticated', await login());
    check('without SNAT peer fails with actual VPN', (await peerProbe({ host: '1.0.0.1' })).ok, false);
    for (let i = 0; i < 2; i++) await exec('/bin/bash', ['scripts/autostart/install.sh', '--usb-gateway'], { env: { ...process.env, NODE_BIN: '/usr/bin/node' } });
    await ready();
    check('additive actual installer keeps VPN PID', await property('clean-vpn.service', 'MainPID'), vpnPid);
    check('additive installer keeps rescue socket', await property('clean-vpn-usb-rescue.socket', 'ActiveEnterTimestampMonotonic'), rescueStart);
  } else {
    check('different kernel boot ID', fs.readFileSync('/state/previous-boot', 'utf8') !== bootId);
    const manifest = JSON.parse(fs.readFileSync('/state/installed.json', 'utf8'));
    check('installed bytes restored from persistent disk', snapshotFiles.every(path => hash(fs.readFileSync(path)) === manifest.files[path]));
    await until(async () => await property('clean-vpn-usb-rescue.socket', 'ActiveState') === 'active', 'rescue at late DHCP');
    check('rescue login before DHCP/VPN', await login());
    check('DHCP is still absent', !link().addr_info.some(a => a.family === 'inet'));
    check('no premature SNAT', !nat().includes(usbSnatLine));
    put('/run/e2e-release-dhcp', 'yes');
    await ready();
    check('SNAT enabled across boot', (await ctl('is-enabled', gatewayUnit)).stdout.trim(), 'enabled');
    check('guard precedes networkd', BigInt(await property('clean-vpn-killswitch.service', 'ExecMainExitTimestampMonotonic')) <= BigInt(await property('systemd-networkd.service', 'ExecMainStartTimestampMonotonic')));
    check('rescue login after delayed real VPN', await login());
  }
  event({ event: 'lifecycle-ready', phase: p });
  await ctl('start', 'usb-e2e-dns-relay.service');
  await ctl('start', 'usb-e2e-ssh.service');
  const matrix = async active => {
    const label = active ? 'active' : 'stopped';
    check(`${label} forwarded HTTPS IPv4`, (await peerProbe({ host: '1.0.0.1' })).peer ?? 'BLOCKED', active ? exitIp : 'BLOCKED');
    const before6 = hits('/run/e2e-http-hits').filter(h => h.host.includes(':')).length;
    check(`${label} forwarded IPv6 blocked`, (await peerProbe({ host: '2606:4700:4700::1111' })).ok, false);
    check(`${label} no IPv6 origin hit`, hits('/run/e2e-http-hits').filter(h => h.host.includes(':')).length, before6);
    for (const server of ['1.1.1.1', '192.168.7.1']) for (const tcp of [false, true]) for (const type of [1, 28]) {
      const q = dnsProbe(server, tcp, type), r = await peerProbe(q), seen = hits('/run/e2e-dns-hits').filter(h => h.name === q.name);
      check(`${label} DNS ${server}/${tcp ? 'TCP' : 'UDP'}/${type}`, r.ok, active);
      if (active) {
        check(`${label} DNS answer ${server}/${tcp}/${type}`, r.answer, type === 1 ? 'c000020a' : ['2001', '0db8', '0000', '0000', '0000', '0000', '0000', '000a'].join(''));
        check(`${label} DNS only exit source ${server}/${tcp}/${type}`, seen.length > 0 && seen.every(h => h.peer === exitIp));
      } else check(`${label} DNS no upstream query ${server}/${tcp}/${type}`, seen.length, 0);
    }
    await privateDns(label, true, active);
    check(`${label} non-DNS LAN IPv4 blocked`, (await peerProbe({ host: '192.168.1.1' })).ok, false);
    check(`${label} non-DNS LAN IPv6 blocked`, (await peerProbe({ host: 'fd00:1::1', localAddress: 'fd00:7::19' })).ok, false);
    await rawTraffic(label, active);
    check(`${label} normal SSH authenticated`, await login('22'));
    check(`${label} rescue SSH authenticated`, await login());
  };
  if (faults) {
    await matrix(true);
    const soak = fs.readFileSync('/proc/cmdline', 'utf8').includes('meshpn.usb-soak=1');
    const pmtu = fs.readFileSync('/proc/cmdline', 'utf8').includes('meshpn.usb-pmtu=1');
    await (pmtu ? runUsbPmtu : soak ? runUsbSoak : runUsbFaultScenarios)({ check, event, ctl, property, sync, ip, at, link, until, ready, matrix, login, hits, peerProbe, dnsProbe });
    sync('/bin/sync'); event({ event: 'completed', phase: p, bootId, usbDnsPolicy: 'cvks4-usb-tunnel-only', faultScenarios: true, ...(soak ? { soak: true } : {}), ...(pmtu ? { pmtu: true } : {}) });
    await ctl('poweroff', '--no-block'); return;
  }
  await matrix(true);
  await ctl('stop', 'clean-vpn.service');
  check('VPN really stopped', await property('clean-vpn.service', 'ActiveState'), 'inactive');
  check('TUN removed', !JSON.parse(ip('-j', 'link', 'show')).some(i => i.ifname === 'tun0'));
  check('guard retained on VPN stop', await property('clean-vpn-killswitch.service', 'ActiveState'), 'active');
  await matrix(false);
  await ctl('start', 'clean-vpn.service'); await ready(); await matrix(true);
  check('restart restored actual exit egress', (await peerProbe({ host: '1.0.0.1' })).peer, exitIp);
  if (!p) {
    const manifest = { files: {}, links: {} };
    for (const path of snapshotFiles) { const b = fs.readFileSync(path); manifest.files[path] = hash(b); put('/state/installed' + path, b); }
    for (const name of links) manifest.links[name] = fs.readlinkSync('/etc/systemd/system/' + name);
    put('/state/installed.json', JSON.stringify(manifest)); put('/state/previous-boot', bootId); put('/state/phase', '1');
  } else {
    const removed = JSON.parse((await exec('/usr/bin/node', ['scripts/clean-vpn-uninstall.mjs'])).stdout);
    check('full actual uninstall succeeds', removed.status, 'uninstalled');
    check('uninstall removes main/guard/SNAT files', [...BOOT_FILES.map(p => '/' + p), ...Object.keys(gatewayFiles('/usr/bin/node'))].every(p => !fs.existsSync(p)));
    check('uninstall removes only owned SNAT', !nat().includes(usbSnatLine) && nat().includes('-o wlan0 -j MASQUERADE'));
    check('uninstall retains rescue files and login', Object.keys(rescueFiles).every(p => fs.existsSync(p)) && await login());
    await baseline('post-uninstall');
    await install(); await ready();
    check('fresh v4 installer rescue authenticated', await login());
    await matrix(true);
    check('fresh v4 uninstall succeeds', JSON.parse((await exec('/usr/bin/node', ['scripts/clean-vpn-uninstall.mjs'])).stdout).status, 'uninstalled');
    check('fresh v4 uninstall preserves rescue', await login());
  }
  sync('/bin/sync'); event({ event: 'completed', phase: p, bootId, usbDnsPolicy: 'cvks4-usb-tunnel-only' });
  await ctl(p ? 'poweroff' : 'reboot', '--no-block');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2]; assertUsbE2eVm(mode);
  try { if (mode === 'prepare') prepare(); else if (mode === 'fixture') await fixture();
    else if (mode === 'probe') console.log(JSON.stringify(await probe(JSON.parse(process.argv[3]))));
    else if (mode === 'long-tcp') await runLongTcpPeer();
    else if (mode === 'fault-monitor') {
      let round = 0;
      while (!fs.existsSync('/run/e2e-monitor-stop')) {
        const prefix = `fault-monitor-${++round}`;
        const tasks = [
          { host: '1.0.0.1', kind: 'https' },
          { kind: 'raw', host: '1.0.0.1', protocol: 'tcp', token: prefix + '-tcp' },
          { kind: 'raw', host: '1.0.0.1', protocol: 'udp', token: prefix + '-udp' },
          { kind: 'dns', server: '1.1.1.1', tcp: false, type: 1, name: prefix + '-udp.test' },
          { kind: 'dns', server: '192.168.1.1', tcp: true, type: 28, name: prefix + '-tcp.test' },
        ];
        await Promise.all(tasks.map(async q => {
          const r = await probe(q);
          fs.appendFileSync('/run/e2e-monitor-results', JSON.stringify({ round, kind: q.kind, ok: r.ok, peer: r.peer }) + '\n');
        }));
        await delay(200);
      }
    } else if (mode === 'probe-worker') {
      for await (const line of createInterface({ input: process.stdin })) {
        assert.ok(line.length < 4096); console.log(JSON.stringify(await probe(JSON.parse(line))));
      }
    } else await run(); }
  catch (e) {
    if (mode === 'run') {
      for (const args of [['-4', 'addr'], ['-4', 'route', 'show', 'table', 'all'], ['-4', 'route', 'get', exitIp], ['-6', 'addr'], ['-6', 'route']]) console.error(ip(...args));
      console.error(sync('sysctl', ['net.ipv6.conf.all.forwarding', 'net.ipv6.conf.wlan0.forwarding', 'net.ipv6.conf.usb0.forwarding']));
      console.error(ip('-6', 'neigh')); console.error(sync('ip6tables', ['-S']));
      for (const ns of ['router', 'peer']) for (const args of [['addr'], ['route'], ['neigh']]) console.error(ns, at(ns, 'ip', '-6', ...args));
      try { console.error((await ctl('status', 'clean-vpn.service', gatewayUnit)).stdout); } catch {}
      try { console.error((await exec('journalctl', ['-b', '-u', 'clean-vpn.service', '-u', gatewayUnit, '-u', 'systemd-networkd.service', '--no-pager', '-n', '100'])).stdout); } catch {}
      for (const path of ['/run/host-boot-client.log', '/run/host-boot-networkd.log', '/run/usb-e2e-exit.log', '/run/usb-e2e-fixture.log', '/run/usb-e2e-relay.log']) if (fs.existsSync(path)) console.error(path, fs.readFileSync(path, 'utf8').slice(-16000));
    }
    console.error(e.stack); event({ event: 'failed', phase: phase(), message: e.message }); process.exitCode = 1;
  } finally { probeWorker?.kill('SIGTERM'); }
}
