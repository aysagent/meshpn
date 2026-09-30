/** Destructive fixture, exclusively inside a NIC-less, explicitly marked QEMU VM. */
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync, chmodSync, unlinkSync, cpSync } from 'node:fs';
import { execFileSync, execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { once } from 'node:events';
import https from 'node:https';
import dgram from 'node:dgram';
import { fileURLToPath } from 'node:url';
import { tunnelDnsFixtureAnswer } from './dns-tunnel-cli-lab.mjs';

export const BOOT_FILES = ['etc/systemd/system/clean-vpn.service', 'etc/systemd/system/clean-vpn-killswitch.service',
  'usr/local/bin/clean-vpn-run.sh', 'usr/local/bin/clean-vpn-killswitch.sh',
  'etc/systemd/system/systemd-networkd.service.d/90-clean-vpn-clean-vpn.conf',
  'etc/systemd/system/systemd-networkd.socket.d/90-clean-vpn-clean-vpn.conf'];
export function hostBootVmUnits() {
  return {
    'default.target': '[Unit]\nDefaultDependencies=no\nWants=host-boot-driver.service host-boot-fixture.service host-boot-exit.service systemd-networkd.service systemd-udev-trigger.service\n',
    ...Object.fromEntries(['network.target', 'network-pre.target', 'multi-user.target', 'sysinit.target', 'basic.target', 'sockets.target'].map(n => [n, '[Unit]\nDefaultDependencies=no\n'])),
    'dbus.socket': '[Unit]\nDefaultDependencies=no\n[Socket]\nListenStream=/run/dbus/system_bus_socket\nSocketMode=0666\n',
    'dbus.service': '[Unit]\nDefaultDependencies=no\nRequires=dbus.socket\nAfter=dbus.socket\n[Service]\nType=notify\nExecStart=/usr/bin/dbus-daemon --nofork --nopidfile --systemd-activation --config-file=/etc/dbus-vm.conf\n',
    'host-boot-fixture.service': '[Unit]\nDefaultDependencies=no\nBefore=host-boot-driver.service\n[Service]\nType=simple\nNetworkNamespacePath=/run/netns/router\nWorkingDirectory=/project\nExecStart=/usr/bin/node /project/scripts/lib/vpn-host-boot-vm.mjs fixture\nStandardOutput=append:/run/host-boot-fixture.log\nStandardError=append:/run/host-boot-fixture.log\n',
    'host-boot-exit.service': '[Unit]\nDefaultDependencies=no\nBefore=host-boot-driver.service\n[Service]\nType=simple\nNetworkNamespacePath=/run/netns/exit\nWorkingDirectory=/project\nEnvironment=PATH=/usr/bin:/usr/sbin:/bin:/sbin OPENSSL_CONF=/dev/null\nExecStart=/usr/bin/node /project/scripts/clean-vpn.js --role=exit --type=tls --server=0.0.0.0:443 --ext=eth0 --ipv6=auto --tls-cert-dir=/state/cert --shared-hmac-key=/state/cert/secret.key --tls-server-name=vpn.test --tls-public-name=vpn.test\nStandardOutput=append:/run/host-boot-exit.log\nStandardError=append:/run/host-boot-exit.log\nTimeoutStopSec=150\nKillMode=mixed\n',
    'host-boot-driver.service': '[Unit]\nDefaultDependencies=no\nWants=dbus.service\nAfter=dbus.service host-boot-fixture.service host-boot-exit.service systemd-networkd.service\n[Service]\nType=oneshot\nWorkingDirectory=/project\nEnvironment=PATH=/usr/bin:/usr/sbin:/bin:/sbin OPENSSL_CONF=/dev/null\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTimeoutStartSec=20min\nSuccessExitStatus=SIGTERM\nExecStart=/usr/bin/node /project/scripts/lib/vpn-host-boot-vm.mjs run\n',
  };
}
export function assertHostBootVm(mode) {
  assert.ok(['prepare', 'fixture', 'run'].includes(mode));
  assert.match(readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.host-cold-boot=1(?:\s|$)/);
  assert.match(readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8'), /^QEMU\s*$/);
  assert.equal(process.getuid(), 0);
  if (mode !== 'prepare') assert.equal(readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
}
const sync = (file, args) => execFileSync(file, args, { encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024 }).trim();
const exec = (file, args) => promisify(execFile)(file, args, { encoding: 'utf8', timeout: 450000, maxBuffer: 1024 * 1024 });
const ip = (...a) => sync('/usr/bin/ip', a);
const at = (ns, ...a) => ip('netns', 'exec', ns, ...a);
const ctl = (...a) => exec('/usr/bin/systemctl', ['--no-pager', ...a]);
const property = async (unit, key) => (await ctl('show', unit, `--property=${key}`, '--value')).stdout.trim();
const put = (p, content, mode = 0o644) => { mkdirSync(p.slice(0, p.lastIndexOf('/')), { recursive: true }); writeFileSync(p, content, { mode }); chmodSync(p, mode); };
const phase = () => existsSync('/state/phase') ? Number(readFileSync('/state/phase', 'utf8')) : 0;
const log = () => existsSync('/run/host-boot-client.log') ? readFileSync('/run/host-boot-client.log', 'utf8') : '';
const event = data => console.log('HOST_BOOT_EVENT ' + JSON.stringify(data));
const until = async (fn, detail, ms = 240000) => { const end = Date.now() + ms; while (!await fn()) { assert.ok(Date.now() < end, `${detail}\n${log()}`); await delay(300); } };

function prepare() {
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(x => x.ifname), ['lo']);
  assert.match(readFileSync('/proc/mounts', 'utf8'), /^\/dev\/vda \/state ext4 /m);
  const p = phase(); assert.ok([0, 1, 2].includes(p));
  ip('link', 'set', 'lo', 'up'); ip('netns', 'add', 'router'); ip('netns', 'add', 'exit');
  ip('link', 'add', 'eth0', 'address', '02:00:00:00:01:02', 'type', 'veth', 'peer', 'name', 'client0', 'netns', 'router');
  at('router', 'ip', 'link', 'add', 'exit0', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'exit');
  for (const ns of ['router', 'exit']) at(ns, 'ip', 'link', 'set', 'lo', 'up');
  for (const [ns, dev, v4, v6] of [['router', 'client0', '192.0.2.1', '2001:db8:1::1'], ['router', 'exit0', '198.51.100.1', '2001:db8:2::1'], ['exit', 'eth0', '198.51.100.2', '2001:db8:2::2']]) {
    at(ns, 'ip', 'addr', 'add', v4 + '/24', 'dev', dev); at(ns, 'ip', '-6', 'addr', 'add', v6 + '/64', 'dev', dev, 'nodad'); at(ns, 'ip', 'link', 'set', dev, 'up');
  }
  at('router', 'sysctl', '-w', 'net.ipv4.ip_forward=1'); at('exit', 'sysctl', '-w', 'net.ipv6.conf.all.forwarding=1');
  at('exit', 'ip', 'route', 'add', 'default', 'via', '198.51.100.1'); at('exit', 'ip', '-6', 'route', 'add', 'default', 'via', '2001:db8:2::1');
  for (const addr of ['1.0.0.1', '1.1.1.1', '8.8.8.8']) at('router', 'ip', 'addr', 'add', addr + '/32', 'dev', 'lo');
  at('router', 'ip', '-6', 'addr', 'add', '2606:4700:4700::1111/128', 'dev', 'lo', 'nodad');
  if (!p) {
    mkdirSync('/state/cert', { recursive: true, mode: 0o700 });
    sync('/usr/bin/openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-x509', '-days', '2', '-subj', '/CN=vpn.test', '-addext', 'subjectAltName=DNS:vpn.test,DNS:origin.test', '-keyout', '/state/cert/privkey.pem', '-out', '/state/cert/fullchain.pem']);
    sync('/usr/bin/openssl', ['rand', '-out', '/state/cert/secret.key', '32']);
  } else {
    for (const name of BOOT_FILES) { const dst = '/' + name; mkdirSync(dst.slice(0, dst.lastIndexOf('/')), { recursive: true }); copyFileSync('/state/installed/' + name, dst); chmodSync(dst, name.endsWith('.sh') ? 0o755 : 0o644); }
    put('/etc/systemd/system/default.target.d/vpn.conf', '[Unit]\nWants=clean-vpn.service\n');
    if (p === 2) put('/etc/systemd/system/clean-vpn-killswitch.service.d/fault.conf', '[Service]\nExecStartPre=/bin/false\n');
  }
  put('/etc/systemd/system/clean-vpn.service.d/log.conf', '[Service]\nStandardOutput=append:/run/host-boot-client.log\nStandardError=append:/run/host-boot-client.log\n');
  put('/etc/systemd/system/clean-vpn-killswitch.service.d/log.conf', '[Service]\nStandardOutput=append:/run/host-boot-client.log\nStandardError=append:/run/host-boot-client.log\n');
  put('/etc/systemd/system/systemd-networkd.service.d/boot.conf', '[Unit]\nRequires=dbus.service systemd-udev-trigger.service\nAfter=dbus.service systemd-udev-trigger.service\n[Service]\nStandardOutput=append:/run/host-boot-networkd.log\nStandardError=append:/run/host-boot-networkd.log\n');
  put('/etc/systemd/network/10-boot.network', '[Match]\nName=eth0\n[Network]\nDHCP=ipv4\nIPv6AcceptRA=no\nLinkLocalAddressing=no\nAddress=2001:db8:1::2/64\nGateway=2001:db8:1::1\n[DHCPv4]\nUseDNS=no\nClientIdentifier=mac\n');
  put('/etc/udev/rules.d/99-boot-net.rules', 'SUBSYSTEM=="net", ACTION=="add", TAG+="systemd"\n');
  // No container marker: networkd must receive real udev initialization.
  assert.equal(existsSync('/run/systemd/container'), false);
  event({ event: 'prepared', phase: p, linkInitiallyDown: !JSON.parse(ip('-j', 'link', 'show', 'eth0'))[0].flags.includes('UP') });
}

async function fixture() {
  const servers = [];
  for (const host of ['1.0.0.1', '2606:4700:4700::1111']) {
    const s = https.createServer({ key: readFileSync('/state/cert/privkey.pem'), cert: readFileSync('/state/cert/fullchain.pem') }, (q, r) => r.end(q.socket.remoteAddress));
    s.listen(18443, host); await once(s, 'listening'); servers.push(s);
  }
  for (const host of ['1.1.1.1', '8.8.8.8']) {
    const s = dgram.createSocket('udp4'); s.on('message', (b, peer) => { put('/run/host-boot-dns-peer', peer.address); s.send(tunnelDnsFixtureAnswer(b, 10), peer.port, peer.address); }); s.bind(53, host); await once(s, 'listening'); servers.push(s);
  }
  if (phase() === 1) await until(() => (log().match(/Не найден default route/g) ?? []).length >= 2, 'DHCP withheld until two client retries', 180000);
  const p = spawn('/usr/sbin/dnsmasq', ['--keep-in-foreground', '--conf-file=/dev/null', '--port=0', '--interface=client0', '--bind-interfaces', '--user=root', '--group=root', '--dhcp-range=192.0.2.2,192.0.2.2,255.255.255.0,10m', '--dhcp-option=3,192.0.2.1', '--dhcp-option=6,1.1.1.1', '--dhcp-leasefile=/run/boot.leases', '--pid-file=/run/boot-dhcp.pid', '--log-dhcp'], { stdio: 'inherit' });
  p.on('exit', code => { if (code) process.exit(code); });
  put('/run/host-boot-fixture-ready', 'yes');
}
async function query(host) {
  try {
    return await new Promise((resolve, reject) => {
      const req = https.get({ host, port: 18443, servername: 'origin.test', ca: readFileSync('/state/cert/fullchain.pem'), agent: false }, r => { let b = ''; r.on('data', x => b += x); r.on('end', () => resolve(b)); });
      const timer = setTimeout(() => req.destroy(new Error('deadline')), 5000); req.on('close', () => clearTimeout(timer)); req.on('error', reject);
    });
  } catch { return 'BLOCKED'; }
}
async function dns() {
  const { exchangePlainDns } = await import('./dns-tunnel-forwarder.mjs');
  const { makeDnsQuery, parseDns } = await import('./lab-dns-wire.mjs');
  try { const b = await exchangePlainDns({ server: '1.1.1.1', localAddress: '0.0.0.0', query: makeDnsQuery('boot.test'), timeoutMs: 5000 }); const r = parseDns(b).records.find(r => r.type === 1); return r ? [...b.subarray(r.offset, r.offset + 4)].join('.') : 'NOANSWER'; }
  catch { return 'BLOCKED'; }
}
async function run() {
  const p = phase(), bootId = readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(), checks = [];
  const check = (name, actual, expected) => { assert.deepEqual(actual, expected, name); checks.push(name); event({ event: 'check', phase: p, name }); };
  const link = () => JSON.parse(ip('-j', 'addr', 'show', 'eth0'))[0];
  const ready = async (offset = 0) => { await until(() => log().slice(offset).includes('IPv6 client: tunnel'), 'VPN not ready'); };
  check('systemd PID1', readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  check('udev active', await property('systemd-udevd.service', 'ActiveState'), 'active');
  check('networkd socket gated', await property('systemd-networkd.socket', 'ActiveState'), p === 2 ? 'inactive' : 'active');
  check('no container marker', existsSync('/run/systemd/container'), false);
  if (!p) {
    await until(() => link().addr_info.some(a => a.local === '192.0.2.2'), 'initial DHCP lease');
    check('direct baseline IPv4', await query('1.0.0.1'), '192.0.2.2');
    const args = ['scripts/autostart/install.sh', '--role=client', '--type=tls', '--server=198.51.100.2:443', '--split-default', '--ipv6=auto', '--tls-cert-dir=/state/cert', '--shared-hmac-key=/state/cert/secret.key', '--tls-server-name=vpn.test', '--tls-public-name=vpn.test'];
    await promisify(execFile)('/bin/bash', args, { env: { ...process.env, NODE_BIN: '/usr/bin/node', KILLSWITCH: '1', KILLSWITCH_PERSIST: '1', NETWORKD_GUARD: '1' }, timeout: 450000 });
  } else if (p === 2) {
    check('failed guard', await property('clean-vpn-killswitch.service', 'ActiveState'), 'failed');
    check('failed guard prevents networkd', await property('systemd-networkd.service', 'MainPID'), '0');
    check('failed guard prevents VPN', await property('clean-vpn.service', 'MainPID'), '0');
    check('failed guard link down', link().flags.includes('UP'), false);
    check('failed guard no addresses', link().addr_info.length, 0);
    for (const [name, fn] of [['IPv4', () => query('1.0.0.1')], ['IPv6', () => query('2606:4700:4700::1111')], ['DNS', dns]]) check('failed guard blocks ' + name, await fn(), 'BLOCKED');
    unlinkSync('/etc/systemd/system/clean-vpn-killswitch.service.d/fault.conf'); await ctl('daemon-reload'); await ctl('reset-failed', 'clean-vpn.service', 'clean-vpn-killswitch.service', 'systemd-networkd.service');
    await ctl('start', 'systemd-networkd.service', 'clean-vpn.service');
  }
  await ready();
  check('client active', await property('clean-vpn.service', 'ActiveState'), 'active');
  check('DHCP IPv4 address', link().addr_info.some(a => a.local === '192.0.2.2' && a.dynamic), true);
  check('DHCP lease recorded', readFileSync('/run/boot.leases', 'utf8').includes('02:00:00:00:01:02 192.0.2.2 '), true);
  check('IPv4 through exit', await query('1.0.0.1'), '198.51.100.2');
  check('IPv6 through exit', await query('2606:4700:4700::1111'), '2001:db8:2::2');
  check('DNS through exit', await dns(), '192.0.2.10'); check('DNS peer exit', readFileSync('/run/host-boot-dns-peer', 'utf8'), '198.51.100.2');
  if (p) {
    check('guard precedes networkd', BigInt(await property('clean-vpn-killswitch.service', 'ExecMainExitTimestampMonotonic')) <= BigInt(await property('systemd-networkd.service', 'ExecMainStartTimestampMonotonic')), true);
    check('boot differs', readFileSync('/state/previous-boot', 'utf8') !== bootId, true);
    if (p === 1) check('late DHCP retried', Number(await property('clean-vpn.service', 'NRestarts')) >= 2, true);
  }
  await ctl('stop', 'clean-vpn.service');
  check('client stopped', await property('clean-vpn.service', 'ActiveState'), 'inactive');
  for (const [name, fn] of [['IPv4', () => query('1.0.0.1')], ['IPv6', () => query('2606:4700:4700::1111')], ['DNS', dns]]) check('stopped VPN blocks ' + name, await fn(), 'BLOCKED');
  if (p === 2) {
    await ctl('stop', 'clean-vpn-killswitch.service');
    check('manual guard stop inactive', await property('clean-vpn-killswitch.service', 'ActiveState'), 'inactive');
    check('manual guard stop stops networkd', await property('systemd-networkd.service', 'ActiveState'), 'inactive');
    check('manual guard stop stops socket', await property('systemd-networkd.socket', 'ActiveState'), 'inactive');
    const status = sync('/usr/local/bin/clean-vpn-killswitch.sh', ['status']);
    check('manual guard stop retains rules', [4, 6].every(f => status.includes(`IPv${f}: cvks2:both:block:tun0:198.51.100.2:22`)), true);
    for (const [name, fn] of [['IPv4', () => query('1.0.0.1')], ['IPv6', () => query('2606:4700:4700::1111')], ['DNS', dns]]) check('manual guard stop blocks ' + name, await fn(), 'BLOCKED');
    check('manual guard stop not reactivated', await property('clean-vpn-killswitch.service', 'ActiveState'), 'inactive');
    await ctl('start', 'systemd-networkd.service');
    cpSync('/project', '/state/next-release', { recursive: true, errorOnExist: true, force: false });
    const gatePaths = BOOT_FILES.filter(n => n.endsWith('.conf')).map(n => '/' + n), gateBefore = gatePaths.map(n => readFileSync(n, 'utf8'));
    const updated = JSON.parse((await exec('/usr/bin/node', ['scripts/clean-vpn-update.mjs', '--release=/state/next-release'])).stdout);
    check('update leaves client stopped', updated.status, 'updated-stopped');
    check('update preserves gate files', gatePaths.map(n => readFileSync(n, 'utf8')), gateBefore);
    check('update preserves active guard', await property('clean-vpn-killswitch.service', 'ActiveState'), 'active');
    check('update changes wrapper release', readFileSync('/usr/local/bin/clean-vpn-run.sh', 'utf8').includes('cd "/state/next-release"'), true);
    const offset = log().length; await ctl('start', 'clean-vpn.service'); await ready(offset);
    check('updated IPv4 through exit', await query('1.0.0.1'), '198.51.100.2');
    check('updated IPv6 through exit', await query('2606:4700:4700::1111'), '2001:db8:2::2');
    check('updated DNS through exit', await dns(), '192.0.2.10');
    const removed = JSON.parse((await exec('/usr/bin/node', ['scripts/clean-vpn-uninstall.mjs'])).stdout);
    check('uninstall complete', removed.status, 'uninstalled');
    check('uninstall removes owned gate and files', BOOT_FILES.every(n => !existsSync('/' + n)), true);
    check('uninstall keeps networkd active', await property('systemd-networkd.service', 'ActiveState'), 'active');
    check('uninstall keeps socket active', await property('systemd-networkd.socket', 'ActiveState'), 'active');
    check('uninstall direct IPv4 restored', await query('1.0.0.1'), '192.0.2.2');
    check('uninstall direct IPv6 restored', await query('2606:4700:4700::1111'), '2001:db8:1::2');
    check('uninstall direct DNS restored', await dns(), '192.0.2.10');
  }
  if (!p) for (const name of BOOT_FILES) { const dst = '/state/installed/' + name; mkdirSync(dst.slice(0, dst.lastIndexOf('/')), { recursive: true }); copyFileSync('/' + name, dst); }
  put('/state/previous-boot', bootId, 0o600); put('/state/phase', String(p + 1), 0o600); sync('/bin/sync', []);
  event({ event: p < 2 ? 'reboot-ready' : 'passed', phase: p, bootId, checks, actualNetworkdInstaller: true, acceptance: p < 2 ? 'matrix-pending' : 'lab-ready-for-host-review', limitations: ['virtual-ethernet-not-wifi', 'DHCP-from-isolated-dnsmasq', 'no-initramfs-network', 'no-power-cut', 'host-preflight-and-console-review-required'] });
  await ctl(p < 2 ? 'reboot' : 'poweroff', '--no-block');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2]; assertHostBootVm(mode);
  try { if (mode === 'prepare') prepare(); else if (mode === 'fixture') await fixture(); else await run(); }
  catch (e) { for (const file of ['/run/host-boot-client.log', '/run/host-boot-networkd.log', '/run/host-boot-fixture.log']) if (existsSync(file)) console.error(file, readFileSync(file, 'utf8')); console.error(e); event({ event: 'failed', phase: phase(), message: e.message }); process.exitCode = 1; }
}
