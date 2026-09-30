/** Build a disposable initramfs from trusted local tools, never a host initramfs/root filesystem. */
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, copyFile, writeFile, readFile, readdir, chmod, symlink, realpath } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { createGzip } from 'node:zlib';
import { createHash } from 'node:crypto';
import { dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dnsSystemdVmUnits } from './dns-systemd-vm-units.mjs';
import { dnsmasqVmUnits } from './dnsmasq-vm-units.mjs';
import { dnsCoupledVmUnits } from './dns-coupled-vm-units.mjs';
import { radxaVmUnits } from './dns-radxa-vm-units.mjs';
import { packageDnsSource } from './dns-source-package.mjs';
import { hostSystemdVmUnits } from './vpn-host-systemd-vm.mjs';
import { hostBootVmUnits } from './vpn-host-boot-vm.mjs';

const exec = (file, args, options = {}) => promisify(execFile)(file, args, { timeout: 30000, maxBuffer: 1024 * 1024, ...options });
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export async function verifyVmPackages(directory) {
  const result = [];
  for (const name of (await readdir(directory)).filter((file) => file.endsWith('.deb')).sort()) {
    const file = join(directory, name);
    const fields = (await exec('dpkg-deb', ['--field', file], { maxBuffer: 1024 * 1024 })).stdout;
    const pkg = /^Package: (.+)$/m.exec(fields)?.[1], version = /^Version: (.+)$/m.exec(fields)?.[1];
    assert.ok(pkg && version);
    const metadata = (await exec('apt-cache', ['show', `${pkg}=${version}`], { maxBuffer: 1024 * 1024 })).stdout;
    const hashes = metadata.split(/\n\n/).filter((entry) => /^Filename: pool\//m.test(entry))
      .map((entry) => /^SHA256: ([a-f0-9]{64})$/m.exec(entry)?.[1]);
    const hash = sha256(await readFile(file)); assert.ok(hashes.includes(hash), `APT digest mismatch: ${pkg}`);
    result.push({ package: pkg, version, sha256: hash });
  }
  assert.ok(result.some((p) => p.package === 'qemu-system-x86'));
  assert.ok(result.some((p) => p.package === 'busybox-static')); return result;
}
export async function buildDnsVmImage({ directory, toolsRoot, kernel, resolved, systemd = false, ingress = false, ipv6 = false, hostResilience = false, hostJoint = false, hostSystemd = false, hostNetworkd = false, hostColdBoot = false, bootDnsmasq = null, dnsConntrack = null, dnsIngressOnly = false, dnsHostOnly = false, dnsmasq = null, coupled = false, radxa = false, deployment = false, publication = false, releasedInspection = false, uninstall = false }) {
  assert.ok(!hostColdBoot || hostNetworkd && hostSystemd && bootDnsmasq);
  assert.ok(!bootDnsmasq || hostColdBoot);
  assert.ok(!hostNetworkd || hostSystemd, 'networkd host fixture requires host systemd');
  assert.ok(!hostSystemd || ingress && ipv6 && dnsConntrack && !systemd && !hostJoint && !hostResilience && !dnsHostOnly && !dnsIngressOnly);
  assert.ok(!ipv6 || ingress && (!dnsConntrack || hostJoint || hostSystemd));
  assert.ok(!hostJoint || ipv6 && dnsConntrack && !hostResilience);
  assert.ok(!hostResilience || ipv6);
  assert.ok(!dnsConntrack || ingress && dnsConntrack.startsWith('/'));
  assert.equal(typeof dnsIngressOnly, 'boolean'); assert.ok(!dnsIngressOnly || dnsConntrack);
  assert.equal(typeof dnsHostOnly, 'boolean'); assert.ok(!dnsHostOnly || dnsConntrack);
  assert.ok(!(dnsHostOnly && dnsIngressOnly));
  assert.ok(!(systemd && ingress), 'separate systemd DNS and ingress fixtures');
  assert.ok(!dnsmasq || systemd && !ingress && dnsmasq.startsWith('/'));
  assert.ok(!coupled || systemd && !dnsmasq && !ingress);
  assert.ok(!radxa || systemd && dnsmasq && !coupled && !ingress);
  assert.ok(!deployment || coupled);
  assert.ok(!publication || deployment);
  assert.ok(!releasedInspection || coupled && !deployment);
  assert.ok(!uninstall || publication && coupled);
  const units = hostColdBoot ? hostBootVmUnits() : hostSystemd ? hostSystemdVmUnits() : radxa ? radxaVmUnits() : coupled ? dnsCoupledVmUnits() : dnsmasq ? dnsmasqVmUnits() : dnsSystemdVmUnits({ cliAdapter: true });
  if (uninstall) units['dns-vm-driver.service'] = units['dns-vm-driver.service'].replace('TimeoutStartSec=15min', 'TimeoutStartSec=35min');
  // This separate case inspects a genuinely never-activated deployment. Only
  // its private D-Bus fixture starts; no guard/network/DNS service is pulled in.
  if (deployment || releasedInspection) {
    // PID1 exposes its API only when both D-Bus service AND socket are running
    // (systemd v255 manager_dbus_is_running). The older fixture only needed
    // resolve1/network1, whose registration does not establish PID1 authority.
    units['dbus.service'] = units['dbus.service'].replace('Requires=dns-vm-network.service\nAfter=dns-vm-network.service',
      releasedInspection ? 'Requires=dns-vm-network.service dbus.socket\nAfter=dns-vm-network.service dbus.socket'
        : 'Requires=dbus.socket\nAfter=dbus.socket');
    units['dbus.socket'] = '[Unit]\nDescription=Private guest system bus socket\nDefaultDependencies=no\n[Socket]\nListenStream=/run/dbus/system_bus_socket\nSocketMode=0666\n';
  }
  const root = join(directory, 'guest'); await mkdir(root, { mode: 0o700 });
  const copied = new Map(), modules = new Set();
  const destination = (path) => { assert.ok(path.startsWith('/') && !path.split('/').includes('..')); return join(root, path); };
  const copy = async (source, target = source) => {
    if (copied.has(target)) return;
    const bytes = await readFile(source); copied.set(target, sha256(bytes));
    await mkdir(dirname(destination(target)), { recursive: true }); await copyFile(source, destination(target));
  };
  const elf = async (source, target = source) => {
    await copy(source, target);
    const output = (await exec('ldd', [source], { maxBuffer: 1024 * 1024 })).stdout;
    assert.ok(!output.includes('not found'), `missing ELF library: ${basename(source)}`);
    for (const line of output.split('\n')) {
      const path = /(?:=>\s+|^\s*)(\/\S+)\s+\(/.exec(line)?.[1];
      if (path) await copy(path);
    }
  };
  await copy(join(toolsRoot, 'usr/bin/busybox'), '/bin/busybox');
  await elf(process.execPath, '/usr/bin/node');
  for (const name of ['ip', 'unshare', 'setpriv', 'hostname', 'flock', 'getent', 'openssl', 'busctl', 'dbus-daemon']) await elf(`/usr/bin/${name}`);
  await elf('/usr/sbin/xtables-legacy-multi'); await elf(resolved, '/usr/lib/systemd/systemd-resolved');
  if (dnsmasq) await elf(dnsmasq, '/usr/sbin/dnsmasq');
  if (ingress) await elf('/usr/sbin/sysctl');
  if (hostResilience || hostJoint || hostSystemd) await elf('/bin/bash');
  if (hostSystemd) await elf('/bin/bash', '/usr/bin/bash');
  if (hostSystemd) for (const name of ['env', 'install']) await elf(`/usr/bin/${name}`);
  if (dnsConntrack) {
    await copy(dnsConntrack, '/usr/sbin/conntrack');
    const output = (await exec('ldd', [dnsConntrack])).stdout;
    assert.ok(!output.includes('not found'), 'conntrack libraries missing; supply private LD_LIBRARY_PATH');
    for (const line of output.split('\n')) {
      const path = /(?:=>\s+|^\s*)(\/\S+)\s+\(/.exec(line)?.[1];
      if (path) await copy(path, path.startsWith('/lib') || path.startsWith('/usr/lib') ? path : `/usr/lib/x86_64-linux-gnu/${basename(path)}`);
    }
  }
  if (systemd || hostSystemd) {
    for (const path of ['/usr/lib/systemd/systemd', '/usr/lib/systemd/systemd-executor', '/usr/lib/systemd/systemd-shutdown', '/usr/bin/systemctl', '/usr/bin/systemd-notify', '/usr/bin/umount']) await elf(path);
    for (const name of ['shutdown.target', 'umount.target', 'final.target', 'reboot.target', 'poweroff.target', 'systemd-reboot.service', 'systemd-poweroff.service']) {
      await copy(`/usr/lib/systemd/system/${name}`);
    }
    await mkdir(destination('/etc/systemd/system'), { recursive: true });
    for (const [name, contents] of Object.entries(units)) await writeFile(destination(`/etc/systemd/system/${name}`), contents, { mode: 0o644 });
    await writeFile(destination('/etc/systemd/resolved.conf'), '[Resolve]\nDNS=\nFallbackDNS=\nLLMNR=no\nMulticastDNS=no\nDNSSEC=no\nDNSOverTLS=no\nCache=no\nReadEtcHosts=no\nDNSStubListener=yes\n', { mode: 0o644 });
    await writeFile(destination('/etc/dbus-vm.conf'), '<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>', { mode: 0o644 });
  }
  if (coupled || hostNetworkd) await elf('/usr/lib/systemd/systemd-networkd');
  if (hostNetworkd) {
    await elf('/bin/false');
    await copy('/usr/lib/systemd/system/systemd-networkd.service');
    // A netlink socket opened by PID1 would bind to the wrong network namespace.
    if (!hostColdBoot) await symlink('/dev/null', destination('/etc/systemd/system/systemd-networkd.socket'));
  }
  if (hostColdBoot) {
    await elf('/bin/true');
    await elf(bootDnsmasq, '/usr/sbin/dnsmasq');
    for (const path of ['/usr/lib/systemd/systemd-udevd', '/usr/bin/udevadm']) await elf(path);
    for (const unit of ['systemd-networkd.socket', 'systemd-udevd.service', 'systemd-udev-trigger.service', 'systemd-udevd-control.socket', 'systemd-udevd-kernel.socket']) await copy(`/usr/lib/systemd/system/${unit}`);
  }
  if (publication) await elf('/usr/bin/mv');
  for (const name of ['libxt_tcp.so', 'libxt_udp.so', 'libipt_REJECT.so', 'libip6t_REJECT.so', 'libxt_standard.so',
    ...(systemd ? ['libxt_comment.so'] : []),
    ...(dnsConntrack ? ['libxt_multiport.so'] : []),
    ...(ingress ? ['libxt_conntrack.so', 'libxt_comment.so', 'libxt_addrtype.so', 'libxt_SNAT.so', 'libxt_DNAT.so', 'libxt_MASQUERADE.so'] : [])]) {
    await elf(`/usr/lib/x86_64-linux-gnu/xtables/${name}`);
  }
  const release = (await exec('uname', ['-r'])).stdout.trim();
  assert.equal(await realpath(kernel), `/boot/vmlinuz-${release}`, 'this builder requires the matching local kernel/modules');
  for (const name of ['iptable_filter', 'ip6table_filter', 'ipt_REJECT', 'ip6t_REJECT', 'xt_tcpudp', 'dummy',
    ...(ipv6 ? ['ip6table_nat'] : []),
    ...(systemd ? ['xt_comment'] : []),
    ...(dnsConntrack ? ['xt_multiport', 'nf_conntrack_netlink'] : []),
    ...(dnsmasq ? ['veth'] : []),
    ...(ingress ? ['tun', 'veth', 'iptable_nat', 'xt_conntrack', 'xt_comment', 'xt_addrtype', 'xt_nat', 'xt_MASQUERADE'] : [])]) {
    const dependencies = (await exec('modprobe', ['--show-depends', name])).stdout;
    for (const match of dependencies.matchAll(/^insmod (\/[^\s]+\.ko)\b/gm)) { await copy(match[1]); modules.add(match[1]); }
  }
  const project = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
  async function copyTree(from, to) {
    for (const entry of await readdir(from, { withFileTypes: true })) {
      assert.ok(!entry.isSymbolicLink(), 'do not import source symlinks');
      if (entry.isDirectory()) await copyTree(join(from, entry.name), `${to}/${entry.name}`);
      else if (entry.isFile() && /\.(?:mjs|js)$/.test(entry.name)) await copy(join(from, entry.name), `${to}/${entry.name}`);
    }
  }
  await copyTree(join(project, 'scripts'), '/project/scripts');
  if (hostResilience || hostJoint || hostSystemd) for (const name of ['killswitch.sh', 'install.sh', 'uninstall.sh'])
    await copy(join(project, 'scripts/autostart', name), `/project/scripts/autostart/${name}`);
  if (systemd && (!dnsmasq || radxa)) {
    // Match the real deployment path: a symlink changes import.meta.url while
    // Node keeps the argv entrypoint spelling, bypassing its main guard.
    const codeRoot = publication ? '/source/clean-vpn' : '/opt/clean-vpn';
    if (coupled) {
      await mkdir(dirname(destination(codeRoot)), { recursive: true });
      const output = join(await realpath(dirname(destination(codeRoot))), basename(codeRoot));
      const packaged = await packageDnsSource({ source: await realpath(project), output });
      const manifest = JSON.parse(await readFile(join(output, 'bundle.json'), 'utf8'));
      for (const [path, digest] of Object.entries(manifest.files)) copied.set(`${codeRoot}/${path}`, digest);
      copied.set(`${codeRoot}/bundle.json`, packaged.bundleSha256);
    } else await copyTree(join(project, 'scripts'), `${codeRoot}/scripts`);
  }
  if (dnsmasq) await copy(join(project, 'scripts/fixtures/dns-clients/radxa-dnsmasq.conf'), '/project/scripts/fixtures/dns-clients/radxa-dnsmasq.conf');
  if (ingress) {
    await copy(join(project, 'package.json'), '/project/package.json');
    for (const name of ['ws', '@matrixai/logger']) {
      await copyTree(join(project, 'node_modules', name), `/project/node_modules/${name}`);
      await copy(join(project, 'node_modules', name, 'package.json'), `/project/node_modules/${name}/package.json`);
    }
    await elf(join(project, 'native/tun_linux/build/Release/tun_linux.node'), '/project/native/tun_linux/build/Release/tun_linux.node');
    await elf(join(project, 'native/boring_tls/build/boring-tls-helper'), '/project/native/boring_tls/build/boring-tls-helper');
  }
  for (const dir of ['/proc', '/sys', '/dev', '/run', '/tmp', '/state', '/etc/systemd', '/etc/ssl', '/usr/sbin', '/sbin', '/lib64', '/usr/local/bin']) {
    await mkdir(destination(dir), { recursive: true });
  }
  for (const name of ['sh', 'mount', 'mkdir', 'chmod', 'chown', 'stat', 'insmod', 'readlink', 'cat', 'sync', 'reboot', 'poweroff', 'sleep', 'realpath', 'dirname', 'rm']) {
    await symlink('/bin/busybox', destination(`/bin/${name}`));
    // Ubuntu systemd's compiled service PATH may omit /bin (merged-/usr).
    if (hostSystemd) await symlink('/bin/busybox', destination(`/usr/bin/${name}`));
  }
  for (const name of ['iptables', 'ip6tables', ...(systemd || hostResilience || hostJoint || hostSystemd ? ['iptables-restore', 'ip6tables-restore'] : [])]) await symlink('/usr/sbin/xtables-legacy-multi', destination(`/usr/sbin/${name}`));
  if (systemd && (!dnsmasq || radxa) && !publication) {
    await mkdir(destination('/etc/clean-vpn/dns'), { recursive: true });
    await writeFile(destination('/etc/clean-vpn/dns/guard-policy.json'), JSON.stringify({ schema: 1,
      kind: 'clean-vpn-dns-boot-policy', enabled: true, firewallBackend: 'legacy',
      input: radxa ? { schema: 1, client: 'radxa', id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', usbInterface: 'usb0', usbAddress: '192.168.7.1' }
        : { schema: 1, client: 'vps2', id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' } }), { mode: 0o600 });
  }
  await writeFile(destination('/etc/passwd'), 'root:x:0:0:root:/root:/bin/sh\nfixture:x:1000:1000:fixture:/tmp:/bin/sh\nsystemd-resolve:x:193:193:resolver:/nonexistent:/bin/false\n'
    + (coupled || hostNetworkd ? 'systemd-network:x:192:192:network:/nonexistent:/bin/false\n' : '')
    + (dnsmasq ? 'nobody:x:65534:65534:Unprivileged fixture:/nonexistent:/bin/false\n' : ''), { mode: 0o644 });
  await writeFile(destination('/etc/group'), 'root:x:0:\nfixture:x:1000:\nsystemd-resolve:x:193:\n'
    + (coupled || hostNetworkd ? 'systemd-network:x:192:\n' : '')
    + (dnsmasq ? 'nogroup:x:65534:\n' : ''), { mode: 0o644 });
  await writeFile(destination('/etc/nsswitch.conf'), 'passwd: files\ngroup: files\nhosts: dns\n', { mode: 0o644 });
  await writeFile(destination('/etc/resolv.conf'), `nameserver ${dnsmasq ? '127.0.0.1' : systemd ? '127.0.0.53' : '127.0.0.55'}\n`, { mode: 0o644 });
  await writeFile(destination('/etc/machine-id'), '11111111111111111111111111111111\n', { mode: 0o644 });
  const init = ingress ? `#!/bin/sh
set -eu
echo INGRESS_VM_INIT
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
export OPENSSL_CONF=/dev/null
export MESHPN_INGRESS_VM=1
${hostResilience ? 'export MESHPN_HOST_RESILIENCE=1' : ''}
${hostJoint ? 'export MESHPN_HOST_JOINT=1' : ''}
${dnsIngressOnly ? 'export MESHPN_DNS_CLI_INGRESS_ONLY=1' : ''}
${dnsHostOnly ? 'export MESHPN_DNS_CLI_HOST_ONLY=1' : ''}
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs -o mode=0755 tmpfs /run
mount -t tmpfs tmpfs /tmp
chmod 1777 /tmp
${[...modules].map((path) => `insmod ${path}${basename(path) === 'dummy.ko' ? ' numdummies=0' : ''}`).join('\n')}
cd /project
${hostColdBoot ? 'mount -t ext4 -o rw /dev/vda /state\nnode scripts/lib/vpn-host-boot-vm.mjs prepare' : ''}
${hostSystemd ? 'mkdir -p /run/dbus\nexec /usr/lib/systemd/systemd --system --log-target=console --log-level=info --show-status=no' : ''}
echo INGRESS_VM_TESTS
node --version
set +e
node --max-old-space-size=192 scripts/${ipv6 ? 'test-vpn-ipv6-real.mjs' : dnsConntrack ? 'test-dns-tunnel-cli-real.mjs' : 'test-ingress-transport-real.mjs'}
result=$?
set -e
if [ "$result" = 0 ]; then echo INGRESS_VM_PASS; else echo INGRESS_VM_FAIL; fi
poweroff -f
` : `#!/bin/sh
set -eu
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
export OPENSSL_CONF=/dev/null
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs -o mode=0755 tmpfs /run
mount -t tmpfs tmpfs /tmp
chmod 1777 /tmp
${[...modules].map((path) => `insmod ${path}${basename(path) === 'dummy.ko' ? ' numdummies=0' : ''}`).join('\n')}
# Outer guest guard before any network setup or consumer; no host network devices exist.
for tool in iptables ip6tables; do
  for protocol in udp tcp; do "$tool" -A OUTPUT -p "$protocol" --dport 53 -j REJECT; done
done
mount -t ext4 -o rw /dev/vda /state
${systemd ? `# Real systemd PID1, not a service wrapper around the namespace fixture.
chmod 700 /state
mkdir -p /run/dbus /run/meshpn
chmod 700 /run/meshpn
exec /usr/lib/systemd/systemd --system --log-target=console --log-level=info --show-status=no
` : ''}
chown 1000:1000 /state
chmod 700 /state
export MESHPN_PARENT_NETNS="$(readlink /proc/self/ns/net)"
export MESHPN_PARENT_MNTNS="$(readlink /proc/self/ns/mnt)"
export MESHPN_PARENT_PIDNS="$(readlink /proc/self/ns/pid)"
export MESHPN_PARENT_UTSNS="$(readlink /proc/self/ns/uts)"
set +e
/usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups /usr/bin/unshare --user --map-current-user --net --mount --uts --pid --fork --mount-proc --keep-caps --kill-child=SIGKILL --propagation private /usr/bin/node --max-old-space-size=192 /project/scripts/lib/dns-vm-guest.mjs
result=$?
set -e
sync
umount_state=0
if mount -o remount,ro /state; then umount_state=1; fi
if [ "$result" = 42 ] && [ "$umount_state" = 1 ]; then
  echo 'DNS_VM_EVENT {"event":"reboot-committed"}'
  reboot -f
fi
if [ "$result" != 0 ]; then echo DNS_VM_GUEST_FAILURE; fi
poweroff -f
`;
  await writeFile(destination('/init'), init, { mode: 0o755 }); await chmod(destination('/init'), 0o755);
  const names = [];
  async function walk(path = '.') {
    // Host staging is enclosed by directory/0700; guest directories must be
    // traversable by fixture UID 1000 after the initramfs becomes its root.
    await chmod(join(root, path), 0o755);
    names.push(path);
    for (const entry of await readdir(join(root, path), { withFileTypes: true })) {
      const name = `${path}/${entry.name}`; assert.ok(!name.includes('\n'));
      if (entry.isDirectory()) await walk(name);
      else {
        // These /etc files are synthetic, public guest configuration (not host
        // secrets). Host umask077 must not hide them from resolved's guest UID.
        if (entry.isFile() && name.startsWith('./etc/')) await chmod(join(root, name), name.endsWith('/guard-policy.json') ? 0o600 : 0o644);
        names.push(name);
      }
    }
  }
  await walk();
  if (systemd || hostSystemd) {
    // Offline verification in the staged root catches unit syntax/ExecStart
    // mistakes before spending a TCG boot. It does not contact host PID1.
    await exec('/usr/bin/systemd-analyze', [`--root=${root}`, '--man=no', 'verify',
      ...Object.keys(units).filter((name) => name.endsWith('.service'))],
    { env: { PATH: '/usr/bin:/usr/sbin:/bin:/sbin', SYSTEMD_LOG_LEVEL: 'warning', SYSTEMD_PAGER: 'cat' } });
  }
  const cpio = spawn('cpio', ['--create', '--format=newc', '--owner=0:0', '--quiet'], { cwd: root, timeout: 60000, killSignal: 'SIGKILL', stdio: ['pipe', 'pipe', 'pipe'] });
  let error = ''; cpio.stderr.on('data', (chunk) => { error = (error + chunk).slice(-4096); });
  const completed = new Promise((resolve, reject) => { cpio.on('error', reject); cpio.once('close', (code) => code === 0 ? resolve() : reject(new Error(error))); });
  const initrd = join(directory, 'guest-initrd.gz');
  const packed = pipeline(cpio.stdout, createGzip({ level: 1 }), createWriteStream(initrd, { flags: 'wx', mode: 0o600 }));
  cpio.stdin.end(`${names.join('\n')}\n`); await Promise.all([completed, packed]);
  const kernelPath = join(directory, 'guest-kernel'); await copyFile(kernel, kernelPath);
  const manifest = { schema: 1, kernelRelease: release, kernelSha256: sha256(await readFile(kernelPath)),
    initrdSha256: sha256(await readFile(initrd)), files: Object.fromEntries(copied) };
  await writeFile(join(directory, 'image-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return { initrd, kernel: kernelPath, manifest };
}
