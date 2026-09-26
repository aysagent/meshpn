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
export async function buildDnsVmImage({ directory, toolsRoot, kernel, resolved, systemd = false, ingress = false, dnsmasq = null, coupled = false }) {
  assert.ok(!(systemd && ingress), 'separate systemd DNS and ingress fixtures');
  assert.ok(!dnsmasq || systemd && !ingress && dnsmasq.startsWith('/'));
  assert.ok(!coupled || systemd && !dnsmasq && !ingress);
  const units = coupled ? dnsCoupledVmUnits() : dnsmasq ? dnsmasqVmUnits() : dnsSystemdVmUnits();
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
  if (systemd) {
    for (const path of ['/usr/lib/systemd/systemd', '/usr/lib/systemd/systemd-executor', '/usr/lib/systemd/systemd-shutdown', '/usr/bin/systemctl', '/usr/bin/systemd-notify', '/usr/bin/umount']) await elf(path);
    for (const name of ['shutdown.target', 'umount.target', 'final.target', 'reboot.target', 'poweroff.target', 'systemd-reboot.service', 'systemd-poweroff.service']) {
      await copy(`/usr/lib/systemd/system/${name}`);
    }
    await mkdir(destination('/etc/systemd/system'), { recursive: true });
    for (const [name, contents] of Object.entries(units)) await writeFile(destination(`/etc/systemd/system/${name}`), contents, { mode: 0o644 });
    await writeFile(destination('/etc/systemd/resolved.conf'), '[Resolve]\nDNS=\nFallbackDNS=\nLLMNR=no\nMulticastDNS=no\nDNSSEC=no\nDNSOverTLS=no\nCache=no\nReadEtcHosts=no\nDNSStubListener=yes\n', { mode: 0o644 });
    await writeFile(destination('/etc/dbus-vm.conf'), '<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>', { mode: 0o644 });
  }
  for (const name of ['libxt_tcp.so', 'libxt_udp.so', 'libipt_REJECT.so', 'libip6t_REJECT.so', 'libxt_standard.so',
    ...(ingress ? ['libxt_conntrack.so', 'libxt_comment.so', 'libxt_addrtype.so', 'libxt_SNAT.so', 'libxt_DNAT.so', 'libxt_MASQUERADE.so'] : [])]) {
    await elf(`/usr/lib/x86_64-linux-gnu/xtables/${name}`);
  }
  const release = (await exec('uname', ['-r'])).stdout.trim();
  assert.equal(await realpath(kernel), `/boot/vmlinuz-${release}`, 'this builder requires the matching local kernel/modules');
  for (const name of ['iptable_filter', 'ip6table_filter', 'ipt_REJECT', 'ip6t_REJECT', 'xt_tcpudp', 'dummy',
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
  for (const dir of ['/proc', '/sys', '/dev', '/run', '/tmp', '/state', '/etc/systemd', '/etc/ssl', '/usr/sbin', '/sbin', '/lib64']) {
    await mkdir(destination(dir), { recursive: true });
  }
  for (const name of ['sh', 'mount', 'mkdir', 'chmod', 'chown', 'insmod', 'readlink', 'cat', 'sync', 'reboot', 'poweroff', 'sleep']) {
    await symlink('/bin/busybox', destination(`/bin/${name}`));
  }
  for (const name of ['iptables', 'ip6tables']) await symlink('/usr/sbin/xtables-legacy-multi', destination(`/usr/sbin/${name}`));
  await writeFile(destination('/etc/passwd'), 'root:x:0:0:root:/root:/bin/sh\nfixture:x:1000:1000:fixture:/tmp:/bin/sh\nsystemd-resolve:x:193:193:resolver:/nonexistent:/bin/false\n'
    + (dnsmasq ? 'nobody:x:65534:65534:Unprivileged fixture:/nonexistent:/bin/false\n' : ''), { mode: 0o644 });
  await writeFile(destination('/etc/group'), 'root:x:0:\nfixture:x:1000:\nsystemd-resolve:x:193:\n'
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
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
chmod 1777 /tmp
${[...modules].map((path) => `insmod ${path}${basename(path) === 'dummy.ko' ? ' numdummies=0' : ''}`).join('\n')}
cd /project
echo INGRESS_VM_TESTS
node --version
set +e
node --max-old-space-size=192 scripts/test-ingress-transport-real.mjs
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
mount -t tmpfs tmpfs /run
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
        if (entry.isFile() && name.startsWith('./etc/')) await chmod(join(root, name), 0o644);
        names.push(name);
      }
    }
  }
  await walk();
  if (systemd) {
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
