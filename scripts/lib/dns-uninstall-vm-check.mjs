/** Complete publication/use/removal in a NIC-less VM. No host entrypoint. */
import assert from 'node:assert/strict';
import { mkdir, open, readFile, writeFile, chmod, unlink, symlink, lstat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import dgram from 'node:dgram';
import { setTimeout as delay } from 'node:timers/promises';
import { assertCoupledDnsVm } from './dns-systemd-vm-safety.mjs';
import { exec } from './browser-lab-driver.mjs';
import { DNS_BOOT_LOCK, requireDnsBootGuardLock } from './dns-boot-guard.mjs';
import { createDnsSystemCommands } from './dns-system-command.mjs';
import { inspectFreshDnsDeployment } from './dns-deployment-inactive.mjs';
import { compileDnsClientDeploymentFiles } from './dns-deployment-files.mjs';
import { dnsDeployment } from './dns-deployment.mjs';
import { removeInstalledReleasedDnsDeployment, DNS_DEPLOYMENT_DIRECTORY, DNS_REMOVAL_DIRECTORY } from './dns-installed-removal.mjs';
import { startSystemdVmAdapterFixture } from './dns-adapter-soak-lab.mjs';
import { sentinel } from './dns-lifecycle-lab.mjs';
import { lookup } from './dns-systemd-vm-worker.mjs';
import { makeDnsQuery, validateDnsResponse } from './lab-dns-wire.mjs';
import { createDnsSystemBus } from './dns-system-bus.mjs';

const hash = (v) => createHash('sha256').update(v).digest('hex');
const source = '/source/clean-vpn', fixtureDirectory = '/run/meshpn/full';
const input = { schema: 1, client: 'vps2', id: 'b'.repeat(32) };
const networkPath = '/etc/systemd/network/10-dnsfixture.network';
const network = '[Match]\nName=dnsfixture\n[Network]\nDHCP=no\nKeepConfiguration=yes\nLinkLocalAddressing=no\nIPv6AcceptRA=no\nDNS=10.129.0.2\nDomains=baseline.test\nDNSDefaultRoute=yes\nLLMNR=no\nMulticastDNS=no\n';
const environment = { PATH: '/usr/bin:/usr/sbin:/bin:/sbin', LC_ALL: 'C', LANG: 'C' };
const ctl = (...args) => exec('/usr/bin/systemctl', args, { env: environment, timeout: 30000 });
async function gate() {
  const o = await assertCoupledDnsVm(); assert.equal(o.phase, 'coupled'); assert.equal(o.point, 'installed-uninstall');
}
async function baselineQuery(tcp, label) {
  await gate(); const packet = makeDnsQuery(`${label}.test`);
  const socket = tcp ? net.connect({ host: '10.129.0.2', port: 53 }) : dgram.createSocket('udp4');
  let timer;
  try {
    const response = await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error('fixture baseline timeout')), 2000);
      socket.once('error', reject);
      if (tcp) {
        let pending = Buffer.alloc(0);
        socket.on('data', (v) => {
          pending = Buffer.concat([pending, v]);
          if (pending.length > 4098) return reject(new Error('fixture baseline response too large'));
          if (pending.length >= 2 && pending.length === pending.readUInt16BE(0) + 2) resolve(pending.subarray(2));
        });
        socket.once('end', () => reject(new Error('fixture baseline EOF')));
        socket.once('connect', () => { const prefix = Buffer.alloc(2); prefix.writeUInt16BE(packet.length); socket.write(Buffer.concat([prefix, packet])); });
      } else { socket.once('message', resolve); socket.send(packet, 53, '10.129.0.2', (e) => { if (e) reject(e); }); }
    });
    assert.equal(validateDnsResponse(response, packet).flags & 15, 0);
  } finally { clearTimeout(timer); if (tcp) socket.destroy(); else socket.close(); }
}
async function transaction(operation) {
  await gate(); assert.ok(['install', 'remove', 'recover'].includes(operation));
  const commands = await createDnsSystemCommands({ assertAuthority: gate, required: ['ip', 'busctl', 'systemctl', 'iptables', 'ip6tables'] });
  if (operation !== 'install') return removeInstalledReleasedDnsDeployment({ commands, operation });
  const bundle = await readFile(`${source}/bundle.json`, 'utf8'), secret = await readFile(`${fixtureDirectory}/cli-key`);
  const domainPolicy = { schema: 1, denySuffixes: ['blocked.test', 'baseline.test'] };
  const files = compileDnsClientDeploymentFiles({ bundle, secret,
    adapter: { schema: 1, exitIp: '93.184.216.36', exitPort: 44443, publicName: 'relay.test', listenPort: 2053,
      readyName: 'systemd-ready.test', domainPolicy, upstream: JSON.parse(await readFile(`${fixtureDirectory}/cli-upstream.json`, 'utf8')) },
    guard: { schema: 1, kind: 'clean-vpn-dns-boot-policy', enabled: true, firewallBackend: 'legacy', input },
    config: { schema: 1, kind: 'clean-vpn-dns-client', client: 'vps2', uplink: 'dnsfixture',
      networkFile: { path: networkPath, sha256: hash(network) }, adapterPort: 2053, readyName: 'systemd-ready.test', domainPolicy } });
  try {
    for (const f of files) await mkdir(dirname(f.path), { recursive: true, mode: 0o755 });
    return await dnsDeployment({ root: '/', directory: DNS_DEPLOYMENT_DIRECTORY, operation, source, files,
      expectedSha256: hash(bundle), lockFd: await requireDnsBootGuardLock(),
      assertInactive: async () => (await inspectFreshDnsDeployment({ commands, input, firewallBackend: 'legacy' })).freshInactive });
  } finally { secret.fill(0); for (const f of files) if (Buffer.isBuffer(f.contents)) f.contents.fill(0); }
}
export async function checkDnsUninstallVm() {
  await gate(); const checks = [], originalResolver = await readFile('/etc/resolv.conf'), originalNss = await readFile('/etc/nsswitch.conf');
  for (const path of ['/opt', '/var', '/var/lib', '/etc/systemd/network']) {
    await mkdir(path, { recursive: true, mode: 0o755 }); await chmod(path, 0o755);
  }
  for (const path of ['/var/lib/clean-vpn', DNS_DEPLOYMENT_DIRECTORY, DNS_REMOVAL_DIRECTORY, '/run/clean-vpn-dns-guard', fixtureDirectory])
    await mkdir(path, { mode: 0o700 });
  const lock = await open(DNS_BOOT_LOCK, 'wx', 0o600); await lock.close();
  await exec('ip', ['link', 'set', 'lo', 'up']);
  await exec('ip', ['link', 'add', 'dnsfixture', 'type', 'dummy']);
  await exec('ip', ['addr', 'add', '10.129.0.1/24', 'dev', 'dnsfixture']);
  await exec('ip', ['link', 'set', 'dnsfixture', 'up']);
  await exec('ip', ['route', 'add', 'default', 'dev', 'dnsfixture']);
  await exec('ip', ['addr', 'add', '10.129.0.2/32', 'dev', 'lo']);
  await writeFile(networkPath, network, { flag: 'wx', mode: 0o644 }); await chmod(networkPath, 0o644);
  await writeFile('/run/systemd/container', 'other\n', { flag: 'wx', mode: 0o644 });
  await writeFile('/etc/nsswitch.conf', 'passwd: files\ngroup: files\nhosts: files dns\n');
  await unlink('/etc/resolv.conf'); await symlink('/run/systemd/resolve/stub-resolv.conf', '/etc/resolv.conf');
  for (const name of ['sysinit.target', 'basic.target', 'network-online.target']) {
    const path = `/etc/systemd/system/${name}`;
    await writeFile(path, '[Unit]\nDescription=Passive isolated VM target\nDefaultDependencies=no\n', { flag: 'wx', mode: 0o644 }); await chmod(path, 0o644);
  }
  const baseline = await sentinel('10.129.0.2'); let lab;
  const outer = async (action) => {
    for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp'])
      await exec(tool, ['-w', '2', action, 'OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT']);
  };
  const run = async (operation) => {
    const started = performance.now(); console.log(`DNS_UNINSTALL_STAGE ${operation} begin`);
    const r = JSON.parse((await exec('/usr/bin/flock', ['-n', '-E', '75', '-F', DNS_BOOT_LOCK, '/usr/bin/node',
      '/project/scripts/lib/dns-uninstall-vm-check.mjs', operation], { env: environment, timeout: 1200000 })).stdout);
    console.log(`DNS_UNINSTALL_STAGE ${operation} passed elapsedMs=${Math.round(performance.now() - started)}`); return r;
  };
  const client = async (operation) => {
    console.log(`DNS_UNINSTALL_STAGE client-${operation} begin`);
    await exec('/usr/bin/flock', ['-n', '-E', '75', '-F', DNS_BOOT_LOCK, '/usr/bin/node',
      '/opt/clean-vpn/scripts/dns-client.mjs', `--${operation}`], { env: environment, timeout: 180000 });
    console.log(`DNS_UNINSTALL_STAGE client-${operation} passed`);
  };
  try {
    await ctl('daemon-reload'); await ctl('start', 'systemd-resolved.service', 'systemd-networkd.service');
    const bus = createDnsSystemBus((tool, args) => exec(tool, args)), owner = await bus.owner();
    const [link] = JSON.parse((await exec('ip', ['-j', 'link', 'show', 'dev', 'dnsfixture'])).stdout);
    const deadline = performance.now() + 15000;
    while (!/^ADMIN_STATE=configured$/m.test(await readFile(`/run/systemd/netif/links/${link.ifindex}`, 'utf8').catch(() => ''))
      || JSON.stringify(await bus.property(owner, link.ifindex, 'DNSEx')) !== JSON.stringify([[2, [10, 129, 0, 2], 0, '']])) {
      assert.ok(performance.now() < deadline, 'networkd fixture readiness'); await delay(100);
    }
    await outer('-D');
    for (const tcp of [false, true]) {
      await baselineQuery(tcp, `full-direct-positive-${tcp}`);
      await lookup(`full-baseline-${tcp}`, '203.0.113.8', tcp);
    }
    assert.ok(baseline.hits() >= 2); await outer('-A'); checks.push('answering-baseline-positive-control');
    lab = await startSystemdVmAdapterFixture(fixtureDirectory, { cli: true }); await lab.prepareCliAdapter();
    assert.equal((await run('install')).stage, 'installed'); checks.push('full-source-and-client-publication');
    await ctl('daemon-reload'); await ctl('start', 'clean-vpn-dns-guard.service');
    const guard = JSON.parse((await exec('/usr/bin/flock', ['-n', '-E', '75', '-F', DNS_BOOT_LOCK, '/usr/bin/node',
      '/opt/clean-vpn/scripts/dns-boot-guard.mjs', '--inspect'], { env: environment, timeout: 60000 })).stdout);
    assert.deepEqual(guard.states, ['present', 'present']); await outer('-D');
    const protectedHits = baseline.hits();
    await ctl('start', 'clean-vpn-dns-adapter.service'); await client('start');
    for (const tcp of [false, true]) for (const family of [4, 6])
      await lookup(`full-protected-${tcp}-${family}`, family === 4 ? '192.0.2.123' : '2001:db8::12', tcp, family);
    await lab.stopExit();
    for (const tcp of [false, true]) await lookup(`full-outage-${tcp}`, null, tcp);
    for (const tcp of [false, true]) await assert.rejects(baselineQuery(tcp, `full-direct-blocked-${tcp}`));
    assert.equal(baseline.hits(), protectedHits); checks.push('protected-nss-and-outage-no-baseline-fallback');
    await client('disable'); await ctl('stop', 'clean-vpn-dns-adapter.service');
    const paths = ['/var/lib/clean-vpn/dns-v1/transaction/journal.json', '/var/lib/clean-vpn/dns-v1/transaction/link/journal.json', '/var/lib/clean-vpn/dns-v1/guard/journal.json'];
    const histories = await Promise.all(paths.map((p) => readFile(p, 'utf8')));
    const managers = async () => Promise.all(['systemd-resolved.service', 'systemd-networkd.service'].map(async (name) =>
      (await ctl('show', name, '--property=MainPID', '--property=InvocationID', '--property=ActiveState')).stdout));
    const managerBefore = await managers();
    assert.equal((await run('remove')).stage, 'removed');
    assert.deepEqual(await managers(), managerBefore);
    assert.deepEqual(await Promise.all(paths.map((p) => readFile(p, 'utf8'))), histories);
    await assert.rejects(lstat('/opt/clean-vpn'), { code: 'ENOENT' });
    await assert.rejects(lstat('/etc/clean-vpn/dns/client-opt-in.json'), { code: 'ENOENT' });
    await lstat(`${DNS_DEPLOYMENT_DIRECTORY}/code/retired/bundle.json`);
    checks.push('real-detach-reload-stop-and-file-uninstall');
    assert.equal((await run('recover')).stage, 'removed'); checks.push('uninstall-repeat-preserves-runtime-history');
    const hits = baseline.hits();
    for (const tcp of [false, true]) await lookup(`full-restored-${tcp}`, '203.0.113.8', tcp);
    assert.ok(baseline.hits() >= hits + 2); checks.push('restored-baseline-positive-control');
    await writeFile('/state/full-uninstall-history.json', JSON.stringify({ histories, managerBefore }), { mode: 0o600 });
    return checks;
  } finally {
    await lab?.close(); await baseline.close();
    await unlink('/etc/resolv.conf'); await writeFile('/etc/resolv.conf', originalResolver, { mode: 0o644 });
    await writeFile('/etc/nsswitch.conf', originalNss);
  }
}
if (process.argv[1] === fileURLToPath(import.meta.url))
  transaction(process.argv[2]).then((v) => console.log(JSON.stringify(v))).catch((e) => { console.error(e.stack); process.exitCode = 1; });
