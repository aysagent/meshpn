/** Synthetic installed baseline check inside the existing NIC-less coupled VM.
 * No host installer: every fixture write follows the VM gate. */
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, unlink, symlink, chmod } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { assertCoupledDnsVm } from './dns-systemd-vm-safety.mjs';
import { exec } from './browser-lab-driver.mjs';
import { DNS_BOOT_LOCK } from './dns-boot-guard.mjs';
import { busContext, coupledBaseline } from './dns-systemd-vm-worker.mjs';
import { resolvedMethod } from './dns-resolved-backend.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
export async function checkInstalledDnsVmBaseline() {
  const options = await assertCoupledDnsVm(); assert.equal(options.phase, 'coupled');
  const resolverBefore = await readFile('/etc/resolv.conf'), nssBefore = await readFile('/etc/nsswitch.conf');
  const domainsBefore = await readFile('/etc/clean-vpn/dns/domains.json');
  const ctl = (...args) => exec('/usr/bin/systemctl', args, { timeout: 30000 });
  const environment = { PATH: '/usr/bin:/usr/sbin:/bin:/sbin', LC_ALL: 'C', LANG: 'C' };
  const inspect = () => exec('/usr/bin/flock', ['-n', '-E', '75', '-F', DNS_BOOT_LOCK, '/usr/bin/node',
    '/opt/clean-vpn/scripts/dns-client.mjs', '--inspect'], { env: environment, timeout: 90000 });
  const refused = (e) => e.code === 1 && /^DNS_CLIENT_REFUSED\n(?:DNS_CLIENT_LOCATION=[a-z0-9-]+\.mjs:\d+\n)?$/.test(e.stderr) && e.stdout === '';
  await assert.rejects(inspect(), refused);
  const networkPath = '/etc/systemd/network/10-dnsfixture.network';
  // A loopback DNS server is exported as ifindex1 by resolved's manager API,
  // regardless of its link. Inspect a synthetic non-loopback uplink server;
  // no DNS query is sent to it. Restore the sentinel before lifecycle tests.
  const network = '[Match]\nName=dnsfixture\n[Network]\nDHCP=no\nKeepConfiguration=yes\nLinkLocalAddressing=no\nIPv6AcceptRA=no\nDNS=10.129.0.2\nDomains=baseline.test\nDNSDefaultRoute=yes\nLLMNR=no\nMulticastDNS=no\n';
  const policy = { schema: 1, denySuffixes: ['blocked.test', 'baseline.test'] };
  const config = JSON.stringify({ schema: 1, kind: 'clean-vpn-dns-client', client: 'vps2', uplink: 'dnsfixture',
    networkFile: { path: networkPath, sha256: hash(network) }, adapterPort: 2053,
    readyName: 'systemd-ready.test', domainPolicy: policy });
  const opt = JSON.stringify({ schema: 1, kind: 'clean-vpn-dns-client-opt-in', enabled: true, client: 'vps2',
    guardId: 'b'.repeat(32), bundleSha256: hash(await readFile('/opt/clean-vpn/bundle.json')), configSha256: hash(config) });
  await mkdir('/etc/systemd/network', { recursive: true }); await chmod('/etc/systemd/network', 0o755);
  await writeFile(networkPath, network, { flag: 'wx', mode: 0o644 }); await chmod(networkPath, 0o644);
  // No udev in this minimal guest; the same networkd mode is used in its
  // existing namespace DHCP test. This is NOT a full Ubuntu rootfs proof.
  await writeFile('/run/systemd/container', 'other\n', { flag: 'wx', mode: 0o644 });
  await writeFile('/etc/clean-vpn/dns/client.json', config, { flag: 'wx', mode: 0o600 });
  await writeFile('/etc/clean-vpn/dns/client-opt-in.json', opt, { flag: 'wx', mode: 0o600 });
  await writeFile('/etc/clean-vpn/dns/domains.json', JSON.stringify(policy));
  await writeFile('/etc/nsswitch.conf', 'passwd: files\ngroup: files\nhosts: files dns\n');
  await unlink('/etc/resolv.conf'); await symlink('/run/systemd/resolve/stub-resolv.conf', '/etc/resolv.conf');
  await exec('ip', ['route', 'add', 'default', 'dev', 'dnsfixture']);
  await ctl('start', 'systemd-networkd.service');
  const [fixtureLink] = JSON.parse((await exec('ip', ['-j', 'link', 'show', 'dev', 'dnsfixture'])).stdout);
  const { bus, ifindex } = await busContext(), owner = await bus.owner();
  const end = performance.now() + 15000;
  for (;;) {
    const state = await readFile(`/run/systemd/netif/links/${fixtureLink.ifindex}`, 'utf8').catch(() => '');
    if (/^ADMIN_STATE=configured$/m.test(state)
      && JSON.stringify(await bus.property(owner, ifindex, 'DNSEx')) === JSON.stringify([[2, [10, 129, 0, 2], 0, '']])) break;
    assert.ok(performance.now() < end, 'networkd fixture readiness'); await delay(100);
  }
  try {
    const report = JSON.parse((await inspect()).stdout);
    assert.equal(report.installedAuthorityVerified, true); assert.equal(report.dnsOwnershipVerified, false);
    assert.equal(report.baseline.baselineChecksPassed, true); assert.equal(report.baseline.activationAuthorized, false);
    assert.equal(report.systemSettingsChanged, false); assert.equal(report.dnsQueriesSent, 0);
    await assert.rejects(exec('/usr/bin/node', ['/opt/clean-vpn/scripts/dns-client.mjs', '--inspect'],
      { env: environment, timeout: 90000 }), refused);
    await writeFile('/etc/clean-vpn/dns/domains.json', domainsBefore);
    await assert.rejects(inspect(), refused);
  } finally {
    await ctl('stop', 'systemd-networkd.service');
    for (const [property, value] of Object.entries(coupledBaseline)) {
      await bus.set(owner, resolvedMethod(property, value, ifindex));
      assert.deepEqual(await bus.property(owner, ifindex, property), value);
    }
    await exec('ip', ['route', 'del', 'default', 'dev', 'dnsfixture']);
    await unlink('/etc/resolv.conf'); await writeFile('/etc/resolv.conf', resolverBefore, { flag: 'wx', mode: 0o644 }); await chmod('/etc/resolv.conf', 0o644);
    await writeFile('/etc/nsswitch.conf', nssBefore); await writeFile('/etc/clean-vpn/dns/domains.json', domainsBefore);
    for (const path of [networkPath, '/run/systemd/container', '/etc/clean-vpn/dns/client.json', '/etc/clean-vpn/dns/client-opt-in.json']) await unlink(path);
  }
}
