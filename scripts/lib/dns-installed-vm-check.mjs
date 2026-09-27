/** Synthetic installed baseline check inside the existing NIC-less coupled VM.
 * No host installer: every fixture write follows the VM gate. */
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, unlink, symlink, chmod } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { assertCoupledDnsVm } from './dns-systemd-vm-safety.mjs';
import { exec } from './browser-lab-driver.mjs';
import { DNS_BOOT_LOCK } from './dns-boot-guard.mjs';
import { busContext, coupledBaseline, control } from './dns-systemd-vm-worker.mjs';
import { resolvedMethod } from './dns-resolved-backend.mjs';
import { DNS_NETWORKD_POLICY, DNS_NETWORKD_CONTENTS } from './dns-networkd-policy.mjs';
import { compileDnsAdapterServicePlan } from './dns-adapter-service-plan.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
export async function checkInstalledDnsVmBaseline() {
  const options = await assertCoupledDnsVm(); assert.equal(options.phase, 'coupled');
  const resolverBefore = await readFile('/etc/resolv.conf'), nssBefore = await readFile('/etc/nsswitch.conf');
  const domainsBefore = await readFile('/etc/clean-vpn/dns/domains.json');
  const ctl = (...args) => exec('/usr/bin/systemctl', args, { timeout: 30000 });
  const environment = { PATH: '/usr/bin:/usr/sbin:/bin:/sbin', LC_ALL: 'C', LANG: 'C' };
  const inspect = (command = '--inspect') => exec('/usr/bin/flock', ['-n', '-E', '75', '-F', DNS_BOOT_LOCK, '/usr/bin/node',
    '/opt/clean-vpn/scripts/dns-client.mjs', command], { env: environment, timeout: 90000 });
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
  await writeFile(DNS_NETWORKD_POLICY, DNS_NETWORKD_CONTENTS, { flag: 'wx', mode: 0o644 }); await chmod(DNS_NETWORKD_POLICY, 0o644);
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
    await assert.rejects(inspect('--inspect-adapter'), refused); // No loaded service yet.
    const adapterPlan = compileDnsAdapterServicePlan({ schema: 1, exitIp: '93.184.216.36', exitPort: 44443,
      publicName: 'relay.test', listenPort: 2053, readyName: 'systemd-ready.test',
      upstream: JSON.parse(await readFile('/etc/clean-vpn/dns/upstream.json', 'utf8')), domainPolicy: policy });
    const adapterUnit = adapterPlan.files[0], guardAlias = '/etc/systemd/system/clean-vpn-dns-guard.service';
    // The tiny guest normally runs only DefaultDependencies=no fixture units.
    // Supply passive targets for the UNMODIFIED production adapter unit; this
    // does not claim a complete distro boot graph or a wait-online test.
    const passiveTargets = ['sysinit.target', 'basic.target', 'network-online.target'];
    for (const name of passiveTargets) {
      const path = `/etc/systemd/system/${name}`;
      await writeFile(path, '[Unit]\nDescription=Passive installed-adapter VM fixture target\nDefaultDependencies=no\n', { flag: 'wx', mode: 0o644 });
      await chmod(path, 0o644);
    }
    await writeFile(adapterUnit.path, adapterUnit.contents, { flag: 'wx', mode: 0o644 }); await chmod(adapterUnit.path, 0o644);
    await symlink('/etc/systemd/system/dns-vm-guard.service', guardAlias);
    try {
      await ctl('daemon-reload'); await ctl('start', 'clean-vpn-dns-adapter.service');
      const queriesBefore = (await control('fixture', 'stats')).resolverBodies;
      const loaded = JSON.parse((await inspect('--inspect-adapter')).stdout);
      assert.equal(loaded.loadedCredentialsVerified, true); assert.equal(loaded.activationAuthorized, false);
      assert.equal(loaded.listenerOwnershipVerified, true);
      assert.equal(loaded.dnsQueriesSent, 0); assert.equal(loaded.systemSettingsChanged, false);
      assert.equal((await control('fixture', 'stats')).resolverBodies, queriesBefore);
      const ready = JSON.parse((await inspect('--probe-adapter')).stdout);
      assert.equal(ready.protectedReadinessVerified, true); assert.equal(ready.dnsQueriesSent, 4);
      assert.equal(ready.activationAuthorized, false); assert.equal(ready.systemSettingsChanged, false);
      assert.equal((await control('fixture', 'stats')).resolverBodies, queriesBefore + 4);
      const keyPath = '/etc/clean-vpn/dns/hmac.key', key = await readFile(keyPath);
      const changed = Buffer.from(key); changed[0] ^= 1;
      try {
        await writeFile(keyPath, changed); await assert.rejects(inspect('--inspect-adapter'), refused);
        await assert.rejects(inspect('--probe-adapter'), refused);
        assert.equal((await control('fixture', 'stats')).resolverBodies, queriesBefore + 4);
      } finally { await writeFile(keyPath, key); key.fill(0); changed.fill(0); }
      assert.equal(JSON.parse((await inspect('--inspect-adapter')).stdout).loadedCredentialsVerified, true);
    } finally {
      await ctl('stop', 'clean-vpn-dns-adapter.service');
      await unlink(adapterUnit.path); await unlink(guardAlias); await ctl('daemon-reload');
      for (const name of passiveTargets) await unlink(`/etc/systemd/system/${name}`);
      await ctl('daemon-reload');
    }
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
    for (const path of [networkPath, DNS_NETWORKD_POLICY, '/run/systemd/container', '/etc/clean-vpn/dns/client.json', '/etc/clean-vpn/dns/client-opt-in.json']) await unlink(path);
  }
}
