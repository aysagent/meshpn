/** Synthetic VPS2 topology. No reusable host authority or deployment API. */
import assert from 'node:assert/strict';
import { mkdir, readFile, readlink, realpath, writeFile, access } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { namespaceResources } from './browser-soak.mjs';
import { child, exec } from './browser-lab-driver.mjs';
import { sentinel } from './dns-lifecycle-lab.mjs';
import { startAdapterSoakLab } from './dns-adapter-soak-lab.mjs';
import { createResolvedBackend, resolvedMethod } from './dns-resolved-backend.mjs';
import { makeDnsQuery, validateDnsResponse } from './lab-dns-wire.mjs';
import { queryLabDns } from './transparent-dns-lab.mjs';
import { startNetworkdPeer } from './dns-networkd-peer.mjs';

export const NETWORKD_CHECKS = Object.freeze(['real-dhcp-baseline', 'resolved-refuses-networkd-owned-link',
  'owned-link-protected-without-uplink-takeover', 'cloud-names-blocked-not-publicly-forwarded',
  'real-dhcp-renew-does-not-replace-vpn-dns', 'networkd-reconfigure-preserves-owned-vpn-link',
  'dhcp-domain-removal-policy-refuses-before-doh', 'dhcp-domain-replacement-policy-refuses-before-doh',
  'exit-outage-no-direct-fallback', 'foreign-owned-link-edit-not-overwritten',
  'disable-preserves-latest-dhcp-not-stale-snapshot']);
export function assertNetworkdEvidence(report) {
  assert.equal(report.status, 'passed'); assert.deepEqual(report.checks, NETWORKD_CHECKS);
  for (const k of ['realDhcpRenew', 'privateBus', 'hostDnsFilesUnchanged', 'hostForwardingUnchanged']) assert.equal(report[k], true, k);
  for (const k of ['networkdOwnedLinkTakeover', 'hostDeploymentImplemented', 'rebootTested', 'durableJournalTested']) assert.equal(report[k], false, k);
  assert.equal(report.baselineQueriesDuringProtection, 0); assert.equal(report.dnsCalls, 0);
  assert.deepEqual(report.cloudDnsChanged, ['10.129.0.2', '10.129.0.3']);
  assert.deepEqual(report.dhcpDomainChanges, ['original', 'removed', 'replaced']);
  assert.equal(report.cloudPolicy, 'explicit-qname-deny-suffixes-before-doh-plus-guard');
  assert.ok(Number.isSafeInteger(report.policyDenied) && report.policyDenied >= 8);
  assert.equal(report.final.processes, 1); assert.equal(report.final.zombies, 0);
  assert.ok(Number.isSafeInteger(report.blockedLookupDeadlines) && report.blockedLookupDeadlines >= 0);
}

export function networkdLabOptions(args) {
  if (args.length === 1 && args[0] === '--help') return { help: true };
  const result = {}, seen = new Set();
  for (const arg of args) {
    if (arg === '--isolated' && !seen.has(arg)) { seen.add(arg); result.isolated = true; continue; }
    const m = /^--(systemd-dir|dnsmasq)=(\/[^\n\0]+)$/.exec(arg);
    assert.ok(m && !seen.has(m[1]), 'explicit absolute --systemd-dir and --dnsmasq required');
    seen.add(m[1]); result[m[1] === 'systemd-dir' ? 'systemdDir' : 'dnsmasq'] = m[2];
  }
  assert.ok(result.systemdDir && result.dnsmasq, 'explicit tools required'); return result;
}

export async function runNetworkdLab(directory, options) {
  await assertDnsMountNamespace();
  assert.ok(process.env.MESHPN_PARENT_UTSNS);
  assert.notEqual(await readlink('/proc/self/ns/uts'), process.env.MESHPN_PARENT_UTSNS);
  assert.notEqual(process.getuid(), 0, 'use mapped current-user launcher, not host root');
  directory = await realpath(directory);
  const links = () => exec('ip', ['-j', 'link']).then((r) => JSON.parse(r.stdout));
  assert.deepEqual((await links()).map((l) => l.ifname), ['lo']);
  const env = { PATH: '/usr/bin:/usr/sbin:/bin:/sbin', LC_ALL: 'C', OPENSSL_CONF: '/dev/null' };
  const daemonEnv = { ...env, LD_LIBRARY_PATH: options.systemdDir, SYSTEMD_LOG_TARGET: 'console',
    SYSTEMD_LOG_LEVEL: 'info', DBUS_SYSTEM_BUS_ADDRESS: 'unix:path=/run/networkd-lab/bus' };
  const versions = {}, hashes = {};
  for (const name of ['systemd-resolved', 'systemd-networkd']) {
    const path = join(options.systemdDir, name);
    if (name === 'systemd-resolved') {
      versions[name] = (await exec(path, ['--version'], { env: daemonEnv })).stdout.split('\n')[0];
      assert.match(versions[name], /^systemd 249 /, 'this fixture specifically requires version 249');
    } else {
      // networkd 249 takes no command-line arguments, including --version.
      const deps = (await exec('ldd', [path], { env: daemonEnv })).stdout;
      assert.ok(deps.includes(`libsystemd-shared-249.so => ${options.systemdDir}/libsystemd-shared-249.so`));
      assert.ok(!deps.includes('not found'));
      versions[name] = 'shared-249 dependency verified; executable identified by SHA256';
    }
    hashes[name] = createHash('sha256').update(await readFile(path)).digest('hex');
  }
  hashes.shared = createHash('sha256').update(await readFile(join(options.systemdDir, 'libsystemd-shared-249.so'))).digest('hex');
  versions.dnsmasq = (await exec(options.dnsmasq, ['--version'], { env })).stdout.split('\n')[0];
  hashes.dnsmasq = createHash('sha256').update(await readFile(options.dnsmasq)).digest('hex');
  const targets = await Promise.all(['/etc/resolv.conf', '/etc/nsswitch.conf', '/etc/passwd', '/etc/group'].map((p) => realpath(p)));
  const run = join(directory, 'run'); await mkdir(run); await exec('mount', ['--bind', run, '/run']);
  for (const target of targets) if (target.startsWith('/run/')) {
    await mkdir(dirname(target), { recursive: true }); await writeFile(target, '', { flag: 'wx' });
  }
  let fileId = 0;
  const bindText = async (target, value) => {
    const file = join(directory, `bind-${fileId++}`); await writeFile(file, value, { flag: 'wx', mode: 0o600 });
    await exec('mount', ['--bind', file, target]);
  };
  await bindText('/etc/passwd', `root:x:0:0:root:/root:/bin/false\nfixture:x:${process.getuid()}:${process.getgid()}:fixture:/nonexistent:/bin/false\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\n`);
  await bindText('/etc/group', `root:x:0:\nfixture:x:${process.getgid()}:\nnogroup:x:65534:\n`);
  await bindText('/etc/nsswitch.conf', 'passwd: files\ngroup: files\nhosts: dns\n');
  await bindText('/etc/resolv.conf', 'nameserver 127.0.0.53\noptions timeout:1 attempts:1\n');
  // Hide host config/includes and mount this netns's sysfs read-only. The private
  // container marker below allows networkd's no-udev container initialization.
  for (const path of ['/etc/systemd', '/usr/lib/systemd', '/usr/local/lib/systemd']) {
    try { await access(path); } catch (e) { if (e.code === 'ENOENT') continue; throw e; }
    const empty = join(directory, `empty-${fileId++}`); await mkdir(empty); await exec('mount', ['--bind', empty, path]);
  }
  await exec('mount', ['-t', 'sysfs', '-o', 'ro,nosuid,nodev,noexec', 'sysfs', '/sys']);
  await mkdir('/etc/systemd/network'); await mkdir('/run/networkd-lab', { mode: 0o700 });
  await mkdir('/run/systemd/network', { recursive: true }); await mkdir('/run/systemd/resolve', { recursive: true });
  await mkdir('/run/systemd/netif', { recursive: true });
  await writeFile('/run/systemd/container', 'other\n');
  await writeFile('/etc/systemd/resolved.conf', '[Resolve]\nDNS=\nFallbackDNS=\nLLMNR=no\nMulticastDNS=no\nDNSSEC=no\nDNSOverTLS=no\nCache=no\nReadEtcHosts=no\nDNSStubListener=yes\n');
  await writeFile('/etc/systemd/network/10-cloud.network', '[Match]\nName=eth0\n[Network]\nDHCP=ipv4\nIPv6AcceptRA=no\nLinkLocalAddressing=no\nLLMNR=no\nMulticastDNS=no\n[DHCPv4]\nUseDNS=yes\nUseDomains=yes\nUseRoutes=yes\nClientIdentifier=mac\n');
  await writeFile('/run/networkd-lab/bus.conf', `<busconfig><type>system</type><listen>${daemonEnv.DBUS_SYSTEM_BUS_ADDRESS}</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>`);
  await exec('hostname', ['networkd-lab']); await exec('ip', ['link', 'set', 'lo', 'up']);
  const processes = [], observers = [], checks = [];
  let lab, peer, report, daemonLog = '';
  const start = (file, args, extraEnv = env) => {
    const p = child(file, args, { env: extraEnv }); processes.push(p);
    p.proc.stderr.on('data', (b) => { daemonLog = (daemonLog + b).slice(-12000); }); return p;
  };
  const wait = async (fn, label) => {
    const end = performance.now() + 15000; let last;
    for (;;) { try { return await fn(); } catch (e) { last = e; }
      assert.ok(performance.now() < end, `${label}: ${last.message}\n${daemonLog}`); await delay(50); }
  };
  const busRun = (args) => exec('/usr/bin/busctl', ['--address', daemonEnv.DBUS_SYSTEM_BUS_ADDRESS, '--timeout=2s',
    '--auto-start=no', '--allow-interactive-authorization=no', '--json=short', ...args], { env, timeout: 3000 });
  const value = async (args) => JSON.parse((await busRun(args)).stdout).data;
  const owner = async (name) => (await value(['call', 'org.freedesktop.DBus', '/org/freedesktop/DBus',
    'org.freedesktop.DBus', 'GetNameOwner', 's', name]))[0];
  const bus = {
    owner: () => owner('org.freedesktop.resolve1'),
    async property(o, index, property) {
      const [path] = await value(['call', o, '/org/freedesktop/resolve1', 'org.freedesktop.resolve1.Manager', 'GetLink', 'i', String(index)]);
      return value(['get-property', o, path, 'org.freedesktop.resolve1.Link', property]);
    },
    set: (o, args) => busRun(['call', o, '/org/freedesktop/resolve1', 'org.freedesktop.resolve1.Manager', ...args]),
  };
  let sequence = 0, guarded = false, blockedLookupDeadlines = 0;
  const guard = async (enabled) => {
    await assertDnsMountNamespace();
    if (guarded === enabled) return;
    for (const tool of ['iptables', 'ip6tables']) for (const proto of ['udp', 'tcp'])
      await exec(tool, ['-w', '2', enabled ? '-A' : '-D', 'OUTPUT', '-p', proto, '--dport', '53', '-j', 'REJECT']);
    guarded = enabled;
  };
  const lookup = async (suffix, expected, tcp = false) => {
    const name = `case-${++sequence}.${suffix}`; let code = 0, stdout;
    try { ({ stdout } = await exec('getent', ['-A', '-s', 'dns', 'ahostsv4', name],
      { env: { ...env, RES_OPTIONS: `timeout:1 attempts:1${tcp ? ' use-vc' : ''}` }, timeout: 5000 })); }
    catch (e) {
      // resolved can keep an upstream-failed TCP request pending beyond glibc's
      // RES_OPTIONS. Record bounded cancellation, never call it a DNS response.
      if (expected === null && tcp && e.killed && e.signal === 'SIGTERM') {
        assert.equal(e.stdout, ''); blockedLookupDeadlines++; return;
      }
      assert.equal(e.killed, false); code = e.code; stdout = e.stdout;
    }
    assert.equal(code, expected ? 0 : 2, name);
    if (expected) assert.ok(stdout.trim().split('\n').every((line) => line.startsWith(`${expected} `)), name);
    else assert.equal(stdout, '', name);
  };
  const hits = async () => [...(await peer.stats()).hits, ...observers.map((s) => s.hits())];
  try {
    lab = await startAdapterSoakLab({ family: 4, modeTag: 'combo-tls', concurrency: 4, timeoutMs: 500,
      domainPolicy: { schema: 1, denySuffixes: ['ru-central1.internal', 'auto.internal'] } }, directory);
    for (const proto of ['udp', 'tcp']) await exec('iptables', ['-w', '2', '-A', 'OUTPUT', '-d', '127.0.0.53', '-p', proto, '--dport', '53', '-j', 'ACCEPT']);
    peer = await startNetworkdPeer(options.dnsmasq);
    for (const address of ['127.0.0.55', '::1']) observers.push(await sentinel(address));
    const dbus = start('/usr/bin/dbus-daemon', ['--nofork', '--print-address=1', '--config-file=/run/networkd-lab/bus.conf']);
    await dbus.waitFor(/unix:path=/);
    await peer.start('10.129.0.2');
    start(join(options.systemdDir, 'systemd-networkd'), [], daemonEnv);
    start(join(options.systemdDir, 'systemd-resolved'), [], { ...daemonEnv, SYSTEMD_LOG_LEVEL: 'info' });
    const ro = await wait(() => bus.owner(), 'resolved readiness');
    const no = await wait(() => owner('org.freedesktop.network1'), 'networkd readiness');
    const eth = (await links()).find((l) => l.ifname === 'eth0').ifindex;
    const dns = (last) => [[2, [10, 129, 0, last], 0, '']];
    const domains = [['ru-central1.internal', false], ['auto.internal', false]];
    let expectedDomains = domains;
    const cloudSettings = async (last) => {
      await wait(async () => assert.deepEqual(await bus.property(ro, eth, 'DNSEx'), dns(last)), 'DHCP DNS applied');
      await wait(async () => assert.deepEqual(await bus.property(ro, eth, 'Domains'), expectedDomains), 'DHCP domains applied');
      const lease = await readFile(`/run/systemd/netif/leases/${eth}`, 'utf8');
      assert.match(lease, /^ADDRESS=10\.129\.0\.18$/m); assert.match(lease, new RegExp(`^DNS=10\\.129\\.0\\.${last}$`, 'm'));
    };
    await cloudSettings(2); assert.ok((await peer.stats()).discovers > 0); assert.ok((await peer.stats()).acks > 0);
    await lookup('test', '203.0.113.8'); await lookup('auto.internal', '203.0.113.8', true); checks.push('real-dhcp-baseline');
    await assert.rejects(bus.set(ro, resolvedMethod('DNSEx', [[2, [127, 0, 0, 1], lab.adapter.port, '']], eth)), /managed/);
    await cloudSettings(2); checks.push('resolved-refuses-networkd-owned-link');
    await guard(true); const protectedHits = await hits();
    await exec('ip', ['link', 'add', 'vpndns', 'type', 'dummy']);
    await exec('ip', ['addr', 'add', '192.0.2.1/32', 'dev', 'vpndns']); await exec('ip', ['link', 'set', 'vpndns', 'up']);
    const identity = async () => { const l = (await links()).find((v) => v.ifname === 'vpndns'); return { ifindex: l.ifindex, ifname: l.ifname, address: l.address }; };
    const vpn = (await identity()).ifindex;
    for (const [p, v] of Object.entries({ DNSEx: [[2, [127, 0, 0, 55], 0, '']], Domains: [], DefaultRoute: false }))
      await bus.set(ro, resolvedMethod(p, v, vpn));
    const backend = await createResolvedBackend({ bus, ifindex: vpn, identity, ensureGuard: () => guard(true), removeGuard: async () => {},
      probe: async () => { for (const tcp of [false, true]) { const q = makeDnsQuery('ready.test');
        assert.equal(validateDnsResponse(await queryLabDns(lab.adapter.port, q, { tcp }), q).rcode, 0); } } });
    await backend.apply(lab.adapter.port);
    for (const tcp of [false, true]) await lookup('test', '192.0.2.123', tcp);
    await cloudSettings(2); assert.deepEqual(await hits(), protectedHits); checks.push('owned-link-protected-without-uplink-takeover');
    const blockedCloud = async () => {
      const before = lab.stats().resolverBodies;
      for (const domain of ['ru-central1.internal', 'auto.internal']) for (const tcp of [false, true]) await lookup(domain, null, tcp);
      assert.equal(lab.stats().resolverBodies, before, 'cloud name reached public DoH fixture'); assert.deepEqual(await hits(), protectedHits);
    };
    await blockedCloud(); checks.push('cloud-names-blocked-not-publicly-forwarded');
    await peer.start('10.129.0.3'); const ackBefore = (await peer.stats()).acks;
    const [networkName, networkPath] = await value(['call', no, '/org/freedesktop/network1', 'org.freedesktop.network1.Manager', 'GetLinkByIndex', 'i', String(eth)]);
    assert.equal(networkName, 'eth0');
    assert.match(networkPath, /^\/org\/freedesktop\/network1\/link\/[A-Za-z0-9_]+$/);
    await busRun(['call', no, networkPath, 'org.freedesktop.network1.Link', 'Renew']);
    await cloudSettings(3); assert.ok((await peer.stats()).acks > ackBefore);
    await backend.verify(); for (const tcp of [false, true]) await lookup('test', '192.0.2.123', tcp);
    await blockedCloud(); checks.push('real-dhcp-renew-does-not-replace-vpn-dns');
    const reconfigureAcks = (await peer.stats()).acks;
    await busRun(['call', no, networkPath, 'org.freedesktop.network1.Link', 'Reconfigure']);
    await wait(async () => assert.ok((await peer.stats()).acks > reconfigureAcks), 'DHCP after reconfigure');
    await cloudSettings(3); await backend.verify(); await lookup('test', '192.0.2.123');
    assert.deepEqual(await hits(), protectedHits); checks.push('networkd-reconfigure-preserves-owned-vpn-link');
    for (const [mode, nextDomains, check] of [
      ['removed', [], 'dhcp-domain-removal-policy-refuses-before-doh'],
      ['replaced', [['changed.internal', false]], 'dhcp-domain-replacement-policy-refuses-before-doh'],
    ]) {
      await peer.start('10.129.0.3', mode); const beforeAcks = (await peer.stats()).acks;
      expectedDomains = nextDomains;
      await busRun(['call', no, networkPath, 'org.freedesktop.network1.Link', 'Renew']);
      await wait(async () => assert.ok((await peer.stats()).acks > beforeAcks), 'DHCP domain-change ACK');
      await cloudSettings(3); await backend.verify();
      const deniedBefore = lab.adapter.stats().stub.policyDenied, attemptsBefore = lab.stats().attempts;
      await blockedCloud();
      assert.ok(lab.adapter.stats().stub.policyDenied >= deniedBefore + 4, 'removed cloud routing must reach adapter policy');
      assert.equal(lab.stats().attempts, attemptsBefore, 'denied names opened an exit connection');
      for (const tcp of [false, true]) await lookup('test', '192.0.2.123', tcp);
      checks.push(check);
    }
    await lab.stopExit(); await lookup('test', null); await blockedCloud(); assert.deepEqual(await hits(), protectedHits);
    await lab.restartExit(); await lookup('test', '192.0.2.123'); checks.push('exit-outage-no-direct-fallback');
    await bus.set(ro, resolvedMethod('Domains', [['foreign.test', true]], vpn));
    await assert.rejects(backend.disable(), /ownership conflict/);
    assert.deepEqual(await bus.property(ro, vpn, 'Domains'), [['foreign.test', true]]); assert.deepEqual(await hits(), protectedHits);
    await bus.set(ro, resolvedMethod('Domains', [['.', true]], vpn)); checks.push('foreign-owned-link-edit-not-overwritten');
    await backend.disable(); await exec('ip', ['link', 'del', 'vpndns']); await cloudSettings(3);
    assert.deepEqual(await hits(), protectedHits); await guard(false);
    for (const tcp of [false, true]) { await lookup('test', '203.0.113.8', tcp); await lookup('auto.internal', '203.0.113.8', tcp); }
    assert.ok((await hits())[1] > protectedHits[1], 'latest DHCP DNS is the restored path'); checks.push('disable-preserves-latest-dhcp-not-stale-snapshot');
    assert.deepEqual(checks, NETWORKD_CHECKS); assert.equal(lab.stats().dnsCalls, 0);
    report = { schema: 1, kind: 'clean-vpn-networkd-lab', status: 'passed', versions, hashes, checks,
      realDhcpRenew: true, dhcp: await peer.stats(), separateCloudNamespace: true,
      cloudDnsChanged: ['10.129.0.2', '10.129.0.3'], networkdOwnedLinkTakeover: false,
      cloudPolicy: 'explicit-qname-deny-suffixes-before-doh-plus-guard', baselineQueriesDuringProtection: 0,
      dhcpDomainChanges: ['original', 'removed', 'replaced'], policyDenied: lab.adapter.stats().stub.policyDenied,
      privateBus: true, blockedLookupDeadlines, dnsCalls: 0, hostDeploymentImplemented: false, rebootTested: false, durableJournalTested: false,
      limitations: ['no-uplink-pcap', 'no-live-VPS', 'no-arbitrary-cloud-domain-policy',
        'not-complete-Ubuntu22-rootfs', 'IPv6-guard-installed-not-traffic-tested', 'no-networkd-sysctl-management'] };
    return report;
  } catch (e) { throw new Error(`${e.stack}\nDaemon diagnostics (bounded):\n${daemonLog}`, { cause: e }); }
  finally {
    for (const p of [...processes].reverse()) await p.stop();
    await peer?.close();
    await lab?.close(); await Promise.all(observers.map((s) => s.close()));
    const final = namespaceResources(); assert.equal(final.tree.live, 1); assert.equal(final.tree.zombies, 0);
    if (report) report.final = { processes: final.tree.live, zombies: final.tree.zombies };
  }
}
