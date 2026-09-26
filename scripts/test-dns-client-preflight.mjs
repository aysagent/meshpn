import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { collectDnsClientOwnership, filterDnsmasqArgv, filterNetworkdState, parseOwnershipUnit,
  dnsmasqSource, dnsmasqConfigPath, networkConfigPath } from './lib/dns-client-ownership.mjs';
import { parseClientPreflightArgs, assessClientPreflight, collectClientPreflight } from './lib/dns-client-preflight.mjs';
import { DIAGNOSTIC_ENV } from './lib/dns-diagnostic.mjs';

const absent = () => Object.assign(new Error('SECRET missing'), { code: 'ENOENT' });
const ns = { net: 'net:[1]', mnt: 'mnt:[2]', pid: 'pid:[3]' };
const statText = (start = '123') => `50 (dnsmasq) S ${Array(18).fill('0').join(' ')} ${start}\n`;
function unitText(name) {
  return Object.entries({ Id: name, LoadState: 'loaded', ActiveState: 'active', SubState: 'running', UnitFileState: 'enabled',
    MainPID: '50', InvocationID: 'a'.repeat(32), FragmentPath: `/usr/lib/systemd/system/${name}`, SourcePath: '', DropInPaths: '',
    ControlGroup: `/system.slice/${name}`, NeedDaemonReload: 'no', Type: 'simple', User: '', Group: '', DynamicUser: 'no',
    RootDirectory: '', RootImage: '', PrivateNetwork: 'no', NetworkNamespacePath: '' }).map(([k, v]) => `${k}=${v}`).join('\n');
}
function fixture() {
  const reads = [], commands = [], links = [], listed = [], units = new Map();
  for (const name of ['dnsmasq.service', 'systemd-networkd.service', 'systemd-resolved.service']) units.set(name, unitText(name));
  const files = new Map([
    ['/proc/50/stat', statText()], ['/proc/50/cgroup', '0::/system.slice/dnsmasq.service\n'],
    ['/proc/50/cmdline', '/usr/sbin/dnsmasq\0--keep-in-foreground\0--conf-file=/etc/dnsmasq.conf\0'],
    ['/etc/dnsmasq.conf', 'conf-dir=/etc/dnsmasq.d,*.conf\nno-resolv\n'],
    ['/etc/dnsmasq.d/usb.conf', 'interface=usb0\nlisten-address=127.0.0.1,192.168.7.1\nserver=1.1.1.1\n'],
    ['/run/systemd/netif/links/2', 'ADMIN_STATE=configured\nOPER_STATE=routable\nNETWORK_FILE=/run/systemd/network/10-netplan-eth0.network\nDNS=10.129.0.2\nDOMAINS=ru-central1.internal auto.internal\nSECRET=never-print\n'],
    ['/run/systemd/network/10-netplan-eth0.network', '[Match]\nName=eth0\n[Network]\nDHCP=yes\n[DHCPv4]\nUseDNS=true\nPrivateKey=SECRET\n'],
  ]);
  const diagnostic = { runtime: { uid: 0 }, deadlineExceeded: false, probes: [],
    inspection: { environment: { pid1: 'systemd' }, resolver: { status: 'ok', mountpoint: false, targetKind: 'resolved-stub' },
      nss: { status: 'ok', customService: false, entries: 1 }, units: { 'NetworkManager.service': 'not-found', 'resolvconf.service': 'not-found', 'systemd-resolved.service': 'inactive' } },
    resolved: { owner: { status: 'ok' } }, commands: { links: { status: 'ok', stdout: JSON.stringify([{ ifindex: 2, ifname: 'eth0' }]) } } };
  const deps = {
    read: async (path, limit) => { reads.push(path); assert.ok(limit <= 32768); if (!files.has(path)) throw absent(); return files.get(path); },
    link: async (path) => { links.push(path); if (path === '/proc/50/exe') return '/usr/sbin/dnsmasq';
      const m = /^\/proc\/(?:50|self)\/ns\/(net|mnt|pid)$/.exec(path); assert.ok(m); return ns[m[1]]; },
    canonical: async (path) => path,
    stat: async (path) => ({ isFile: () => path !== '/etc/dnsmasq.d', isDirectory: () => path === '/etc/dnsmasq.d',
      nlink: 1n, dev: 1n, ino: 23n, ctimeNs: 50n, size: 100n, uid: 0n, gid: 0n, mode: 0o100644n }),
    list: async (path) => { listed.push(path); assert.equal(path, '/etc/dnsmasq.d'); return ['usb.conf', 'README', '.secret.conf', 'ignored.conf~', '#backup#']; },
    run: async (file, args, options) => { commands.push({ file, args, options }); assert.equal(file, '/usr/bin/systemctl');
      const name = args[3]; assert.ok(units.has(name)); return { code: 0, reason: null, stdout: units.get(name), stderr: 'SECRET ignored' }; },
  };
  return { files, units, diagnostic, deps, reads, commands, links, listed };
}

test('preflight requires explicit supported client, permits only optional DNS probe', () => {
  assert.deepEqual(parseClientPreflightArgs(['--client=vps2']), { client: 'vps2', probe: false });
  assert.deepEqual(parseClientPreflightArgs(['--probe', '--client=radxa']), { client: 'radxa', probe: true });
  assert.deepEqual(parseClientPreflightArgs(['--help']), { help: true });
  for (const args of [[], ['--client=vps1'], ['--client=radxa', '--apply'], ['--client=radxa', '--probe', '--probe'],
    ['--client=vps2', '--client=radxa'], ['--help', '--probe'], ['--config=/etc/shadow']]) {
    assert.throws(() => parseClientPreflightArgs(args));
    const r = spawnSync(process.execPath, ['scripts/dns-client-preflight.mjs', ...args], { encoding: 'utf8', timeout: 5000 });
    assert.equal(r.status, 1); assert.doesNotMatch(r.stdout, /PREFLIGHT BEGIN/); assert.doesNotMatch(r.stderr, /shadow/);
  }
});
test('unit filter omits ExecStart/environment, preserves only ownership fields', () => {
  const r = parseOwnershipUnit(`${unitText('dnsmasq.service')}\nExecStart=SECRET\nEnvironment=SECRET`, 'dnsmasq.service');
  assert.equal(r.MainPID, 50); assert.equal(r.InvocationID, 'a'.repeat(32)); assert.doesNotMatch(JSON.stringify(r), /SECRET/);
  assert.throws(() => parseOwnershipUnit(unitText('dnsmasq.service') + '\nMainPID=51', 'dnsmasq.service'));
  assert.throws(() => parseOwnershipUnit(unitText('dnsmasq.service'), 'systemd-resolved.service'));
});
test('unit private paths are omitted and namespace overrides remain visible', () => {
  const text = unitText('dnsmasq.service').replace('RootDirectory=', 'RootDirectory=/private/SECRET')
    .replace('FragmentPath=/usr/lib/systemd/system/dnsmasq.service', 'FragmentPath=/private/SECRET');
  const r = parseOwnershipUnit(text, 'dnsmasq.service'); assert.equal(r.RootDirectory, '[configured]');
  assert.equal(r.FragmentPath, '[unsupported-path]'); assert.doesNotMatch(JSON.stringify(r), /SECRET/);
});
test('argv filter handles long/short config sources without exposing private values', () => {
  const r = filterDnsmasqArgv('/usr/sbin/dnsmasq\0-C/etc/dnsmasq.conf\0-7\0/etc/dnsmasq.d,.dpkg-old,.dpkg-new\0-R\0--server=1.1.1.1\0--pid-file=/private/SECRET\0--dhcp-script=/private/SECRET\0--password=SECRET\0');
  assert.equal(r.defaultConfigCandidate, false); assert.equal(r.sources.length, 2); assert.equal(r.hooksObserved, true);
  assert.equal(r.omitted, 2); assert.doesNotMatch(JSON.stringify(r), /SECRET/);
  assert.ok(r.options.some((o) => o.key === 'no-resolv'));
  assert.deepEqual(r.sources[1].suffixes, ['.dpkg-old', '.dpkg-new']);
});
test('default, disabled, unsafe and additional config sources are distinguished', () => {
  assert.equal(filterDnsmasqArgv('dnsmasq\0-k\0').sources[0].implicit, true);
  assert.deepEqual(filterDnsmasqArgv('dnsmasq\0--conf-file=\0').sources, [{ key: 'conf-file', disabled: true }]);
  const r = filterDnsmasqArgv('dnsmasq\0--conf-file=/etc/shadow\0--servers-file=/private/SECRET\0');
  assert.equal(r.sources[0].unsupported, true); assert.equal(r.additionalSourcesObserved, true); assert.doesNotMatch(JSON.stringify(r), /SECRET|shadow/);
  for (const text of ['dnsmasq', 'other\0', 'dnsmasq\0' + 'x'.repeat(16384) + '\0']) assert.throws(() => filterDnsmasqArgv(text));
  assert.equal(dnsmasqSource('conf-dir', '/etc/dnsmasq.d,*.conf,.old').unsupported, true);
});
test('supported path selection rejects traversal, secrets, devices and shell syntax', () => {
  assert.equal(dnsmasqConfigPath('/etc/dnsmasq.d/usb.conf'), true);
  assert.equal(networkConfigPath('/run/systemd/network/10-netplan-eth0.network'), true);
  for (const p of ['/etc/shadow', '/dev/zero', '/etc/dnsmasq.d/../shadow', '/etc/dnsmasq.d/./usb', '/etc/dnsmasq.d/a b', '/etc/dnsmasq.d/$(x)']) assert.equal(dnsmasqConfigPath(p), false);
  assert.equal(networkConfigPath('/run/systemd/network/../secret.network'), false);
});
test('networkd state retains DNS ownership hints, not arbitrary environment assignments', () => {
  const r = filterNetworkdState('NETWORK_FILE=/run/systemd/network/u.network\nDNS=10.129.0.2\nDOMAINS=auto.internal\nOTHER=SECRET\n');
  assert.equal(r.NETWORK_FILE, '/run/systemd/network/u.network'); assert.deepEqual(r.DNS, ['10.129.0.2']);
  assert.doesNotMatch(JSON.stringify(r), /SECRET/);
  assert.throws(() => filterNetworkdState('DNS=1.1.1.1\nDNS=8.8.8.8\n'));
});
test('collector ties main PID, invocation, cgroup, namespace and supported config graph without setters', async () => {
  const f = fixture(), r = await collectDnsClientOwnership(f.diagnostic, f.deps);
  assert.equal(r.status, 'collected'); assert.equal(r.systemSettingsChanged, false); assert.equal(r.takeoverAuthorized, false);
  assert.equal(r.dnsmasq.status, 'ok'); assert.equal(r.dnsmasq.cgroupMatchesUnit, true);
  assert.deepEqual(r.dnsmasq.namespacesMatch, { net: true, mnt: true, pid: true });
  assert.equal(r.dnsmasq.sourceGraphComplete, true); assert.equal(r.dnsmasq.loadedConfigProven, false);
  assert.deepEqual(Object.keys(r.dnsmasq.configs), ['/etc/dnsmasq.conf', '/etc/dnsmasq.d/usb.conf']);
  assert.equal(r.networkd[0].stable, true); assert.equal(r.networkd[0].selectedConfig.status, 'ok');
  assert.doesNotMatch(JSON.stringify(r), /SECRET|never-print|ExecStart/);
  for (const c of f.commands) {
    assert.deepEqual(c.options.env, DIAGNOSTIC_ENV); assert.equal(c.options.timeoutMs, 3000);
    assert.equal(c.args[2], 'show'); assert.ok(!c.args.some((a) => /^(start|stop|restart|enable|ExecStart|Environment)$/.test(a)));
  }
  assert.ok(!f.reads.some((p) => /environ|shadow|journal/.test(p)));
});
test('non-systemd collector refuses even an exposed host bus or proc namespace', async () => {
  const f = fixture(); f.diagnostic.inspection.environment.pid1 = 'other';
  const r = await collectDnsClientOwnership(f.diagnostic, f.deps);
  assert.equal(r.status, 'not-probed-non-systemd'); assert.equal(f.commands.length + f.reads.length + f.links.length, 0);
});
for (const change of ['invocation', 'pid-token', 'executable', 'proc-permission']) test(`dnsmasq ownership unavailable on ${change}, no raw private diagnostics`, async () => {
  const f = fixture(), run = f.deps.run, read = f.deps.read; let unitCalls = 0, statCalls = 0;
  if (change === 'invocation') f.deps.run = async (...args) => {
    const r = await run(...args); if (args[1][3] === 'dnsmasq.service' && ++unitCalls > 1) r.stdout = r.stdout.replace('a'.repeat(32), 'b'.repeat(32)); return r;
  };
  if (change === 'pid-token') f.deps.read = async (path, n) => path.endsWith('/stat') && ++statCalls > 1 ? statText('124') : read(path, n);
  if (change === 'executable') f.deps.link = async () => '/private/SECRET';
  if (change === 'proc-permission') f.deps.read = async (path, n) => { if (path.endsWith('/cmdline')) throw Object.assign(new Error('SECRET'), { code: 'EACCES' }); return read(path, n); };
  const r = await collectDnsClientOwnership(f.diagnostic, f.deps);
  assert.equal(r.dnsmasq.status, 'unavailable'); assert.doesNotMatch(JSON.stringify(r), /SECRET/);
});
test('inactive dnsmasq never has its cmdline read and no service is started', async () => {
  const f = fixture(); f.units.set('dnsmasq.service', unitText('dnsmasq.service').replace('ActiveState=active', 'ActiveState=inactive'));
  const r = await collectDnsClientOwnership(f.diagnostic, f.deps); assert.equal(r.dnsmasq.status, 'no-active-main-pid');
  assert.ok(!f.reads.some((p) => p.startsWith('/proc/50/')));
});
test('config source outside supported roots, hooks and include loops prevent complete inventory', async () => {
  const f = fixture(); f.files.set('/etc/dnsmasq.conf', 'conf-file=/etc/shadow\nconf-file=/etc/dnsmasq.conf\nconf-script=/private/SECRET\n');
  const r = await collectDnsClientOwnership(f.diagnostic, f.deps);
  assert.equal(r.dnsmasq.sourceGraphComplete, false); assert.ok(!f.reads.includes('/etc/shadow')); assert.doesNotMatch(JSON.stringify(r), /SECRET|shadow/);
});
test('canonical target escape is refused before reading config bytes', async () => {
  const f = fixture(); f.deps.canonical = async (p) => p === '/etc/dnsmasq.conf' ? '/etc/shadow' : p;
  const r = await collectDnsClientOwnership(f.diagnostic, f.deps);
  assert.equal(r.dnsmasq.sourceGraphComplete, false); assert.ok(!f.reads.includes('/etc/dnsmasq.conf') && !f.reads.includes('/etc/shadow'));
});
test('bounded config graph reports truncation, does not silently declare completeness', async () => {
  const f = fixture(); f.deps.list = async () => Array.from({ length: 80 }, (_, i) => `f${i}.conf`);
  const r = await collectDnsClientOwnership(f.diagnostic, f.deps);
  assert.equal(r.dnsmasq.sourceGraphComplete, false); assert.equal(r.dnsmasq.directories[0].truncated, true);
  assert.ok(f.reads.filter((p) => p.startsWith('/etc/dnsmasq.d/')).length <= 32);
});
test('networkd selected file EACCES remains explicit and unchanged state is not enough', async () => {
  const f = fixture(), read = f.deps.read;
  f.deps.read = async (path, n) => { if (path.endsWith('.network')) throw Object.assign(new Error('SECRET'), { code: 'EACCES' }); return read(path, n); };
  const r = await collectDnsClientOwnership(f.diagnostic, f.deps);
  assert.equal(r.networkd[0].selectedConfig.reason, 'EACCES');
  assert.ok(assessClientPreflight('vps2', f.diagnostic, r).observedIssues.includes('eth0-selected-network-file-not-confirmed'));
});
test('networkd runtime selection drift cannot appear stable', async () => {
  const f = fixture(), read = f.deps.read; let calls = 0;
  f.deps.read = async (path, n) => path.includes('/netif/links/') && ++calls > 1 ? 'ADMIN_STATE=pending\n' : read(path, n);
  const r = await collectDnsClientOwnership(f.diagnostic, f.deps); assert.equal(r.networkd[0].stable, false); assert.equal(r.networkd[0].status, 'changed');
});
test('deadline prevents further subprocesses and is reported, not interpreted as ready', async () => {
  const f = fixture(), run = f.deps.run;
  f.deps.run = async (...args) => { await delay(5); return run(...args); };
  const r = await collectDnsClientOwnership(f.diagnostic, { ...f.deps, budgetMs: 1 });
  assert.equal(r.deadlineExceeded, true); assert.equal(f.commands.length, 1);
  assert.ok(assessClientPreflight('radxa', f.diagnostic, r).observedIssues.includes('collection-deadline-exceeded'));
});
test('complete evidence never grants install permission or selects cloud policy', async () => {
  const f = fixture(); f.units.set('dnsmasq.service', unitText('dnsmasq.service').replace('ActiveState=active', 'ActiveState=inactive'));
  const o = await collectDnsClientOwnership(f.diagnostic, f.deps);
  const r = assessClientPreflight('vps2', f.diagnostic, o);
  assert.equal(r.status, 'ready-for-manual-review'); assert.equal(r.installationAllowed, false); assert.equal(r.dnsV1Complete, false);
  assert.ok(r.pendingOperatorDecisions.includes('explicit-cloud-name-policy'));
  assert.ok(r.pendingOperatorDecisions.includes('independent-emergency-access'));
});
test('zero-exit DNS commands with NXDOMAIN or empty output are not healthy baseline evidence', async () => {
  const f = fixture(); f.diagnostic.probes = Array.from({ length: 5 }, () => ({ result: { status: 'ok', stdout: 'status: NXDOMAIN, ANSWER: 0,' } }));
  const r = assessClientPreflight('vps2', f.diagnostic, await collectDnsClientOwnership(f.diagnostic, f.deps));
  assert.ok(r.observedIssues.includes('baseline-probes-incomplete-or-failed'));
});
for (const change of ['namespace', 'cgroup', 'non-root-config', 'group-writable', 'unit-reload']) test(`Radxa assessment requires review for ${change}`, async () => {
  const f = fixture(), link = f.deps.link, stat = f.deps.stat;
  if (change === 'namespace') f.deps.link = async (p) => p === '/proc/50/ns/net' ? 'net:[99]' : link(p);
  if (change === 'cgroup') f.files.set('/proc/50/cgroup', '0::/different.scope\n');
  if (change === 'non-root-config') f.deps.stat = async (...a) => ({ ...await stat(...a), uid: 1000n });
  if (change === 'group-writable') f.deps.stat = async (...a) => ({ ...await stat(...a), mode: 0o100664n });
  if (change === 'unit-reload') f.units.set('dnsmasq.service', unitText('dnsmasq.service').replace('NeedDaemonReload=no', 'NeedDaemonReload=yes'));
  const r = assessClientPreflight('radxa', f.diagnostic, await collectDnsClientOwnership(f.diagnostic, f.deps));
  assert.equal(r.status, 'needs-evidence-or-repair'); assert.equal(r.installationAllowed, false);
});
test('changed config inode invalidates that inventory entry', async () => {
  const f = fixture(), stat = f.deps.stat; let n = 0;
  f.deps.stat = async (p) => ({ ...await stat(p), ...(p === '/etc/dnsmasq.conf' && ++n > 1 ? { ino: 24n } : {}) });
  const r = await collectDnsClientOwnership(f.diagnostic, f.deps);
  assert.equal(r.dnsmasq.configs['/etc/dnsmasq.conf'].status, 'unavailable'); assert.equal(r.dnsmasq.sourceGraphComplete, false);
});
test('Radxa dangling link is a separate repair even when current probes work', async () => {
  const f = fixture(); f.diagnostic.inspection.resolver = { status: 'unavailable', object: 'symlink', targetStatus: 'missing', mountpoint: false };
  f.diagnostic.probes = Array.from({ length: 5 }, () => ({ result: { status: 'ok' } }));
  const r = assessClientPreflight('radxa', f.diagnostic, await collectDnsClientOwnership(f.diagnostic, f.deps));
  assert.ok(r.observedIssues.includes('dangling-resolver-needs-separate-baseline-repair'));
  assert.equal(r.installationAllowed, false);
});
test('one bundle defaults to no probes and remains read-only with explicit probes', async () => {
  for (const probe of [false, true]) {
    const f = fixture(); let observed;
    const r = await collectClientPreflight({ client: 'radxa', probe }, {
      diagnostic: async (options) => { observed = options; return f.diagnostic; }, ownership: (d) => collectDnsClientOwnership(d, f.deps),
    });
    assert.deepEqual(observed, { probe }); assert.equal(r.systemSettingsChanged, false); assert.equal(r.installationAttempted, false);
    assert.equal(r.kind, 'clean-vpn-dns-client-preflight');
  }
});
