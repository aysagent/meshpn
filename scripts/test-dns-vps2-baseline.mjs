import assert from 'node:assert/strict';
import test from 'node:test';
import { validateVps2DnsConfig, assessVps2DnsBaseline } from './lib/dns-vps2-baseline.mjs';
import { inspectInstalledVps2Dns, validateVps2DnsUnit, validateReleasedDnsManagerUnit } from './lib/dns-installed-vps2.mjs';
import { DNS_NETWORKD_CONTENTS } from './lib/dns-networkd-policy.mjs';

const config = () => ({ schema: 1, kind: 'clean-vpn-dns-client', client: 'vps2', uplink: 'eth0',
  networkFile: { path: '/run/systemd/network/10-netplan-eth0.network', sha256: 'a'.repeat(64) },
  adapterPort: 2053, readyName: 'example.com', domainPolicy: { schema: 1, denySuffixes: ['auto.internal', 'ru-central1.internal'] } });
const evidence = () => ({ resolverTarget: '/run/systemd/resolve/stub-resolv.conf',
  resolverText: '# managed by systemd-resolved\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch auto.internal ru-central1.internal\n',
  nssText: 'passwd: files\nhosts: files dns # conventional stub\n',
  addresses: [{ ifindex: 1, ifname: 'lo', flags: ['UP'], addr_info: [{ family: 'inet', local: '127.0.0.1', scope: 'host' }] },
    { ifindex: 2, ifname: 'eth0', flags: ['UP'], addr_info: [{ family: 'inet', local: '10.129.0.18', scope: 'global' }] }],
  routes4: [{ dst: 'default', dev: 'eth0' }, { dst: '10.129.0.0/24', dev: 'eth0' }, { dst: '127.0.0.1', type: 'local', dev: 'lo' }],
  networkState: 'NETWORK_FILE=/run/systemd/network/10-netplan-eth0.network\nADMIN_STATE=configured\nDOMAINS=auto.internal ru-central1.internal\n',
  networkFileSha256: 'a'.repeat(64), adapterDomainPolicy: config().domainPolicy,
  networkdExclusion: DNS_NETWORKD_CONTENTS,
  manager: { DNSEx: [[2, 2, [10, 129, 0, 2], 0, '']], FallbackDNSEx: [],
    Domains: [[2, 'auto.internal', false], [2, 'ru-central1.internal', false]], ResolvConfMode: 'stub' } });
test('strict VPS2 config has no implicit cloud policy, backend, uplink or paths', () => {
  const c = config(); assert.deepEqual(validateVps2DnsConfig(c), c);
  for (const field of Object.keys(c)) { const v = config(); delete v[field]; assert.throws(() => validateVps2DnsConfig(v)); }
  for (const patch of [{ client: 'radxa' }, { schema: 2 }, { extra: true }, { uplink: 'lo' }, { uplink: 'cvdns12345678' },
    { uplink: '../../eth0' }, { adapterPort: 53 }, { adapterPort: '2053' }, { readyName: 'EXAMPLE.COM' },
    { readyName: 'auto.internal' }, { networkFile: { path: '/tmp/a.network', sha256: 'a'.repeat(64) } },
    { networkFile: { path: c.networkFile.path, sha256: 'A'.repeat(64) } }, { domainPolicy: { schema: 1, denySuffixes: [] } },
    { domainPolicy: { schema: 1, denySuffixes: ['Auto.internal.'] } }]) assert.throws(() => validateVps2DnsConfig({ ...config(), ...patch }));
});
test('baseline validates known input without mutating it or granting activation authority', () => {
  const c = config(), e = evidence(), before = structuredClone({ c, e });
  const report = assessVps2DnsBaseline(c, e);
  assert.equal(report.baselineChecksPassed, true); assert.equal(report.activationAuthorized, false);
  assert.equal(report.systemSettingsChanged, false); assert.equal(report.dnsQueriesSent, 0);
  assert.deepEqual({ c, e }, before);
});
for (const [name, change] of [
  ['foreign resolver target', (e) => { e.resolverTarget = '/etc/resolv.conf'; }],
  ['open resolver fallback', (e) => { e.resolverText += 'nameserver 1.1.1.1\n'; }],
  ['duplicate stub', (e) => { e.resolverText += 'nameserver 127.0.0.53\n'; }],
  ['unknown search domain', (e) => { e.resolverText += 'search other.internal\n'; }],
  ['unknown resolver option', (e) => { e.resolverText += 'options rotate\n'; }],
  ['additional NSS resolver', (e) => { e.nssText = 'hosts: files resolve dns'; }],
  ['NSS duplicate', (e) => { e.nssText += 'hosts: files dns\n'; }],
  ['existing DNS link', (e) => { e.addresses.push({ ifname: 'cvdns12345678', ifindex: 3, addr_info: [] }); }],
  ['duplicate link name', (e) => { e.addresses.push({ ...e.addresses[1], ifindex: 3 }); }],
  ['duplicate link index', (e) => { e.addresses.push({ ...e.addresses[1], ifname: 'other' }); }],
  ['address collision', (e) => { e.addresses[1].addr_info.push({ family: 'inet', local: '192.0.2.1' }); }],
  ['uplink down', (e) => { e.addresses[1].flags = []; }],
  ['no IPv4 uplink', (e) => { e.addresses[1].addr_info = []; }],
  ['missing default route', (e) => { e.routes4.shift(); }],
  ['networkd selected file changed', (e) => { e.networkState = e.networkState.replace('10-netplan-eth0', '20-other'); }],
  ['networkd not configured', (e) => { e.networkState = e.networkState.replace('configured', 'configuring'); }],
  ['network file bytes changed', (e) => { e.networkFileSha256 = 'b'.repeat(64); }],
  ['missing networkd exclusion', (e) => { delete e.networkdExclusion; }],
  ['changed networkd exclusion', (e) => { e.networkdExclusion = DNS_NETWORKD_CONTENTS.replace('Unmanaged=yes', 'Unmanaged=no'); }],
  ['new DHCP domain', (e) => { e.networkState = e.networkState.replace('DOMAINS=', 'DOMAINS=other.internal '); }],
  ['DHCP catch-all', (e) => { e.networkState += 'ROUTE_DOMAINS=.\n'; }],
  ['adapter policy mismatch', (e) => { e.adapterDomainPolicy.denySuffixes.pop(); }],
  ['resolved global DNS', (e) => { e.manager.DNSEx[0][0] = 0; }],
  ['another link DNS', (e) => { e.manager.DNSEx[0][0] = 3; }],
  ['resolved malformed DNS', (e) => { e.manager.DNSEx[0][2] = [999, 1, 1, 1]; }],
  ['empty DNS baseline', (e) => { e.manager.DNSEx = []; }],
  ['resolved fallback DNS', (e) => { e.manager.FallbackDNSEx = [[2, [8, 8, 8, 8], 0, '']]; }],
  ['foreign resolved domain', (e) => { e.manager.Domains.push([2, 'other.internal', false]); }],
  ['resolved catch-all route', (e) => { e.manager.Domains.push([2, '.', true]); }],
  ['non-stub mode', (e) => { e.manager.ResolvConfMode = 'foreign'; }],
]) test(`baseline refuses ${name}`, () => {
  const e = evidence(); change(e); assert.throws(() => assessVps2DnsBaseline(config(), e));
});
test('reserved address conflict includes covering routes in any table, including blackholes', () => {
  for (const dst of ['192.0.2.1', '192.0.2.1/32', '192.0.2.0/24', '192.0.0.0/16', '128.0.0.0/1']) {
    const e = evidence(); e.routes4.push({ dst, table: 800, type: 'blackhole' }); assert.throws(() => assessVps2DnsBaseline(config(), e));
  }
  for (const dst of ['192.0.2.2/32', '192.0.3.0/24', '0.0.0.0/0']) {
    const e = evidence(); e.routes4.push({ dst }); assert.equal(assessVps2DnsBaseline(config(), e).baselineChecksPassed, true);
  }
  for (const dst of ['bad', undefined, '192.0.2.1/99', '192.0.2.1/032', '192.0.2.1/32/junk']) {
    const e = evidence(); e.routes4.push({ dst }); assert.throws(() => assessVps2DnsBaseline(config(), e));
  }
});
test('DHCP domain removal is allowed; explicit adapter denial remains independent of DHCP', () => {
  const e = evidence(); e.networkState = e.networkState.split('DOMAINS=')[0]; e.manager.Domains = [];
  assert.equal(assessVps2DnsBaseline(config(), e).baselineChecksPassed, true);
  e.manager.Domains = [[2, 'child.auto.internal', true]];
  assert.equal(assessVps2DnsBaseline(config(), e).baselineChecksPassed, true);
});
const unit = (name = 'systemd-resolved') => `Id=${name}.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=42\nInvocationID=${'a'.repeat(32)}\nNeedDaemonReload=no\n`;
test('unit evidence binds service invocation and MainPID to unique D-Bus peer', () => {
  for (const name of ['systemd-resolved', 'systemd-networkd']) assert.equal(validateVps2DnsUnit(unit(name), name, 42).MainPID, '42');
  for (const text of [unit().replace('active', 'inactive'), unit().replace('running', 'dead'), unit().replace('=no', '=yes'),
    unit().replace('MainPID=42', 'MainPID=043'), unit().replace('InvocationID=', 'Unknown='), unit() + 'MainPID=42\n',
    unit().replace('NeedDaemonReload=no\n', '')]) assert.throws(() => validateVps2DnsUnit(text, 'systemd-resolved', 42));
  assert.throws(() => validateVps2DnsUnit(unit(), 'systemd-resolved', 43));
});
test('installed collector rejects fake tokens before executing any system commands', async () => {
  for (const token of [{}, null, config(), evidence()]) await assert.rejects(inspectInstalledVps2Dns(token), /token required/);
});
test('quiescent manager evidence reports pending reload without authorizing an active baseline', () => {
  const pending = unit().replace('NeedDaemonReload=no', 'NeedDaemonReload=yes');
  assert.equal(validateReleasedDnsManagerUnit(pending, 'systemd-resolved', 42).NeedDaemonReload, 'yes');
  assert.throws(() => validateVps2DnsUnit(pending, 'systemd-resolved', 42));
  for (const text of [pending.replace('=yes', '=unknown'), pending.replace('active', 'inactive'),
    pending.replace('running', 'dead'), pending.replace('MainPID=42', 'MainPID=43')])
    assert.throws(() => validateReleasedDnsManagerUnit(text, 'systemd-resolved', 42));
});
