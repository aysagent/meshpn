import assert from 'node:assert/strict';
import test from 'node:test';
import { assessLoadedDnsAdapter, parseLoadedDnsAdapterUnit, inspectInstalledDnsAdapter } from './lib/dns-installed-adapter.mjs';
import { compileDnsAdapterServicePlan } from './lib/dns-adapter-service-plan.mjs';
import { parseDnsClientArgs } from './dns-client.mjs';

const input = () => ({ schema: 1, exitIp: '93.184.216.36', exitPort: 443, publicName: 'relay.example', listenPort: 2053, readyName: 'example.com',
  upstream: { schema: 1, transport: 'doh', hostname: 'resolver.example', port: 443, path: '/dns-query', bootstrap: { addresses: ['93.184.216.35'] }, trust: { mode: 'bundled' } },
  domainPolicy: { schema: 1, denySuffixes: ['internal'] } });
const evidence = () => {
  const i = input(), unitText = compileDnsAdapterServicePlan(i).files[0].contents;
  return { config: { adapterPort: i.listenPort, readyName: i.readyName, domainPolicy: i.domainPolicy }, unitText,
    argv: /^ExecStart=(.+)$/m.exec(unitText)[1].replaceAll('${CREDENTIALS_DIRECTORY}', '/run/credentials/clean-vpn-dns-adapter.service').split(' '),
    environment: ['PATH=/usr/bin:/bin', 'CREDENTIALS_DIRECTORY=/run/credentials/clean-vpn-dns-adapter.service'], upstream: i.upstream, domainPolicy: i.domainPolicy };
};
const unit = () => ({ Id: 'clean-vpn-dns-adapter.service', LoadState: 'loaded', ActiveState: 'active', SubState: 'running', MainPID: '111',
  InvocationID: 'a'.repeat(32), NeedDaemonReload: 'no', FragmentPath: '/etc/systemd/system/clean-vpn-dns-adapter.service',
  DropInPaths: '', Type: 'notify', DynamicUser: 'yes', ControlGroup: '/system.slice/clean-vpn-dns-adapter.service' });
const text = (v) => Object.entries(v).map(([k, val]) => `${k}=${val}`).join('\n') + '\n';
test('loaded unit data requires exact service, no dropins/reload and live notify process', () => {
  assert.deepEqual(parseLoadedDnsAdapterUnit(text(unit())), unit());
  for (const k of Object.keys(unit())) { const v = unit(); delete v[k]; assert.throws(() => parseLoadedDnsAdapterUnit(text(v))); }
  for (const [k, value] of Object.entries({ Id: 'other.service', LoadState: 'not-found', ActiveState: 'activating', SubState: 'dead',
    MainPID: '0', InvocationID: '', NeedDaemonReload: 'yes', FragmentPath: '/run/unit', DropInPaths: '/etc/dropin.conf',
    Type: 'simple', DynamicUser: 'no', ControlGroup: '/user.slice/other' })) assert.throws(() => parseLoadedDnsAdapterUnit(text({ ...unit(), [k]: value })));
  assert.throws(() => parseLoadedDnsAdapterUnit(text(unit()) + 'MainPID=111\n'));
});
test('loaded adapter assessment matches exact template and inputs without mutation or credentials in report', () => {
  const e = evidence(), before = structuredClone(e);
  assert.deepEqual(assessLoadedDnsAdapter(e), { templateMatches: true, configurationMatches: true });
  assert.deepEqual(e, before);
});
for (const [name, change] of [
  ['extra argv', (e) => e.argv.push('--other')], ['interpreter', (e) => { e.argv[0] = '/tmp/node'; }],
  ['Node injection', (e) => { e.argv[1] = '--import=/tmp/inject.mjs'; }],
  ['foreign credential path', (e) => { e.argv[3] = '--config=/tmp/upstream.json'; }],
  ['private exit', (e) => { e.argv[6] = '--exit-ip=127.0.0.1'; }],
  ['noncanonical port', (e) => { e.argv[7] = '--exit-port=0443'; }],
  ['listen mismatch', (e) => { e.config.adapterPort++; }], ['ready mismatch', (e) => { e.config.readyName = 'other.test'; }],
  ['policy mismatch', (e) => { e.config = { ...e.config, domainPolicy: { schema: 1, denySuffixes: ['elsewhere.test'] } }; }],
  ['unit drift', (e) => { e.unitText += '# drift\n'; }], ['old loaded exit', (e) => { e.argv[6] = '--exit-ip=8.8.8.8'; }],
  ['credential directory', (e) => { e.environment[1] = 'CREDENTIALS_DIRECTORY=/tmp'; }],
  ['duplicate environment', (e) => { e.environment.push(e.environment[0]); }],
  ['runtime environment injection', (e) => { e.environment.push('NODE_OPTIONS=--import=/tmp/code'); }],
]) test(`loaded adapter refuses ${name}`, () => { const e = evidence(); change(e); assert.throws(() => assessLoadedDnsAdapter(e)); });
test('adapter OS collector rejects forged authority before system operations', async () => {
  for (const token of [{}, null, { installedAuthorityVerified: true }]) await assert.rejects(inspectInstalledDnsAdapter(token), /installed authority token required/);
  assert.equal(parseDnsClientArgs(['--inspect-adapter']), 'inspect-adapter');
  assert.throws(() => parseDnsClientArgs(['--inspect-adapter', '--start']));
});
