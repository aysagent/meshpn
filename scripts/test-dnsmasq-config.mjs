import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { filterDnsmasqDiagnostic } from './lib/dnsmasq-config.mjs';
import { compileRadxaDnsmasqLabConfig } from './lib/dnsmasq-lab-config.mjs';

const baseline = await readFile(new URL('./fixtures/dns-clients/radxa-dnsmasq.conf', import.meta.url), 'utf8');
test('diagnostic keeps hash port syntax, flags, DHCP DNS/router; omits scripts, secrets and quoted fields', () => {
  const result = filterDnsmasqDiagnostic('server=127.0.0.1#1053\nno-resolv\n# comment-secret\n'
    + 'dhcp-option=option:dns-server,192.168.7.1\ndhcp-option=252,secret-value\ndhcp-script=secret-script\n'
    + 'server="secret"\nconf-file=/etc/secret\ninvalid private text\n');
  assert.deepEqual(result.entries, [{ key: 'server', value: '127.0.0.1#1053' }, { key: 'no-resolv' },
    { key: 'dhcp-option', value: 'option:dns-server,192.168.7.1' }, { key: 'conf-file', value: '[not-followed]' }]);
  assert.equal(result.omitted, 3); assert.equal(result.unparsed, 1);
  assert.doesNotMatch(JSON.stringify(result), /secret/);
});
test('Radxa fixture replaces both upstreams, explicitly normalizes DHCP DNS and retains exact baseline', () => {
  const plan = compileRadxaDnsmasqLabConfig(baseline, { port: 1053, normalizeDhcpDns: true });
  assert.equal(plan.baseline, baseline); assert.equal(plan.hostChangesAllowed, false);
  const result = filterDnsmasqDiagnostic(plan.managed).entries;
  assert.deepEqual(result.filter((e) => e.key === 'server'), [{ key: 'server', value: '127.0.0.1#1053' }]);
  assert.deepEqual(result.filter((e) => e.key === 'dhcp-option'), [
    { key: 'dhcp-option', value: '3,192.168.7.1' }, { key: 'dhcp-option', value: '6,192.168.7.1' }]);
  assert.match(plan.managed, /dhcp-range=192.168.7.10,192.168.7.50,255.255.255.0,12h/);
  assert.match(plan.managed, /no-resolv/);
});
test('fixture normalization and high-port choice are explicit; no implicit operator permission', () => {
  assert.throws(() => compileRadxaDnsmasqLabConfig(baseline, { port: 1053 }), /explicit/);
  for (const port of [53, 0, 1023, 65536, '1053', NaN]) assert.throws(() =>
    compileRadxaDnsmasqLabConfig(baseline, { port, normalizeDhcpDns: true }));
});
test('fixture compiler refuses extra sources, execution hooks, malformed and unrecognized configs', () => {
  for (const extra of ['conf-file=/etc/other', 'conf-dir=/etc/dnsmasq.d', 'resolv-file=/etc/resolv.conf',
    'servers-file=/etc/upstreams', 'conf-script=/bin/false', 'dhcp-script=/bin/false',
    'server=127.0.0.1#53', 'listen-address=0.0.0.0', 'no-resolv=secret', 'invalid syntax']) {
    assert.throws(() => compileRadxaDnsmasqLabConfig(`${baseline}\n${extra}\n`, { port: 1053, normalizeDhcpDns: true }));
  }
});
test('lab CLI refuses host execution of worker and unknown options before mutation', () => {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.startsWith('MESHPN_PARENT_')) delete env[key];
  for (const args of [['--apply'], ['--isolated'], ['--help', '--apply']]) {
    const result = spawnSync(process.execPath, ['scripts/dnsmasq-lab.mjs', ...args], { env, encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 1); assert.equal(result.stdout, '');
  }
});
