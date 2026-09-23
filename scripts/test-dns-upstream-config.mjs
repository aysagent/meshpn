import assert from 'node:assert/strict';
import test from 'node:test';
import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import https from 'node:https';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, writeFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileDnsUpstream, compileLabDnsUpstream, parseDnsUpstream, dnsUpstreamTlsOptions,
  dnsUpstreamSummary, labDnsUpstreamTarget } from './lib/dns-upstream-config.mjs';
import { startTransparentDnsLab, queryLabDns } from './lib/transparent-dns-lab.mjs';
import { startLabDohStub } from './lib/lab-doh-stub.mjs';
import { makeDnsQuery, validateDnsResponse } from './lib/lab-dns-wire.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

const cert = readFileSync(new URL('./fixtures/boring-tls-local.cert.pem', import.meta.url), 'utf8');
const config = () => ({ schema: 1, transport: 'doh', hostname: 'Resolver.Example', port: 443, path: '/dns-query',
  bootstrap: { addresses: ['93.184.216.34', '2606:4700::1111'] }, trust: { mode: 'bundled' } });
const labConfig = () => ({ ...config(), hostname: 'localhost', bootstrap: { addresses: ['127.0.0.1'] },
  trust: { mode: 'custom', certificates: [cert] } });
const invalid = (value) => assert.throws(() => compileDnsUpstream(value), { code: 'DNS_UPSTREAM_CONFIG', message: 'DNS_UPSTREAM_CONFIG' });

test('offline public contract separates immutable numeric candidates and TLS identity', () => {
  const input = config(), profile = compileDnsUpstream(input);
  assert.equal(profile.hostname, 'resolver.example'); assert.equal(profile.authority, 'resolver.example');
  assert.deepEqual(profile.addresses, [{ address: '93.184.216.34', family: 4, port: 443 }, { address: '2606:4700::1111', family: 6, port: 443 }]);
  input.bootstrap.addresses[0] = '127.0.0.1'; input.hostname = 'evil.example';
  assert.equal(profile.hostname, 'resolver.example'); assert.equal(profile.addresses[0].address, '93.184.216.34');
  for (const value of [profile, profile.addresses, ...profile.addresses, profile.trust, profile.ca]) assert.ok(Object.isFrozen(value));
  const options = dnsUpstreamTlsOptions(profile);
  assert.equal(options.servername, 'resolver.example'); assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.minVersion, 'TLSv1.3'); assert.deepEqual(options.ca, tls.rootCertificates);
  options.ca.length = 0; assert.ok(dnsUpstreamTlsOptions(profile).ca.length > 0);
  assert.equal('host' in options, false); assert.equal('port' in options, false);
});
test('IPv6 equivalent addresses deduplicate without reordering or DNS', () => {
  const input = config(); input.bootstrap.addresses.push('2606:4700:0:0:0:0:0:1111', '93.184.216.34');
  assert.equal(compileDnsUpstream(input).addresses.length, 2);
});
for (const name of ['localhost', 'singlelabel', '127.0.0.1', '2130706433', '0x7f.0.0.1', 'a.local', 'a.home.arpa',
  'a.internal', 'dns.example.', '-dns.example', 'a..example', 'https://dns.example', 'dns.example:443', '*.example', 'днс.example', 'bad\r\nHost: x']) {
  test(`reject invalid TLS hostname ${JSON.stringify(name)}`, () => invalid({ ...config(), hostname: name }));
}
for (const address of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '192.0.2.1', '::1', 'fc00::1', '2001:db8::1',
  '::ffff:93.184.216.34', 'fe80::1%eth0', 'resolver.example', '0177.0.0.1']) {
  test(`reject entire mixed bootstrap set containing ${address}`, () => {
    const input = config(); input.bootstrap.addresses.push(address); invalid(input);
  });
}
for (const [name, change] of [
  ['missing addresses', (c) => { c.bootstrap.addresses = []; }],
  ['too many addresses', (c) => { c.bootstrap.addresses = Array(9).fill('93.184.216.34'); }],
  ['sparse addresses', (c) => { c.bootstrap.addresses = Array(2); }],
  ['DNS bootstrap', (c) => { c.bootstrap.lookup = true; }],
  ['allowPrivate', (c) => { c.allowPrivate = true; }], ['fallback', (c) => { c.fallback = 'system'; }],
  ['TLS bypass', (c) => { c.rejectUnauthorized = false; }], ['Host override', (c) => { c.authority = 'evil.example'; }],
  ['transport downgrade', (c) => { c.transport = 'dns'; }], ['version', (c) => { c.schema = 2; }],
  ['port type', (c) => { c.port = '443'; }], ['port zero', (c) => { c.port = 0; }],
  ['unknown trust', (c) => { c.trust = { mode: 'system' }; }], ['extra CA with bundled', (c) => { c.trust.certificates = [cert]; }],
  ['empty custom CA', (c) => { c.trust = { mode: 'custom', certificates: [] }; }],
  ['malformed PEM', (c) => { c.trust = { mode: 'custom', certificates: ['-----BEGIN CERTIFICATE-----\nnotacert\n-----END CERTIFICATE-----'] }; }],
  ['key in CA', (c) => { c.trust = { mode: 'custom', certificates: [cert + '\n-----BEGIN PRIVATE KEY-----\nsecret'] }; }],
  ['multiple certs in item', (c) => { c.trust = { mode: 'custom', certificates: [cert + cert] }; }],
]) test(`configuration fails closed: ${name}`, () => { const input = config(); change(input); invalid(input); });
for (const path of ['http://resolver.example/dns-query', '//evil/dns', '/dns?token=secret', '/dns#fragment', '/%64ns', '/a/../dns', '/dns\r\nHost:bad']) {
  test(`reject unsafe HTTP path ${JSON.stringify(path)}`, () => invalid({ ...config(), path }));
}
test('custom trust is CA-only, deduplicated and replaces bundled trust', () => {
  const input = config(); input.trust = { mode: 'custom', certificates: [cert, cert] };
  const profile = compileDnsUpstream(input); assert.equal(profile.ca.length, 1);
  assert.equal(profile.trust.fingerprints.length, 1); input.trust.certificates.length = 0;
  assert.equal(dnsUpstreamTlsOptions(profile).ca.length, 1);
});
test('TLS checks the configured name even when caller passes a different host', () => {
  const options = dnsUpstreamTlsOptions(compileLabDnsUpstream(labConfig()));
  assert.equal(options.checkServerIdentity('ignored.example', new X509Certificate(cert).toLegacyObject()), undefined);
  const other = compileLabDnsUpstream({ ...labConfig(), hostname: 'wrong-name.test' });
  assert.ok(dnsUpstreamTlsOptions(other).checkServerIdentity('localhost', new X509Certificate(cert).toLegacyObject()));
});
test('unbranded objects and public profiles cannot activate lab target', () => {
  assert.throws(() => dnsUpstreamTlsOptions({ ...compileDnsUpstream(config()) }));
  assert.throws(() => labDnsUpstreamTarget(compileDnsUpstream(config()), 12345));
  for (const ip of ['127.0.0.2', '::1', '93.184.216.34']) assert.throws(() => compileLabDnsUpstream({ ...labConfig(), bootstrap: { addresses: [ip] } }));
  invalid(labConfig());
});
test('offline compiler performs no DNS, TCP, TLS or HTTP I/O', (t) => {
  const forbidden = () => { throw new Error('NETWORK_FORBIDDEN'); };
  for (const [object, methods] of [[dns, ['lookup', 'resolve']], [dnsPromises, ['lookup', 'resolve']],
    [net, ['connect']], [tls, ['connect']], [https, ['request']]]) for (const method of methods) t.mock.method(object, method, forbidden);
  assert.equal(parseDnsUpstream(JSON.stringify(config())).scope, 'public-contract');
  const summary = dnsUpstreamSummary(compileDnsUpstream(config()));
  assert.equal(summary.runtimeEnabled, false); assert.equal(summary.status, 'validated-offline');
  assert.ok(!JSON.stringify(summary).includes('resolver.example'));
});
test('JSON errors and size limits are redacted; unknown keys are rejected', () => {
  for (const text of ['{"secret":"sensitive"', ' '.repeat(128 * 1024 + 1), 'null', '[]', '{"__proto__":{}}']) {
    assert.throws(() => parseDnsUpstream(text), { code: 'DNS_UPSTREAM_CONFIG', message: 'DNS_UPSTREAM_CONFIG' });
  }
});
test('duplicate JSON keys, including escaped equivalents, cannot silently override settings', () => {
  const text = JSON.stringify(config());
  for (const modified of [text.replace('"schema":1', '"schema":0,"schema":1'),
    text.replace('"mode":"bundled"', '"mode":"custom","m\\u006fde":"bundled"')]) {
    assert.throws(() => parseDnsUpstream(modified), { code: 'DNS_UPSTREAM_CONFIG' });
  }
  assert.equal(parseDnsUpstream(text).hostname, 'resolver.example');
});

for (const [name, change, rcode] of [
  ['custom CA and non-default HTTPS authority/path', (c) => { c.port = 8443; c.path = '/operator/dns'; }, 0],
  ['untrusted certificate', (c) => { c.trust = { mode: 'bundled' }; }, 2],
  ['wrong TLS hostname', (c) => { c.hostname = 'wrong-name.test'; }, 2],
]) test(`profile over actual relay: ${name}`, async (t) => {
  const input = labConfig(); change(input);
  const lab = await startTransparentDnsLab({ upstreamConfig: input });
  t.after(async () => { await lab.close(); assert.equal(lab.stats().stub.timers, 0); assert.equal(lab.relay.stats().sockets, 0); });
  input.hostname = 'mutated.example'; input.trust = { mode: 'bundled' };
  for (const tcp of [false, true]) {
    const query = makeDnsQuery('profile-check.dns-lab.test', tcp ? 28 : 1);
    assert.equal(validateDnsResponse(await queryLabDns(lab.stub.port, query, { tcp }), query).flags & 15, rcode);
  }
  assert.equal(lab.stats().resolverRequests, rcode === 0 ? 2 : 0);
  assert.equal(lab.relay.captures.find((x) => x.stage === 'origin').sni, rcode === 2 && name === 'wrong TLS hostname' ? 'wrong-name.test' : 'localhost');
});
test('profile cannot be mixed with legacy overrides or point lab at public IP', async () => {
  await assert.rejects(startTransparentDnsLab({ upstreamConfig: config() }));
  await assert.rejects(startTransparentDnsLab({ upstreamConfig: labConfig(), ca: [] }));
  await assert.rejects(startLabDohStub({ profile: compileLabDnsUpstream(labConfig()), relayPort: 12345, upstream: {} }));
});
test('offline CLI validates without revealing configuration and fails closed on unsafe files/options', { timeout: 10000 }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-dns-config-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'config.json'), link = join(dir, 'link.json');
  await writeFile(file, JSON.stringify(config())); await symlink(file, link);
  const run = (args) => runCommand(process.execPath, ['scripts/dns-upstream-check.mjs', ...args], { env: cleanEnvironment(process.env) });
  const passed = await run([`--config=${file}`]); assert.equal(passed.code, 0); assert.ok(passed.stdout.includes('validated-offline'));
  assert.ok(!passed.stdout.includes('Resolver')); assert.ok(!passed.stdout.includes('93.184'));
  for (const args of [[`--config=${link}`], [`--config=${dir}`], ['--serve'], [`--config=${file}`, '--allow-private'], []]) {
    const result = await run(args); assert.notEqual(result.code, 0); assert.equal(result.stderr.trim(), 'DNS_UPSTREAM_CONFIG_INVALID');
  }
  await writeFile(file, 'sensitive invalid text'); const rejected = await run([`--config=${file}`]);
  assert.notEqual(rejected.code, 0); assert.ok(!rejected.stderr.includes('sensitive'));
});
