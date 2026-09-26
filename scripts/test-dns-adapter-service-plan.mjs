import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, symlink, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import dns from 'node:dns';
import net from 'node:net';
import tls from 'node:tls';
import { compileDnsAdapterServicePlan, readDnsAdapterServicePlan } from './lib/dns-adapter-service-plan.mjs';
import { parseDnsExitArgs } from './dns-exit-adapter.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

const config = () => ({ schema: 1, exitIp: '93.184.216.36', exitPort: 443, publicName: 'Relay.Example',
  listenPort: 1053, readyName: 'Example.com',
  upstream: { schema: 1, transport: 'doh', hostname: 'resolver.example', port: 443, path: '/dns-query',
    bootstrap: { addresses: ['93.184.216.35'] }, trust: { mode: 'bundled' } },
  domainPolicy: { schema: 1, denySuffixes: ['internal', 'home.arpa'] } });
const invalid = (c) => assert.throws(() => compileDnsAdapterServicePlan(c), { message: 'DNS_SERVICE_PLAN_INVALID', code: 'DNS_SERVICE_PLAN_INVALID' });

test('offline service plan has exact artifacts, stable digests, no install permission or network', (t) => {
  for (const [o, n] of [[dns, 'lookup'], [dns, 'resolve'], [net, 'connect'], [tls, 'connect']]) {
    t.mock.method(o, n, () => assert.fail('offline renderer attempted network'));
  }
  const c = config(), p = compileDnsAdapterServicePlan(c);
  assert.equal(p.installationAllowed, false); assert.equal(p.systemSettingsChanged, false); assert.equal(p.dnsQueriesSent, 0);
  assert.deepEqual(p, compileDnsAdapterServicePlan(c));
  assert.deepEqual(p.files.map((f) => [f.path, f.mode]), [
    ['/etc/systemd/system/clean-vpn-dns-adapter.service', '0644'],
    ['/etc/clean-vpn/dns/upstream.json', '0600'], ['/etc/clean-vpn/dns/domains.json', '0600']]);
  for (const f of p.files) assert.equal(f.sha256, createHash('sha256').update(f.contents).digest('hex'));
  assert.deepEqual(JSON.parse(p.files[1].contents), c.upstream); assert.deepEqual(JSON.parse(p.files[2].contents), c.domainPolicy);
  c.domainPolicy.denySuffixes[0] = 'changed.test'; assert.ok(!JSON.stringify(p).includes('changed.test'));
});
test('unit uses credentials, unprivileged identity, explicit readiness and mandatory guard; no shell, enable or rollback hooks', () => {
  const unit = compileDnsAdapterServicePlan(config()).files[0].contents;
  for (const line of ['Type=notify', 'NotifyAccess=all', 'DynamicUser=yes', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=',
    'BindsTo=clean-vpn-dns-guard.service', 'After=network-online.target clean-vpn-dns-guard.service',
    'ProtectSystem=strict', 'ProtectHome=yes', 'Restart=no', 'LimitCORE=0']) assert.ok(unit.split('\n').includes(line), line);
  assert.equal((unit.match(/^LoadCredential=/gm) ?? []).length, 3);
  for (const word of ['[Install]', 'ExecStop=', 'ExecStartPre=', 'SetCredential=', '%d', '/bin/sh', 'MemoryDenyWriteExecute=']) assert.ok(!unit.includes(word), word);
  const command = /^ExecStart=(.+)$/m.exec(unit)[1];
  const args = command.split(' ').slice(3).map((a) => a.replace('${CREDENTIALS_DIRECTORY}', '/run/credentials/clean-vpn-dns-adapter.service'));
  const parsed = parseDnsExitArgs(args);
  assert.equal(parsed['ready-name'], 'example.com'); assert.equal(parsed['public-name'], 'relay.example');
  assert.equal(parsed['systemd-notify'], true); assert.match(parsed['shared-hmac-key'], /\/hmac.key$/);
});
test('IPv6 exit remains one literal CLI argument', () => {
  const p = compileDnsAdapterServicePlan({ ...config(), exitIp: '2606:4700::1111' });
  assert.ok(p.files[0].contents.includes('--exit-ip=2606:4700::1111 '));
});
for (const [label, change] of [
  ['unknown option', (c) => { c.apply = true; }], ['schema', (c) => { c.schema = 2; }],
  ['PSK field', (c) => { c.secret = 'DO_NOT_PRINT_SECRET'; }], ['root override', (c) => { c.user = 'root'; }],
  ['private exit', (c) => { c.exitIp = '10.0.0.1'; }], ['DNS exit', (c) => { c.exitIp = 'exit.example'; }],
  ['IPv6 zone', (c) => { c.exitIp = '2606:4700::1111%eth0'; }],
  ['newline', (c) => { c.publicName = 'relay.example\nExecStart=/bin/sh'; }],
  ['specifier', (c) => { c.publicName = '%n.example'; }], ['env', (c) => { c.readyName = '${HOME}.example'; }],
  ['port string', (c) => { c.exitPort = '443'; }], ['port overflow', (c) => { c.exitPort = 65536; }],
  ['privileged listener', (c) => { c.listenPort = 53; }], ['missing ready', (c) => { delete c.readyName; }],
  ['policy absent', (c) => { delete c.domainPolicy; }], ['policy null', (c) => { c.domainPolicy = null; }],
  ['denied ready', (c) => { c.domainPolicy.denySuffixes.push('example.com'); }],
  ['direct fallback', (c) => { c.upstream.fallback = 'system'; }],
  ['unverified TLS', (c) => { c.upstream.rejectUnauthorized = false; }],
  ['private resolver', (c) => { c.upstream.bootstrap.addresses = ['127.0.0.1']; }],
  ['oversized policy artifact', (c) => { c.domainPolicy.denySuffixes = Array.from({ length: 128 }, (_, i) => `${'a'.repeat(63)}.${'b'.repeat(63)}.${i}.example`); }],
]) test(`service plan refuses ${label}`, () => { const c = config(); change(c); invalid(c); });

test('bounded reader and CLI are read-only, reject bad files/flags, never print secret input in errors', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-service-plan-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'input.json'), body = JSON.stringify(config()); await writeFile(path, body);
  assert.equal((await readDnsAdapterServicePlan(path)).mode, 'offline-render');
  const ok = await runCommand(process.execPath, ['scripts/dns-adapter-service-plan.mjs', `--config=${path}`], { env: cleanEnvironment(process.env) });
  assert.equal(ok.code, 0); assert.deepEqual(JSON.parse(ok.stdout), compileDnsAdapterServicePlan(config()));
  assert.equal(await readFile(path, 'utf8'), body);
  await symlink(path, join(dir, 'link')); await assert.rejects(readDnsAdapterServicePlan(join(dir, 'link')), { code: 'DNS_SERVICE_PLAN_INVALID' });
  await assert.rejects(readDnsAdapterServicePlan(dir), { code: 'DNS_SERVICE_PLAN_INVALID' });
  for (const bytes of [Buffer.alloc(131073), Buffer.from([0xff]), Buffer.from('{"secret":"DO_NOT_PRINT_SECRET"}')]) {
    await writeFile(path, bytes); await assert.rejects(readDnsAdapterServicePlan(path), { code: 'DNS_SERVICE_PLAN_INVALID' });
  }
  for (const args of [[], ['--apply'], [`--config=${path}`], [`--config=${path}`, '--apply'], ['--help', '--apply']]) {
    const r = await runCommand(process.execPath, ['scripts/dns-adapter-service-plan.mjs', ...args], { env: cleanEnvironment(process.env) });
    assert.equal(r.code, 1); assert.equal(r.stdout, ''); assert.equal(r.stderr.trim(), 'DNS_SERVICE_PLAN_INVALID');
  }
  const help = await runCommand(process.execPath, ['scripts/dns-adapter-service-plan.mjs', '--help']);
  assert.equal(help.code, 0); assert.match(help.stdout, /Offline JSON plan only/);
});
