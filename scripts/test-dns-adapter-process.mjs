import assert from 'node:assert/strict';
import test from 'node:test';
import { createNamespaceDnsAdapter, validateAdapterProcessConfig } from './lib/dns-adapter-process.mjs';
import { assertProcessAdapterIdle } from './lib/dns-adapter-crash-lab.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

const config = () => ({ port: 1053, secretHex: 'ab'.repeat(32), publicName: 'relay.test', exitAddress: '93.184.216.36', exitPort: 443,
  profile: { schema: 1, transport: 'doh', hostname: 'resolver.test', port: 443, path: '/dns-query',
    bootstrap: { addresses: ['93.184.216.35'] }, trust: { mode: 'bundled' } } });
test('private adapter config accepts pinned public IPv4/IPv6 and does not mutate input', () => {
  for (const address of ['93.184.216.36', '2606:4700::1113']) {
    const value = config(); value.exitAddress = address; const before = structuredClone(value);
    assert.ok(validateAdapterProcessConfig(value)); assert.deepEqual(value, before);
  }
});
for (const [name, mutate] of [
  ['port zero', (c) => { c.port = 0; }], ['privileged port', (c) => { c.port = 53; }],
  ['port overflow', (c) => { c.port = 65536; }], ['fractional port', (c) => { c.port = 1053.5; }],
  ['exit hostname', (c) => { c.exitAddress = 'exit.test'; }], ['private exit', (c) => { c.exitAddress = '127.0.0.1'; }],
  ['zero exit port', (c) => { c.exitPort = 0; }], ['invalid cover', (c) => { c.publicName = 'bad name.test'; }],
  ['empty secret', (c) => { c.secretHex = ''; }], ['nonhex secret', (c) => { c.secretHex = 'z'.repeat(64); }],
  ['unknown field', (c) => { c.hostDns = true; }], ['implicit bootstrap', (c) => { delete c.profile.bootstrap; }],
  ['untrusted scope', (c) => { c.profile.bootstrap.addresses = ['127.0.0.1']; }],
  ['oversized config', (c) => { c.profile.path = `/${'x'.repeat(16000)}`; }],
]) test(`private adapter config rejects ${name}`, () => {
  const value = config(); mutate(value); assert.throws(() => validateAdapterProcessConfig(value));
});
test('namespace adapter launcher refuses the host before starting a process', async () => {
  await assert.rejects(createNamespaceDnsAdapter(config()));
});
test('private adapter worker refuses standalone host execution without exposing config', async () => {
  const result = await runCommand(process.execPath, ['scripts/lib/dns-adapter-process-worker.mjs'], { env: cleanEnvironment(process.env) });
  assert.equal(result.code, 2); assert.equal(result.reason, null); assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'DNS_ADAPTER_WORKER_REFUSED\n');
});
const snapshot = () => ({ owned: { stub: { inflight: 0, tcpSockets: 0, tlsSockets: 0, requests: 0, jobs: 0, timers: 0 },
  transport: { sockets: 0, jobs: 0 } }, resources: { fds: 20, rss: 64 * 1048576 } });
test('process idle check requires a fresh, bounded snapshot', () => {
  assertProcessAdapterIdle(snapshot());
  for (const value of [undefined, null, {}, { owned: {} }]) assert.throws(() => assertProcessAdapterIdle(value));
});
for (const key of ['inflight', 'tcpSockets', 'tlsSockets', 'requests', 'jobs', 'timers']) test(`process idle rejects live stub ${key}`, () => {
  const value = snapshot(); value.owned.stub[key] = 1; assert.throws(() => assertProcessAdapterIdle(value));
});
for (const key of ['sockets', 'jobs']) test(`process idle rejects live transport ${key}`, () => {
  const value = snapshot(); value.owned.transport[key] = 1; assert.throws(() => assertProcessAdapterIdle(value));
});
for (const [key, value] of [['rss', NaN], ['rss', -1], ['rss', 192 * 1048576], ['fds', -1], ['fds', 64]]) {
  test(`process idle rejects resource ${key}=${value}`, () => {
    const sample = snapshot(); sample.resources[key] = value; assert.throws(() => assertProcessAdapterIdle(sample));
  });
}
for (const args of [['--resolved-adapter', '--crash'], ['--resolved-adapter', '--resolved-journal'],
  ['--resolved-adapter', '--resolved-adapter'], ['--resolved-adapter', '--family=5']]) {
  test(`adapter process CLI refuses invalid combination ${args.join(' ')}`, async () => {
    const result = await runCommand(process.execPath, ['scripts/dns-lifecycle-lab.mjs', ...args], { env: cleanEnvironment(process.env) });
    assert.equal(result.code, 1); assert.equal(result.reason, null); assert.equal(result.stdout, '');
  });
}
