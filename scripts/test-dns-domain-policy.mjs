import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileDnsDomainPolicy, readDnsDomainPolicy, DNS_DOMAIN_POLICY_MAX_BYTES } from './lib/dns-domain-policy.mjs';
import { makeDnsQuery, parseDnsQuery } from './lib/lab-dns-wire.mjs';
import { startLabDohStub } from './lib/lab-doh-stub.mjs';
import { parseDnsExitArgs } from './dns-exit-adapter.mjs';

const config = () => ({ schema: 1, denySuffixes: ['auto.internal', 'ru-central1.internal'] });
const failure = { code: 'DNS_DOMAIN_POLICY' };
test('domain policy snapshots exact suffixes and wire label boundaries with ASCII case folding', () => {
  const input = config(), policy = compileDnsDomainPolicy(input);
  input.denySuffixes.length = 0;
  for (const name of ['auto.internal', 'AUTO.Internal.', '_srv._tcp.auto.internal', 'vm.ru-central1.internal'])
    assert.equal(policy.denies(parseDnsQuery(makeDnsQuery(name))), true, name);
  for (const name of ['notauto.internal', 'auto.internal.test', 'internal', '.', 'ordinary.test'])
    assert.equal(policy.denies(parseDnsQuery(makeDnsQuery(name))), false, name);
  // A single binary label "auto.internal" is not two DNS labels.
  const base = makeDnsQuery('auto.internal');
  const binary = Buffer.concat([base.subarray(0, 12), Buffer.from([13]), Buffer.from('auto.internal'), Buffer.from([0]), base.subarray(-4)]);
  assert.equal(policy.denies(parseDnsQuery(binary)), false);
  // Binary left-hand labels do not bypass a genuine blocked suffix.
  const prefix = Buffer.concat([base.subarray(0, 12), Buffer.from([3, 0, 46, 255]), base.subarray(12)]);
  assert.equal(policy.denies(parseDnsQuery(prefix)), true);
  assert.equal(compileDnsDomainPolicy({ schema: 1, denySuffixes: ['AUTO.Internal.'] }).denies(parseDnsQuery(base)), true);
});
test('domain policy rejects unknown keys, empty/oversized lists, invalid names and normalized duplicates', async () => {
  for (const input of [null, {}, [], { ...config(), schema: 2 }, { ...config(), allow: [] },
    ...[[], 'auto.internal', Array(129).fill('test'), ['auto.internal', 'AUTO.Internal.'],
      ['.'], [''], ['*.internal'], ['a..b'], ['https://x.test'], ['x\n.test'], ['é.test'],
      ['-a.test'], ['a-.test'], ['x'.repeat(64)], [Array(4).fill('x'.repeat(63)).join('.')], [null]].map((denySuffixes) => ({ schema: 1, denySuffixes }))])
    assert.throws(() => compileDnsDomainPolicy(input), failure);
  await assert.rejects(startLabDohStub({ domainPolicy: {} }), failure); // Before any listener/config use.
  assert.doesNotThrow(() => compileDnsDomainPolicy({ schema: 1, denySuffixes: Array.from({ length: 128 }, (_, n) => `n${n}.test`) }));
});
test('policy file is bounded, regular, UTF-8 and nofollow; errors do not disclose contents', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-domain-policy-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'policy.json'); await writeFile(path, JSON.stringify(config()));
  assert.deepEqual(await readDnsDomainPolicy(path), config());
  const link = join(dir, 'link'); await symlink(path, link);
  for (const target of [link, dir, join(dir, 'missing'), '']) await assert.rejects(readDnsDomainPolicy(target), failure);
  for (const bytes of [Buffer.alloc(DNS_DOMAIN_POLICY_MAX_BYTES + 1, 32), Buffer.from([255]), Buffer.from('{private-invalid'), Buffer.from('{}')]) {
    await writeFile(path, bytes); await assert.rejects(readDnsDomainPolicy(path), { ...failure, message: 'DNS_DOMAIN_POLICY' });
  }
});
test('adapter policy CLI is explicit, optional, unique and cannot be empty', () => {
  const args = ['--config=/upstream', '--exit-ip=93.184.216.34', '--exit-port=443', '--public-name=relay.test', '--shared-hmac-key=/key', '--listen-port=1053'];
  assert.equal(parseDnsExitArgs(args)['domain-policy'], undefined);
  assert.equal(parseDnsExitArgs([...args, '--domain-policy=/policy'])['domain-policy'], '/policy');
  for (const extra of [['--domain-policy='], ['--domain-policy=/a', '--domain-policy=/b']]) assert.throws(() => parseDnsExitArgs([...args, ...extra]));
});
