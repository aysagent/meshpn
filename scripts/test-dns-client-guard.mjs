import assert from 'node:assert/strict';
import test from 'node:test';
import { runCommand } from './lib/transparent-acceptance.mjs';
import { compileDnsClientGuard, inspectDnsClientGuard, dnsClientGuardBatch, createDnsClientGuard } from './lib/dns-client-guard.mjs';

const input = { schema: 1, client: 'vps2', id: 'a'.repeat(32) };
const radxa = { ...input, client: 'radxa', usbInterface: 'usb0', usbAddress: '192.168.7.1' };
const policies = '-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n';
function snapshot(plan, family) {
  const { chains } = plan.families.find((part) => part.family === family);
  return policies + chains.flatMap((c) => [`-N ${c.name}`, `-A ${c.hook} ${c.jump.join(' ')}`,
    ...c.rules.map((r) => `-A ${c.name} ${r.join(' ')}`)]).join('\n') + '\n';
}
for (const config of [input, radxa]) test(`${config.client}: exact dual-stack plan, positive ownership and no global flush`, () => {
  const plan = compileDnsClientGuard(config);
  for (const family of [4, 6]) {
    assert.equal(inspectDnsClientGuard(plan, family, policies), 'absent');
    assert.equal(inspectDnsClientGuard(plan, family, snapshot(plan, family)), 'present');
    const install = dnsClientGuardBatch(plan, family, 'install');
    assert.match(install, /^\*filter\n-N CVD_/); assert.match(install, /\nCOMMIT\n$/);
    assert.doesNotMatch(install, /ACCEPT|--ctstate|ESTABLISHED|^-F|^:/m);
    assert.doesNotMatch(dnsClientGuardBatch(plan, family, 'release'), /^-F|^:/m);
    assert.equal(plan.families.find((p) => p.family === family).chains.length, config.client === 'radxa' ? 3 : 1);
  }
});
test('Radxa allows only explicit local DNS, not arbitrary USB forwarding or IPv6 DNS listeners', () => {
  const plan = compileDnsClientGuard(radxa);
  assert.match(dnsClientGuardBatch(plan, 4, 'install'), /-d 192\.168\.7\.1.*-j RETURN/);
  assert.match(dnsClientGuardBatch(plan, 6, 'install'), /-o lo -d ::1.*-j RETURN/);
  const input6 = plan.families[1].chains.find((c) => c.hook === 'INPUT');
  assert.ok(input6.rules.every((r) => r.includes('DROP') && !r.includes('RETURN')));
});
for (const changes of [{ client: 'auto' }, { id: 'bad' }, { id: 'A'.repeat(32) }, { schema: 2 }, { extra: true }, { usbInterface: 'usb0' }]) {
  test(`reject malformed guard config ${JSON.stringify(changes)}`, () => assert.throws(() => compileDnsClientGuard({ ...input, ...changes })));
}
for (const name of ['lo', 'usb0\nCOMMIT', 'usb0+', '../usb0', '', 'a'.repeat(16)]) {
  test(`reject unsafe USB interface ${JSON.stringify(name)}`, () => assert.throws(() => compileDnsClientGuard({ ...radxa, usbInterface: name })));
}
for (const address of ['127.0.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', 'host.test']) {
  test(`reject invalid USB address ${address}`, () => assert.throws(() => compileDnsClientGuard({ ...radxa, usbAddress: address })));
}
test('ownership rejects missing/reordered/duplicate rules, renamed identities and references', () => {
  const plan = compileDnsClientGuard(radxa), original = snapshot(plan, 4), chain = plan.families[0].chains[0];
  const lines = original.trim().split('\n'), rules = lines.filter((l) => l.startsWith(`-A ${chain.name} `));
  for (const changed of [original.replace(rules[0] + '\n', ''), original + rules[0] + '\n',
    original.replace('192.168.7.1', '192.168.7.2'), original + `-A INPUT -j ${chain.name}\n`,
    original.replace(rules[0], 'PLACEHOLDER').replace(rules[1], rules[0]).replace('PLACEHOLDER', rules[1]),
    original.replace('-A OUTPUT ', '-A OUTPUT -j ACCEPT\n-A OUTPUT '),
    original.replaceAll(input.id, 'b'.repeat(32))]) assert.throws(() => inspectDnsClientGuard(plan, 4, changed));
});
test('unrelated rules remain opaque; iptables address masks/quoted comments are normalized', () => {
  const plan = compileDnsClientGuard(input);
  const actual = snapshot(plan, 4).replaceAll('-d 127.0.0.53 ', '-d 127.0.0.53/32 ')
    .replace(/--comment (\S+)/g, '--comment "$1"');
  assert.equal(inspectDnsClientGuard(plan, 4, actual + '-A INPUT -m comment --comment "unrelated quoted text" -j DROP\n'), 'present');
});
function fixture() {
  const plan = compileDnsClientGuard(input), state = new Map([[4, policies], [6, policies]]), calls = [];
  let fail6 = false, context = true;
  const executor = createDnsClientGuard({ input,
    assertContext: async () => assert.equal(context, true), read: async (family) => state.get(family),
    restore: async (family, batch) => {
      calls.push(family); if (family === 6 && fail6) throw new Error('injected IPv6 failure');
      state.set(family, batch.includes('\n-N ') ? snapshot(plan, family) : policies);
    } });
  return { plan, state, calls, executor, fail6: (v) => { fail6 = v; }, context: (v) => { context = v; } };
}
test('ensure idempotence and recovery after IPv4 commit retain protection; release is explicit', async () => {
  const f = fixture(); f.fail6(true);
  await assert.rejects(f.executor.ensure(), /IPv6/);
  assert.deepEqual(await f.executor.inspect(), ['present', 'absent']);
  f.fail6(false); await f.executor.ensure(); assert.deepEqual(f.calls, [4, 6, 6]);
  await f.executor.ensure(); assert.deepEqual(f.calls, [4, 6, 6]);
  await assert.rejects(f.executor.release()); await assert.rejects(f.executor.release(async () => false));
  assert.deepEqual(await f.executor.inspect(), ['present', 'present']);
  await f.executor.release(async () => true); assert.deepEqual(await f.executor.inspect(), ['absent', 'absent']);
});
test('foreign IPv6 state prevents any IPv4 mutation', async () => {
  const f = fixture(); f.state.set(6, policies + '-N CVD_foreign\n');
  await assert.rejects(f.executor.ensure()); assert.deepEqual(f.calls, []);
});
test('context mismatch prevents writes and release', async () => {
  const f = fixture(); f.context(false);
  await assert.rejects(f.executor.ensure()); await assert.rejects(f.executor.release(async () => true));
  assert.deepEqual(f.calls, []);
});
test('interrupted release resumes only with fresh explicit baseline authorization', async () => {
  const f = fixture(); await f.executor.ensure(); f.fail6(true);
  await assert.rejects(f.executor.release(async () => true));
  assert.deepEqual(await f.executor.inspect(), ['absent', 'present']);
  f.fail6(false); await assert.rejects(f.executor.release(async () => false));
  await f.executor.release(async () => true); assert.deepEqual(await f.executor.inspect(), ['absent', 'absent']);
});
test('missing commit acknowledgement is recovered by readback without duplicate rules', async () => {
  const plan = compileDnsClientGuard(input), state = new Map([[4, policies], [6, policies]]), calls = [];
  let fail = true;
  const guard = createDnsClientGuard({ input, assertContext: async () => {}, read: async (family) => state.get(family),
    restore: async (family) => {
      calls.push(family); state.set(family, snapshot(plan, family));
      if (fail) { fail = false; throw new Error('lost acknowledgement'); }
    } });
  await assert.rejects(guard.ensure(), /acknowledgement/); await guard.ensure();
  assert.deepEqual(calls, [4, 6]); assert.deepEqual(await guard.inspect(), ['present', 'present']);
});
test('changed plan, truncated chain-id collision and oversized snapshots are rejected', () => {
  const plan = compileDnsClientGuard(input);
  assert.throws(() => inspectDnsClientGuard({ ...plan, schema: 2 }, 4, policies));
  assert.throws(() => inspectDnsClientGuard(plan, 4, ' '.repeat(262145)));
  const other = compileDnsClientGuard({ ...input, id: 'a'.repeat(16) + 'b'.repeat(16) });
  assert.throws(() => inspectDnsClientGuard(plan, 4, snapshot(other, 4)));
});
test('isolated guard lab cannot be used as a host setter or arbitrary command', async () => {
  for (const arg of ['--isolated', '--apply', '--client=radxa']) {
    const result = await runCommand(process.execPath, ['scripts/dns-client-guard-lab.mjs', arg]);
    assert.equal(result.code, 1); assert.equal(result.stdout, '');
    assert.match(result.stderr, /use public browser soak launcher|no host apply option/);
  }
});
