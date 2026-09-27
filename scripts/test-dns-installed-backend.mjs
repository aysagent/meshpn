import assert from 'node:assert/strict';
import test from 'node:test';
import { createInstalledVps2Runtime, isReadOnlyInstalledIp } from './lib/dns-installed-vps2-runtime.mjs';
import { assertDnsInstalledSession } from './lib/dns-installed-authority.mjs';
import { createInstalledOwnedLinkBackend, createInstalledOwnedLinkContext } from './lib/dns-owned-link-backend.mjs';
import { createInstalledCoupledBackend } from './lib/dns-coupled-backend.mjs';
import { createInstalledVps2Controller, DNS_INSTALLED_STATE, DNS_INSTALLED_GUARD, DNS_INSTALLED_TRANSACTION } from './lib/dns-installed-controller.mjs';

test('installed runtime cannot obtain authority from data or injected IO', async () => {
  for (const token of [null, {}, { client: 'vps2', installedAuthorityVerified: true }, { assertAuthority: async () => true }]) {
    await assert.rejects(createInstalledVps2Runtime(token), /installed authority token required/);
    await assert.rejects(assertDnsInstalledSession(token), /installed authority token required/);
  }
});
test('only fixed ip observations use session checks; writes and unknown args require full authority', () => {
  for (const args of [['-d', '-j', 'link', 'show'], ['-d', '-j', 'link', 'show', 'dev', 'cvdns1234abcd'],
    ['-j', 'addr', 'show', 'dev', 'cvdns1234abcd']]) assert.equal(isReadOnlyInstalledIp(args), true);
  for (const args of [null, [], ['link', 'delete', 'cvdns1234abcd'], ['link', 'set', 'dev', 'cvdns1234abcd', 'up'],
    ['addr', 'add', '192.0.2.1/32', 'dev', 'cvdns1234abcd'], ['-j', 'addr', 'show', 'dev', 'eth0'],
    ['-d', '-j', 'link', 'show', 'dev', 'cvdns1234abcd', 'up'], ['-batch', '/tmp/commands']]) assert.equal(isReadOnlyInstalledIp(args), false);
});
for (const [name, factory] of [['owned', createInstalledOwnedLinkBackend], ['context', createInstalledOwnedLinkContext], ['coupled', createInstalledCoupledBackend]]) {
  test(`installed ${name} refuses fake authority before guard/bus/probe callbacks or OS setters`, async () => {
    let calls = 0;
    const bad = () => { calls++; throw new Error('must not run'); };
    await assert.rejects(factory({ token: {}, bus: { id: bad, owner: bad, set: bad }, commands: { run: bad },
      ensureGuard: bad, releaseGuard: bad, probe: bad, assertAuthority: async () => true }), /installed authority token required/);
    assert.equal(calls, 0);
  });
}
test('installed controller state is fixed and fake opt-in cannot create storage or install a guard', async () => {
  assert.equal(DNS_INSTALLED_STATE, '/var/lib/clean-vpn/dns-v1');
  assert.equal(DNS_INSTALLED_GUARD, `${DNS_INSTALLED_STATE}/guard`);
  assert.equal(DNS_INSTALLED_TRANSACTION, `${DNS_INSTALLED_STATE}/transaction`);
  for (const command of ['start', 'disable', 'anything']) await assert.rejects(createInstalledVps2Controller({ token: {}, command,
    directory: '/tmp/override', createGuard: () => assert.fail('injected guard ran') }), /installed authority token required/);
});
