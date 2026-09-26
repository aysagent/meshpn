import assert from 'node:assert/strict';
import test from 'node:test';
import { networkdLabOptions, runNetworkdLab, NETWORKD_CHECKS, assertNetworkdEvidence } from './lib/dns-networkd-lab.mjs';
import { runCommand } from './lib/transparent-acceptance.mjs';

test('networkd lab requires explicit tools, rejects duplicates and host actions', () => {
  assert.deepEqual(networkdLabOptions(['--help']), { help: true });
  const args = ['--systemd-dir=/tools/systemd', '--dnsmasq=/tools/dnsmasq'];
  assert.deepEqual(networkdLabOptions(args), { systemdDir: '/tools/systemd', dnsmasq: '/tools/dnsmasq' });
  assert.equal(networkdLabOptions([...args, '--link-journal']).linkJournal, true);
  assert.throws(() => networkdLabOptions([...args, '--link-journal', '--link-journal']));
  for (const extra of ['--apply', '--ssh=host', '--systemd-dir=/other', '--dnsmasq=/other', '--help'])
    assert.throws(() => networkdLabOptions([...args, extra]));
  for (const bad of [[], ['--isolated'], ['--systemd-dir=relative', '--dnsmasq=/tool'], [...args, '--isolated', '--isolated']])
    assert.throws(() => networkdLabOptions(bad));
});
test('networkd namespace worker refuses the host before filesystem or network mutation', async () => {
  await assert.rejects(runNetworkdLab('/does-not-exist', {}), /launcher|namespace|provenance/);
  const r = await runCommand(process.execPath, ['scripts/dns-networkd-lab.mjs', '--isolated', '--systemd-dir=/none', '--dnsmasq=/none']);
  assert.equal(r.code, 1); assert.match(r.stderr, /namespace|launcher|provenance/); assert.equal(r.stdout, '');
});
test('networkd public CLI help is non-mutating and unknown flags fail', async () => {
  const help = await runCommand(process.execPath, ['scripts/dns-networkd-lab.mjs', '--help']);
  assert.equal(help.code, 0); assert.match(help.stdout, /Private namespaces only/);
  const bad = await runCommand(process.execPath, ['scripts/dns-networkd-lab.mjs', '--apply']);
  assert.equal(bad.code, 1); assert.equal(bad.stdout, '');
});
test('cloud peer refuses host execution even with an executable supplied', async () => {
  const r = await runCommand(process.execPath, ['scripts/lib/dns-networkd-peer.mjs', '/none']);
  assert.equal(r.code, 1); assert.match(r.stderr, /CLOUD_FAILED/); assert.equal(r.stdout, '');
});
test('networkd evidence requires exact gates, real renewal and complete cleanup', () => {
  const evidence = { status: 'passed', checks: [...NETWORKD_CHECKS], realDhcpRenew: true, privateBus: true,
    hostDnsFilesUnchanged: true, hostForwardingUnchanged: true, networkdOwnedLinkTakeover: false,
    hostDeploymentImplemented: false, rebootTested: false, durableJournalTested: false,
    baselineQueriesDuringProtection: 0, dnsCalls: 0, cloudDnsChanged: ['10.129.0.2', '10.129.0.3'],
    dhcpDomainChanges: ['original', 'removed', 'replaced'], policyDenied: 8,
    cloudPolicy: 'explicit-qname-deny-suffixes-before-doh-plus-guard',
    final: { processes: 1, zombies: 0 }, blockedLookupDeadlines: 0 };
  assertNetworkdEvidence(evidence);
  assert.throws(() => assertNetworkdEvidence(evidence, { linkJournal: true }));
  for (const key of Object.keys(evidence).filter((k) => !['checks', 'final'].includes(k)))
    assert.throws(() => assertNetworkdEvidence({ ...evidence, [key]: typeof evidence[key] === 'boolean' ? !evidence[key] : null }), key);
  for (let i = 0; i < NETWORKD_CHECKS.length; i++) assert.throws(() =>
    assertNetworkdEvidence({ ...evidence, checks: evidence.checks.filter((_, n) => n !== i) }));
  assert.throws(() => assertNetworkdEvidence({ ...evidence, checks: [...evidence.checks, evidence.checks[0]] }));
  assert.throws(() => assertNetworkdEvidence({ ...evidence, final: { processes: 2, zombies: 0 } }));
});
