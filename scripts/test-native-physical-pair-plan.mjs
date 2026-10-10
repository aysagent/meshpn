import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { collectNativePhysicalPairPlan, composeNativePhysicalPair, parseNativePhysicalPairArgs } from './lib/native-physical-pair-plan.mjs';

const NOW = Date.parse('2026-10-11T12:00:00.000Z');
function report(role) {
  const config = `${role}-config`, siteProfile = `${role}-site`;
  return { schema: 1, kind: 'clean-vpn-native-physical-preflight', timestamp: new Date(NOW - 1000).toISOString(),
    status: 'ready-for-reviewed-trial-plan', observedIssues: [], warnings: [], mutationAllowed: false,
    systemSettingsChanged: false, networkProbesSent: 0, installationAttempted: false, aborted: false,
    request: { role, name: `trial-${role}` }, evidence: { config: { sha256: config }, siteProfile: { sha256: siteProfile }, binary: { sha256: `${role}-binary` } },
    engine: { role, transport: 'combo-tls', publicName: 'cover.example', architectureMatchesHost: true,
      capabilitiesStatus: 'ok', configCheck: 'ok', capability: { engine: 'clean-vpn-native-m1', packet_ipc: false,
        service_mode: true, dns_socket_mark: '0x43564e', combo: { single_exit_listener: true, packet_ipc: false, site_provisioning: true } } },
    offlineInstallDryRun: { status: 'eligible' },
    site: { role, transport: 'combo-tls', endpoint: '198.51.100.10', port: 443, listenPort: role === 'client' ? 2443 : 443,
      tunAddress: role === 'client' ? '10.99.0.2/32' : '10.99.0.1/24', lan: role === 'client' ? { subnet: '192.168.7.0/24' } : null },
    plan: { fingerprints: { config, siteProfile } } };
}

test('pair parser accepts only two distinct absolute reports', () => {
  assert.deepEqual(parseNativePhysicalPairArgs(['--client=/tmp/client.txt', '--exit=/tmp/exit.txt']), { client: '/tmp/client.txt', exit: '/tmp/exit.txt' });
  for (const args of [[], ['--client=/tmp/c'], ['--client=/tmp/x', '--exit=/tmp/x'], ['--client=relative', '--exit=/tmp/e'], ['--client=/tmp/c', '--exit=/tmp/e', '--apply']])
    assert.throws(() => parseNativePhysicalPairArgs(args));
});

test('matching fresh pair reaches design gate but never mutation authority', () => {
  const result = composeNativePhysicalPair(report('client'), report('exit'), { now: NOW });
  assert.equal(result.status, 'ready-for-human-approved-transient-design');
  assert.equal(result.mutationAllowed, false);
  assert.deepEqual(result.pair, { endpoint: '198.51.100.10', port: 443, publicName: 'cover.example',
    clientTun: '10.99.0.2/32', exitTun: '10.99.0.1/24', clientLan: '192.168.7.0/24',
    clientInstance: 'trial-client', exitInstance: 'trial-exit', pskProof: 'not-provided' });
  assert.ok(result.warnings.includes('cross-host-psk-equivalence-not-proven-by-preflight'));
});

test('matching one-use proofs close only the PSK gate', () => {
  const client = report('client'), exit = report('exit'), challenge = '34'.repeat(32);
  client.pairProof = { version: 1, challenge, boring: [{ peerIpv4: '10.99.0.2', value: 'ab'.repeat(32) }], relay: 'cd'.repeat(32) };
  exit.pairProof = { version: 1, challenge, boring: [{ peerIpv4: '10.99.0.2', value: 'ab'.repeat(32) }], relay: 'cd'.repeat(32) };
  const result = composeNativePhysicalPair(client, exit, { now: NOW });
  assert.equal(result.status, 'ready-for-human-approved-transient-design'); assert.equal(result.pair.pskProof, 'matched-one-use-challenge');
  assert.ok(!result.requiredProofsBeforeMutation.includes('cross-host-psk-equivalence-proved-without-disclosing-secret'));
  assert.ok(result.requiredProofsBeforeMutation.includes('exit-certificate-chain-and-name-pair-proved'));
});

test('partial or mismatched proof blocks the pair', () => {
  const client = report('client'), exit = report('exit'), challenge = '56'.repeat(32);
  client.pairProof = { version: 1, challenge, boring: [{ peerIpv4: '10.99.0.2', value: 'ab'.repeat(32) }], relay: 'cd'.repeat(32) };
  exit.pairProof = { version: 1, challenge, boring: [{ peerIpv4: '10.99.0.2', value: 'ef'.repeat(32) }], relay: 'cd'.repeat(32) };
  const result = composeNativePhysicalPair(client, exit, { now: NOW });
  assert.equal(result.status, 'blocked'); assert.ok(result.observedIssues.includes('cross-host-psk-proof-mismatch'));
});

for (const [name, mutate, issue] of [
  ['endpoint', (c, e) => { e.site.endpoint = '198.51.100.11'; }, 'exit-endpoint-mismatch'],
  ['port', (c, e) => { e.site.listenPort = 8443; }, 'exit-port-mismatch'],
  ['tunnel subnet', c => { c.site.tunAddress = '10.100.0.2/32'; }, 'client-tun-address-not-covered-by-exit-subnet'],
  ['LAN overlap', c => { c.site.lan.subnet = '10.99.0.0/24'; }, 'client-lan-missing-or-overlaps-tunnel'],
  ['stale report', c => { c.timestamp = new Date(NOW - 2 * 60 * 60 * 1000).toISOString(); }, 'client:stale-or-invalid-timestamp'],
  ['unready source', c => { c.status = 'blocked'; }, 'client:preflight-not-ready'],
  ['tampered fingerprint', c => { c.plan.fingerprints.config = 'different'; }, 'source-fingerprint-mismatch'],
]) test(`${name} blocks pair composition`, () => {
  const client = report('client'), exit = report('exit'); mutate(client, exit);
  const result = composeNativePhysicalPair(client, exit, { now: NOW });
  assert.equal(result.status, 'blocked'); assert.ok(result.observedIssues.includes(issue)); assert.equal(result.mutationAllowed, false);
});

test('collector accepts exact wrapper and emits only summarized source data', t => {
  const directory = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'native-pair-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const paths = {};
  for (const role of ['client', 'exit']) {
    const file = `${directory}/${role}.txt`, body = JSON.stringify(report(role));
    fs.writeFileSync(file, `=== CLEAN-VPN NATIVE PHYSICAL PREFLIGHT BEGIN ===\n${body}\n=== CLEAN-VPN NATIVE PHYSICAL PREFLIGHT END ===\n`, { mode: 0o600 });
    paths[role] = file;
  }
  const result = collectNativePhysicalPairPlan(paths, { now: NOW });
  assert.equal(result.status, 'ready-for-human-approved-transient-design');
  assert.equal(result.systemSettingsChanged, false); assert.equal(result.networkProbesSent, 0);
  assert.equal(JSON.stringify(result).includes('plannedUnitState'), false);
  assert.equal(result.sourceEvidence.client.mode, '600');
});
