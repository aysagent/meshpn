import assert from 'node:assert/strict';
import test from 'node:test';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

test('actual dnsmasq: baseline, protected UDP/TCP A/AAAA, faults, restart and explicit restore', { timeout: 65000 }, async () => {
  const result = await runCommand(process.execPath, ['scripts/dnsmasq-lab.mjs'],
    { timeoutMs: 62000, env: cleanEnvironment(process.env) });
  assert.equal(result.reason, null); assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'passed'); assert.equal(report.hostDnsChanged, false);
  assert.equal(report.baselineQueriesDuringProtection, 0); assert.equal(report.exactFixtureBaselineRestored, true);
  assert.equal(report.checks.length, 14); assert.equal(new Set(report.checks).size, 14);
  assert.equal(report.durableRecoveryImplemented, false); assert.equal(report.dhcpLeaseExchangeTested, false);
  assert.equal(report.final.processes, 1); assert.equal(report.final.zombies, 0);
});

test('USB peer: DHCP DORA, real port 53, local names, IPv4/IPv6 direct guard and fault-time DHCP', { timeout: 95000 }, async () => {
  const result = await runCommand(process.execPath, ['scripts/dnsmasq-lab.mjs', '--usb'],
    { timeoutMs: 92000, env: cleanEnvironment(process.env) });
  assert.equal(result.reason, null); assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'passed'); assert.equal(report.hostDnsChanged, false);
  assert.equal(report.dhcpLeaseExchangeTested, true); assert.equal(report.usbPeerSeparateNetworkNamespace, true);
  assert.equal(report.usbDirectDnsGuardTested, 'IPv4-and-IPv6-INPUT-and-FORWARD');
  assert.equal(report.usbForwardRulesInstalledButNotTrafficTested, false);
  assert.equal(report.upstreamSeparateNetworkNamespace, true);
  assert.equal(report.hostForwardingUnchanged, true);
  assert.equal(report.forwardedQueriesDuringProtection, 0);
  assert.deepEqual(report.forwardGuardCounters.map(({ family, protocol }) => [family, protocol]),
    [[4, 'udp'], [4, 'tcp'], [6, 'udp'], [6, 'tcp']]);
  for (const counter of report.forwardGuardCounters) assert.ok(counter.packets >= 4);
  assert.equal(report.staleDhcpDnsRequiresReacquire, true);
  assert.equal(report.checks.length, 61); assert.equal(new Set(report.checks).size, 61);
  assert.equal(report.dhcp.length, 6);
  for (const exchange of report.dhcp) {
    assert.deepEqual(exchange.stages, ['DISCOVER', 'OFFER', 'REQUEST', 'ACK']);
    assert.equal(exchange.ack.mask, '255.255.255.0');
    assert.deepEqual(exchange.ack.routers, ['192.168.7.1']);
    assert.equal(exchange.ack.leaseSeconds, 43200);
  }
  assert.deepEqual(report.dhcp[0].ack.dns, ['1.1.1.1']);
  for (const exchange of report.dhcp.slice(1, -1)) assert.deepEqual(exchange.ack.dns, ['192.168.7.1']);
  assert.deepEqual(report.dhcp.at(-1).ack.dns, ['1.1.1.1']);
  assert.equal(report.baselineQueriesDuringProtection, 0); assert.equal(report.exactFixtureBaselineRestored, true);
  assert.equal(report.durableRecoveryImplemented, false); assert.equal(report.systemResolverTakeoverTested, false);
  assert.equal(report.final.processes, 1); assert.equal(report.final.zombies, 0);
});
