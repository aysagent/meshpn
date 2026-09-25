/** Actual dnsmasq + actual exit adapter, private network/PID/mount namespace only. */
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { child, exec } from './browser-lab-driver.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { namespaceResources } from './browser-soak.mjs';
import { startAdapterSoakLab } from './dns-adapter-soak-lab.mjs';
import { sentinel } from './dns-lifecycle-lab.mjs';
import { queryLabDns } from './transparent-dns-lab.mjs';
import { makeDnsQuery, validateDnsResponse } from './lab-dns-wire.mjs';
import { compileRadxaDnsmasqLabConfig } from './dnsmasq-lab-config.mjs';

export async function runDnsmasqLab(directory, executable) {
  await assertDnsMountNamespace();
  assert.ok(executable?.startsWith('/'), 'absolute MESHPN_DNSMASQ executable required');
  const links = JSON.parse((await exec('ip', ['-j', 'link', 'show'])).stdout);
  assert.deepEqual(links.map((l) => l.ifname), ['lo']);
  await exec('ip', ['link', 'set', 'lo', 'up']);
  const baseline = await readFile(new URL('../fixtures/dns-clients/radxa-dnsmasq.conf', import.meta.url), 'utf8');
  const env = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' };
  const version = (await exec(executable, ['--version'], { env })).stdout.split('\n')[0];
  const executableSha256 = createHash('sha256').update(await readFile(executable)).digest('hex');
  let lab, daemon;
  const observers = [], checks = [];
  const configPath = join(directory, 'dnsmasq.conf'), listenPort = 1054;
  const hits = () => observers.reduce((n, s) => n + s.hits(), 0);
  const daemonArgs = ['--no-daemon', `--conf-file=${configPath}`, '--bind-interfaces', '--no-hosts',
    '--cache-size=0', `--port=${listenPort}`, '--pid-file=', '--log-facility=-', `--dhcp-leasefile=${join(directory, 'leases')}`];
  async function start(contents) {
    await writeFile(configPath, contents, { mode: 0o600 }); // exclusively owned temporary fixture
    await exec(executable, [...daemonArgs, '--test'], { env });
    daemon = child(executable, daemonArgs, { env });
    await daemon.waitFor(/using nameserver/, 5000);
  }
  async function stop(signal) { await daemon?.stop(signal); daemon = undefined; }
  let sequence = 0;
  async function lookup(label, expected, tcp = false, type = 1) {
    const query = makeDnsQuery(`dnsmasq-${++sequence}.test`, type);
    const reply = await queryLabDns(listenPort, query, { tcp, timeoutMs: 4000 });
    const parsed = validateDnsResponse(reply, query);
    assert.equal(parsed.rcode, expected === null ? 2 : 0, label);
    if (expected !== null) {
      const rr = parsed.records.find((r) => r.type === type && r.section === 0);
      assert.ok(rr, label);
      if (type === 1) assert.equal([...reply.subarray(rr.offset, rr.offset + rr.length)].join('.'), expected, label);
      else assert.equal(rr.length, 16, label);
    }
    checks.push(label);
  }
  try {
    lab = await startAdapterSoakLab({ family: 4, modeTag: 'combo-tls', concurrency: 4, timeoutMs: 1000 }, directory);
    // Baseline "public" resolvers are only local aliases in a NIC-less namespace.
    for (const address of ['1.1.1.1', '8.8.8.8']) {
      await exec('ip', ['addr', 'add', `${address}/32`, 'dev', 'lo']);
      observers.push(await sentinel(address));
    }
    await exec('ip', ['link', 'add', 'usb0', 'type', 'dummy']);
    await exec('ip', ['addr', 'add', '192.168.7.1/24', 'dev', 'usb0']);
    await exec('ip', ['link', 'set', 'usb0', 'up']);
    const plan = compileRadxaDnsmasqLabConfig(baseline, { port: lab.adapter.port, normalizeDhcpDns: true });
    await start(baseline);
    await lookup('baseline-udp-positive-control', '203.0.113.8');
    await lookup('baseline-tcp-positive-control', '203.0.113.8', true);
    assert.ok(hits() >= 2); await stop();
    // Config switch/restart is fixture-owned, not a crash-safe host transaction.
    const before = hits(); await start(plan.managed);
    for (const tcp of [false, true]) for (const type of [1, 28]) {
      await lookup(`managed-${tcp ? 'tcp' : 'udp'}-${type}`, '192.0.2.123', tcp, type);
    }
    await lab.stopExit();
    await lookup('exit-down-udp-no-baseline-fallback', null);
    await lookup('exit-down-tcp-no-baseline-fallback', null, true);
    await lab.restartExit(); await lookup('exit-recovered', '192.0.2.123');
    await stop('SIGKILL'); await start(plan.managed);
    await lookup('dnsmasq-restarted-protected', '192.0.2.123');
    await lab.adapter.close();
    // TCP refusal is returned as SERVFAIL by dnsmasq; UDP may wait longer than
    // the client budget. Record cancellation separately, never as SERVFAIL.
    const q = makeDnsQuery('adapter-down.test');
    try {
      const result = validateDnsResponse(await queryLabDns(listenPort, q, { timeoutMs: 1200 }), q);
      assert.notEqual(result.rcode, 0); checks.push('adapter-down-dns-error');
    } catch (error) {
      assert.equal(error.code, 'DNS_CLIENT_TIMEOUT'); checks.push('adapter-down-client-deadline');
    }
    assert.equal(hits(), before, 'direct baseline upstream used during managed mode');
    checks.push('zero-baseline-queries-during-protection');
    await stop(); await start(plan.baseline);
    assert.equal(await readFile(configPath, 'utf8'), baseline);
    await lookup('explicit-restore-udp', '203.0.113.8');
    await lookup('explicit-restore-tcp', '203.0.113.8', true);
    assert.ok(hits() > before);
    await stop(); await lab.close();
    for (const observer of observers) await observer.close(); observers.length = 0;
    const final = namespaceResources();
    assert.equal(final.tree.live, 1); assert.equal(final.tree.zombies, 0);
    return { schema: 1, kind: 'clean-vpn-dnsmasq-lab', status: 'passed', version, executableSha256,
      hostDnsChanged: false, backend: 'radxa-fixture-only', checks, baselineQueriesDuringProtection: 0,
      exactFixtureBaselineRestored: true, dhcpRangeAndRouterRetained: true, dhcpLeaseExchangeTested: false,
      durableRecoveryImplemented: false, systemResolverTakeoverTested: false, independentPcap: false,
      final: { processes: final.tree.live, zombies: final.tree.zombies } };
  } finally {
    await stop(); await lab?.close();
    for (const observer of observers) await observer.close();
  }
}
