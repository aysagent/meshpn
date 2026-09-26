/** Actual dnsmasq + actual exit adapter, private network/PID/mount namespace only. */
import assert from 'node:assert/strict';
import { readFile, writeFile, readlink, realpath } from 'node:fs/promises';
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
import { startDnsmasqUsbPeer, startDnsmasqUpstreamPeer } from './dnsmasq-usb-peer.mjs';
import { createDnsmasqJournalFiles } from './dnsmasq-journal-files.mjs';
import { readDnsmasqJournal, inspectDnsmasqTransaction } from './dnsmasq-journal.mjs';
import { controller } from './dns-lifecycle-crash-lab.mjs';

export async function runDnsmasqLab(directory, executable, { usb = false, journal = false } = {}) {
  await assertDnsMountNamespace();
  assert.ok(!journal || usb, 'journal lab requires USB fixture');
  directory = await realpath(directory);
  assert.ok(executable?.startsWith('/'), 'absolute MESHPN_DNSMASQ executable required');
  const links = JSON.parse((await exec('ip', ['-j', 'link', 'show'])).stdout);
  assert.deepEqual(links.map((l) => l.ifname), ['lo']);
  await exec('ip', ['link', 'set', 'lo', 'up']);
  const baseline = await readFile(new URL('../fixtures/dns-clients/radxa-dnsmasq.conf', import.meta.url), 'utf8');
  const env = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' };
  const version = (await exec(executable, ['--version'], { env })).stdout.split('\n')[0];
  const executableSha256 = createHash('sha256').update(await readFile(executable)).digest('hex');
  let lab, daemon, peer, upstream, daemonDiagnostics = '';
  let forwardedBefore, forwardGuardCounters;
  let journalBackend, loadedIdentity;
  const journalScope = {}, journalEvidence = { controllerSigkills: 0, lockConflicts: 0, checkpoints: [] };
  const observers = [], checks = [];
  const dhcp = [];
  const configPath = join(directory, 'dnsmasq.conf'), listenPort = usb ? 53 : 1054;
  const hits = () => observers.reduce((n, s) => n + s.hits(), 0);
  const daemonArgs = ['--no-daemon', `--conf-file=${configPath}`, '--bind-interfaces', '--no-hosts',
    '--cache-size=0', `--port=${listenPort}`, '--pid-file=', '--log-facility=-', `--dhcp-leasefile=${join(directory, 'leases')}`];
  async function start(contents) {
    if (contents !== undefined) await writeFile(configPath, contents, { mode: 0o600 }); // exclusively owned temporary fixture
    await exec(executable, [...daemonArgs, '--test'], { env });
    daemon = child(executable, daemonArgs, { env });
    daemonDiagnostics = '';
    daemon.proc.stderr.on('data', (part) => { daemonDiagnostics = (daemonDiagnostics + part).slice(-4096); });
    await daemon.waitFor(/using nameserver/, 5000);
  }
  async function stop(signal) { await daemon?.stop(signal); daemon = undefined; loadedIdentity = undefined; }
  let sequence = 0;
  async function lookup(label, expected, tcp = false, type = 1) {
    if (peer) {
      const result = await peer.lookup({ tcp, type });
      assert.equal(result.outcome, 'dns-response', label);
      assert.equal(result.rcode, expected === null ? 2 : 0, label);
      if (expected !== null) {
        assert.ok(result.answer, label);
        assert.equal(result.answer, type === 1 ? Buffer.from(expected.split('.').map(Number)).toString('hex')
          : Buffer.from([0x20, 1, 0x0d, 0xb8, ...Array(11).fill(0), 0x12]).toString('hex'), label);
      }
      checks.push(label); return;
    }
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
  async function lease(label, managed) {
    const result = await peer.acquire();
    assert.deepEqual(result.stages, ['DISCOVER', 'OFFER', 'REQUEST', 'ACK']);
    if (managed) assert.deepEqual(result.ack.dns, ['192.168.7.1']);
    dhcp.push({ label, ...result }); checks.push(label); return result.ack;
  }
  async function usbGuard(enabled) {
    if (!peer) return;
    for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
      await exec(tool, ['-w', '2', enabled ? '-A' : '-D', 'INPUT', '-i', 'usb0',
        ...(tool === 'iptables' ? ['!', '-d', '192.168.7.1'] : []),
        '-p', protocol, '--dport', '53', '-j', 'REJECT']);
      await exec(tool, ['-w', '2', enabled ? '-A' : '-D', 'FORWARD', '-i', 'usb0',
        '-p', protocol, '--dport', '53', '-j', 'REJECT']);
    }
  }
  async function journalGuard(enabled) {
    // Unlike the USB-only smoke guard this also blocks the daemon's old upstreams.
    for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
      const rules = [ ['OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT'],
        ['INPUT', '-i', 'usb0', ...(tool === 'iptables' ? ['!', '-d', '192.168.7.1'] : []),
          '-p', protocol, '--dport', '53', '-j', 'REJECT'],
        ['FORWARD', '-i', 'usb0', '-p', protocol, '--dport', '53', '-j', 'REJECT'] ];
      for (const rule of rules) {
        let exists = true;
        try { await exec(tool, ['-w', '2', '-C', ...rule]); }
        catch (error) { if (error.code !== 1) throw error; exists = false; }
        if (enabled !== exists) await exec(tool, ['-w', '2', enabled ? '-A' : '-D', ...rule]);
      }
    }
  }
  async function runJournal(operation, pause) {
    const worker = controller(directory, operation, journalBackend, pause, 'dnsmasq');
    if (!pause) {
      const result = await worker.done; assert.equal(result.code, 0, result.stderr); return result.result;
    }
    try {
      await worker.reached;
      if (pause === 'prepared') {
        const rival = await controller(directory, 'recover', journalBackend, undefined, 'dnsmasq').done;
        assert.equal(rival.code, 75); journalEvidence.lockConflicts++;
      }
    } finally { worker.kill(); }
    assert.equal((await worker.done).signal, 'SIGKILL'); journalEvidence.controllerSigkills++;
    journalEvidence.checkpoints.push(pause);
  }
  async function forwardedProbes(phase, blocked) {
    if (!upstream) return;
    for (const family of [4, 6]) for (const tcp of [false, true]) {
      const result = await peer.lookup({ direct: true, forwarded: true, family, tcp });
      const label = `${phase} IPv${family} ${tcp ? 'TCP' : 'UDP'} ${JSON.stringify(result)}`;
      if (blocked) assert.ok(['client-deadline', 'transport-error'].includes(result.outcome), label);
      else { assert.equal(result.rcode, 0, label); assert.equal(result.answer, 'cb007108', label); }
      checks.push(`forward-ipv${family}-${tcp ? 'tcp' : 'udp'}-${phase}`);
    }
  }
  try {
    lab = await startAdapterSoakLab({ family: 4, modeTag: 'combo-tls', concurrency: 4, timeoutMs: 1000 }, directory);
    // Baseline "public" resolvers are only local aliases in a NIC-less namespace.
    if (usb) {
      await exec('ip', ['link', 'add', 'upstreamfixture', 'type', 'dummy']);
      await exec('ip', ['link', 'set', 'upstreamfixture', 'up']);
    }
    for (const address of ['1.1.1.1', '8.8.8.8']) {
      await exec('ip', ['addr', 'add', `${address}/32`, 'dev', usb ? 'upstreamfixture' : 'lo']);
      observers.push(await sentinel(address));
    }
    if (usb) {
      await exec('ip', ['-6', 'addr', 'add', '2001:db8:53::1/128', 'dev', 'upstreamfixture', 'nodad']);
      observers.push(await sentinel('2001:db8:53::1'));
    }
    if (usb) { peer = await startDnsmasqUsbPeer(); upstream = await startDnsmasqUpstreamPeer(); }
    else {
      await exec('ip', ['link', 'add', 'usb0', 'type', 'dummy']);
      await exec('ip', ['addr', 'add', '192.168.7.1/24', 'dev', 'usb0']);
      await exec('ip', ['link', 'set', 'usb0', 'up']);
    }
    const plan = compileRadxaDnsmasqLabConfig(baseline, { port: lab.adapter.port, normalizeDhcpDns: true });
    await start(baseline);
    if (peer) {
      await lease('baseline-dhcp-dora', false);
      await forwardedProbes('positive-control', false);
      for (const family of [4, 6]) for (const tcp of [false, true]) {
        const r = await peer.lookup({ direct: true, tcp, family });
        assert.equal(r.rcode, 0); assert.equal(r.answer, 'cb007108');
        checks.push(`usb-direct-ipv${family}-${tcp ? 'tcp' : 'udp'}-positive-control`);
      }
    }
    await lookup('baseline-udp-positive-control', '203.0.113.8');
    await lookup('baseline-tcp-positive-control', '203.0.113.8', true);
    assert.ok(hits() >= 2); await stop();
    // Config switch/restart is fixture-owned, not a crash-safe host transaction.
    const before = hits(); forwardedBefore = await upstream?.hits();
    if (upstream) assert.deepEqual(forwardedBefore, [2, 2], 'both external sentinels must receive UDP and TCP controls');
    if (journal) {
      for (const key of ['net', 'mnt', 'pid']) journalScope[key] = await readlink(`/proc/self/ns/${key}`);
      await writeFile(join(directory, 'lock'), '', { flag: 'wx', mode: 0o600 });
      journalBackend = await createDnsmasqJournalFiles({ directory, port: lab.adapter.port, normalizeDhcpDns: true,
        identity: async () => {
          const [link] = JSON.parse((await exec('ip', ['-j', 'link', 'show', 'dev', 'usb0'])).stdout);
          return { scope: journalScope, bootId: (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim(),
            executableSha256: createHash('sha256').update(await readFile(executable)).digest('hex'),
            link: { ifname: link.ifname, ifindex: link.ifindex, address: link.address } };
        }, ensureGuard: () => journalGuard(true), removeGuard: () => journalGuard(false),
        probe: async () => {
          for (const tcp of [false, true]) {
            const query = makeDnsQuery(`journal-ready-${++sequence}.test`);
            const reply = await queryLabDns(lab.adapter.port, query, { tcp, timeoutMs: 4000 });
            assert.equal(validateDnsResponse(reply, query).rcode, 0, 'adapter not ready');
          }
        }, activate: async (record) => {
          const selected = record[record.direction === 'apply' ? 'managed' : 'restored'];
          if (daemon && daemon.proc.exitCode === null && daemon.proc.signalCode === null && loadedIdentity === selected.identity) return;
          await stop(); await start(); loadedIdentity = selected.identity;
        } });
      await runJournal('enable', 'prepared');
      const beforeDryRun = await readFile(join(directory, 'journal.json'));
      const dryRun = await inspectDnsmasqTransaction({ directory, scope: journalScope, backend: journalBackend });
      assert.equal(dryRun.mode, 'dry-run'); assert.deepEqual(await readFile(join(directory, 'journal.json')), beforeDryRun);
      await runJournal('recover', 'apply:config:set');
      await runJournal('recover', 'apply:daemon:set');
      const activated = await runJournal('recover'); journalEvidence.id = activated.id;
      assert.equal(activated.status, 'active');
    } else { await usbGuard(true); await start(plan.managed); }
    if (peer) {
      // This dnsmasq fixture advertises 1.1.1.1 in the original duplicate option 6.
      // DHCP clients do not learn the changed option until another exchange.
      assert.deepEqual(dhcp[0].ack.dns, ['1.1.1.1'], 'baseline duplicate option behavior changed; review fixture');
      const stale = await peer.lookup();
      assert.ok(['client-deadline', 'transport-error'].includes(stale.outcome));
      checks.push('stale-dhcp-dns-blocked-until-reacquire');
      const acquired = await lease('managed-dhcp-dora', true);
      await forwardedProbes('managed-blocked', true);
      for (const family of [4, 6]) for (const tcp of [false, true]) {
        const direct = await peer.lookup({ direct: true, tcp, family });
        assert.ok(['client-deadline', 'transport-error'].includes(direct.outcome));
        checks.push(`usb-direct-ipv${family}-${tcp ? 'tcp' : 'udp'}-blocked`);
      }
      for (const tcp of [false, true]) {
        const local = await peer.lookup({ local: true, tcp });
        assert.equal(local.rcode, 0);
        assert.equal(local.answer, Buffer.from(acquired.address.split('.').map(Number)).toString('hex'));
        checks.push(`usb-local-name-${tcp ? 'tcp' : 'udp'}`);
      }
    }
    for (const tcp of [false, true]) for (const type of [1, 28]) {
      await lookup(`managed-${tcp ? 'tcp' : 'udp'}-${type}`, '192.0.2.123', tcp, type);
    }
    await lab.stopExit();
    if (journal) {
      const result = await controller(directory, 'recover', journalBackend, undefined, 'dnsmasq').done;
      assert.equal(result.code, 2); journalEvidence.exitDownRecoveryRefused = true;
    }
    await forwardedProbes('exit-down-blocked', true);
    if (peer) await lease('exit-down-dhcp-still-works', true);
    await lookup('exit-down-udp-no-baseline-fallback', null);
    await lookup('exit-down-tcp-no-baseline-fallback', null, true);
    await lab.restartExit(); await lookup('exit-recovered', '192.0.2.123');
    await stop('SIGKILL');
    if (journal) assert.equal((await runJournal('recover')).status, 'active');
    else await start(plan.managed);
    await forwardedProbes('dnsmasq-restart-blocked', true);
    if (peer) {
      const acquired = await lease('dnsmasq-restart-dhcp', true);
      assert.equal(acquired.address, dhcp[1].ack.address, 'lease survives dnsmasq restart');
    }
    await lookup('dnsmasq-restarted-protected', '192.0.2.123');
    await lab.adapter.close();
    await forwardedProbes('adapter-down-blocked', true);
    if (peer) {
      await lease('adapter-down-dhcp-still-works', true);
      const local = await peer.lookup({ local: true });
      assert.equal(local.rcode, 0); assert.ok(local.answer); checks.push('adapter-down-local-name-still-works');
    }
    // TCP refusal is returned as SERVFAIL by dnsmasq; UDP may wait longer than
    // the client budget. Record cancellation separately, never as SERVFAIL.
    const q = makeDnsQuery('adapter-down.test');
    if (peer) {
      const result = await peer.lookup();
      assert.ok(result.outcome === 'client-deadline' || result.outcome === 'dns-response' && result.rcode !== 0);
      checks.push(result.outcome === 'client-deadline' ? 'adapter-down-client-deadline' : 'adapter-down-dns-error');
    } else try {
      const result = validateDnsResponse(await queryLabDns(listenPort, q, { timeoutMs: 1200 }), q);
      assert.notEqual(result.rcode, 0); checks.push('adapter-down-dns-error');
    } catch (error) {
      assert.equal(error.code, 'DNS_CLIENT_TIMEOUT'); checks.push('adapter-down-client-deadline');
    }
    assert.equal(hits(), before, 'direct baseline upstream used during managed mode');
    checks.push('zero-baseline-queries-during-protection');
    if (upstream) {
      assert.deepEqual(await upstream.hits(), forwardedBefore, 'forwarded DNS escaped the guard');
      forwardGuardCounters = [];
      for (const tool of ['iptables-save', 'ip6tables-save']) {
        const rules = (await exec(tool, ['-c', '-t', 'filter'])).stdout.split('\n')
          .filter((line) => line.includes('-A FORWARD -i usb0 ') && line.includes('--dport 53 -j REJECT'));
        assert.equal(rules.length, 2, 'both UDP and TCP FORWARD guards required');
        for (const protocol of ['udp', 'tcp']) {
          const rule = rules.find((line) => line.includes(`-p ${protocol} `));
          const packets = Number(/^\[(\d+):\d+\]/.exec(rule)?.[1]);
          assert.ok(packets >= 4, 'each fault phase must traverse its FORWARD guard');
          forwardGuardCounters.push({ family: tool === 'iptables-save' ? 4 : 6, protocol, packets });
        }
      }
      checks.push('forward-zero-upstream-queries-and-four-rule-counters');
    }
    if (journal) {
      // Explicit disable works even with the adapter down. Each file/daemon
      // boundary is killed and completed by a new flock-owning controller.
      await runJournal('disable', 'restore-start');
      await runJournal('recover', 'restore:config:set');
      await runJournal('recover', 'restore:daemon:set');
      const held = await peer.lookup();
      assert.ok(held.outcome === 'client-deadline' || held.outcome === 'dns-response' && held.rcode !== 0,
        'baseline daemon must not reach direct upstream before release');
      assert.equal(hits(), before, 'baseline must stay blocked before explicit release');
      journalEvidence.baselineDaemonBlockedBeforeRelease = true;
      await runJournal('recover', 'guard-removed');
      const released = await runJournal('recover');
      assert.equal(released.status, 'released'); assert.equal(released.id, journalEvidence.id);
      assert.equal((await readDnsmasqJournal(directory)).stage, 'released');
    } else { await stop(); await start(plan.baseline); await usbGuard(false); }
    assert.equal(await readFile(configPath, 'utf8'), baseline);
    if (peer) {
      await lease('explicit-restore-dhcp', false);
      assert.deepEqual(dhcp.at(-1).ack.dns, dhcp[0].ack.dns, 'baseline DHCP DNS restored');
    }
    await lookup('explicit-restore-udp', '203.0.113.8');
    await lookup('explicit-restore-tcp', '203.0.113.8', true);
    await forwardedProbes('restored', false);
    if (upstream) assert.deepEqual(await upstream.hits(), [4, 4], 'both restored external sentinels must answer');
    if (peer) for (const family of [4, 6]) for (const tcp of [false, true]) {
      const direct = await peer.lookup({ direct: true, tcp, family });
      assert.equal(direct.rcode, 0); assert.equal(direct.answer, 'cb007108');
      checks.push(`usb-direct-ipv${family}-${tcp ? 'tcp' : 'udp'}-restored`);
    }
    assert.ok(hits() > before);
    await stop(); await peer?.close(); await upstream?.close(); await lab.close();
    for (const observer of observers) await observer.close(); observers.length = 0;
    const final = namespaceResources();
    assert.equal(final.tree.live, 1); assert.equal(final.tree.zombies, 0);
    return { schema: 1, kind: 'clean-vpn-dnsmasq-lab', status: 'passed', version, executableSha256,
      hostDnsChanged: false, backend: 'radxa-fixture-only', checks, baselineQueriesDuringProtection: 0,
      exactFixtureBaselineRestored: true, dhcpRangeAndRouterRetained: true, dhcpLeaseExchangeTested: usb,
      ...(usb ? { dhcp, usbPeerSeparateNetworkNamespace: true, usbDirectDnsGuardTested: 'IPv4-and-IPv6-INPUT-and-FORWARD',
        upstreamSeparateNetworkNamespace: true, forwardGuardCounters, forwardedQueriesDuringProtection: 0,
        usbForwardRulesInstalledButNotTrafficTested: false, staleDhcpDnsRequiresReacquire: true } : {}),
      durableRecoveryImplemented: journal, ...(journal ? { journal: journalEvidence, recoveryScope: 'same-namespace-fixture',
        controllerBackend: 'parent-owned-rpc', rebootTested: false } : {}),
      systemResolverTakeoverTested: false, independentPcap: false,
      final: { processes: final.tree.live, zombies: final.tree.zombies } };
  } catch (error) {
    throw new Error(`${error.message}\nfixture dnsmasq: ${daemonDiagnostics}`);
  } finally {
    await stop(); await peer?.close(); await upstream?.close(); await lab?.close();
    for (const observer of observers) await observer.close();
  }
}
