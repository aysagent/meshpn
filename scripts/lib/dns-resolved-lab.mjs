/** Real resolved + private D-Bus, inside the DNS lifecycle namespace ONLY. */
import assert from 'node:assert/strict';
import { mkdir, writeFile, readFile, readlink } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { child, exec } from './browser-lab-driver.mjs';
import { cleanEnvironment } from './transparent-acceptance.mjs';
import { createResolvedBackend, resolvedMethod } from './dns-resolved-backend.mjs';
import { makeDnsQuery, validateDnsResponse } from './lab-dns-wire.mjs';
import { queryLabDns } from './transparent-dns-lab.mjs';
import { runResolvedCrashLab } from './dns-resolved-crash-lab.mjs';
import { runAdapterCrashLab } from './dns-adapter-crash-lab.mjs';

export async function runResolvedLab({ directory, lab, bindText, setGuard, lookup, hits, journal = false, adapterProcess = false }) {
  await assertDnsMountNamespace();
  assert.ok(process.env.MESHPN_PARENT_UTSNS);
  assert.notEqual(await readlink('/proc/self/ns/uts'), process.env.MESHPN_PARENT_UTSNS);
  await exec('hostname', ['meshpn-resolved-lab']);
  await mkdir('/run/systemd/resolve', { recursive: true, mode: 0o755 });
  // The mapped UID may be supplied by a host NSS daemon hidden with /run.
  // Give EXTERNAL D-Bus authentication a private, deterministic passwd entry.
  assert.notEqual(process.getuid(), 0, 'resolved lab requires non-root mapped user');
  await bindText('/etc/passwd', `root:x:0:0:root:/root:/bin/false\nfixture:x:${process.getuid()}:${process.getgid()}:fixture:/nonexistent:/bin/false\n`);
  await bindText('/etc/group', `root:x:0:\nfixture:x:${process.getgid()}:\n`);
  await bindText('/etc/nsswitch.conf', 'passwd: files\ngroup: files\nhosts: dns\n');
  const systemdDir = join(directory, 'systemd-conf'); await mkdir(systemdDir);
  await writeFile(join(systemdDir, 'resolved.conf'), '[Resolve]\nDNS=\nFallbackDNS=\nLLMNR=no\nMulticastDNS=no\nDNSSEC=no\nDNSOverTLS=no\nCache=no\nReadEtcHosts=no\nDNSStubListener=yes\n', { mode: 0o600, flag: 'wx' });
  await exec('mount', ['--bind', systemdDir, '/etc/systemd']);
  // /run was already replaced by the namespace launcher. No host bus socket is used.
  const busDir = '/run/meshpn-resolved-lab'; await mkdir(busDir, { mode: 0o700 });
  const address = `unix:path=${busDir}/bus`;
  const busConfig = join(directory, 'bus.conf');
  await writeFile(busConfig, `<busconfig><type>system</type><listen>${address}</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>`, { flag: 'wx', mode: 0o600 });
  const env = cleanEnvironment(process.env);
  for (const key of Object.keys(env)) if (/^(SYSTEMD_|DBUS_|LISTEN_|NOTIFY_SOCKET$|CREDENTIALS_DIRECTORY$)/.test(key)) delete env[key];
  Object.assign(env, { DBUS_SYSTEM_BUS_ADDRESS: address, SYSTEMD_LOG_LEVEL: 'info', SYSTEMD_LOG_TARGET: 'console', SYSTEMD_PAGER: 'cat' });
  let dbus, resolved;
  const executable = process.env.MESHPN_SYSTEMD_RESOLVED || '/usr/lib/systemd/systemd-resolved';
  const busRun = async (args) => exec('/usr/bin/busctl', ['--address', address, '--timeout=2s', '--auto-start=no',
    '--allow-interactive-authorization=no', '--json=short', ...args], { env, timeout: 3000, maxBuffer: 65536 });
  const value = async (args) => JSON.parse((await busRun(args)).stdout).data;
  const bus = {
    async id() { return (await value(['call', 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetId']))[0]; },
    async owner() { const data = await value(['call', 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetNameOwner', 's', 'org.freedesktop.resolve1']); return data[0]; },
    async property(owner, index, property) {
      const [path] = await value(['call', owner, '/org/freedesktop/resolve1', 'org.freedesktop.resolve1.Manager', 'GetLink', 'i', String(index)]);
      assert.match(path, /^\/org\/freedesktop\/resolve1\/link\/[A-Za-z0-9_]+$/);
      return (await value(['get-property', owner, path, 'org.freedesktop.resolve1.Link', property]));
    },
    async set(owner, args) { await busRun(['call', owner, '/org/freedesktop/resolve1', 'org.freedesktop.resolve1.Manager', ...args]); },
  };
  async function start() {
    resolved = child(executable, [], { env });
    let startupLog = '';
    resolved.proc.stderr.on('data', (chunk) => { startupLog = (startupLog + chunk).slice(-4096); });
    const deadline = performance.now() + 5000;
    for (;;) {
      try { await bus.owner(); return; } catch (error) {
        if (resolved.proc.exitCode !== null) { await resolved.waitFor(/NEVER_READY/, 1); }
        assert.ok(performance.now() < deadline, `resolved bus readiness deadline: ${error.message}; ${startupLog}`); await delay(25);
      }
    }
  }
  try {
    dbus = child('/usr/bin/dbus-daemon', ['--nofork', '--print-address=1', `--config-file=${busConfig}`], { env });
    await dbus.waitFor(/unix:path=/);
    const version = (await exec(executable, ['--version'], { env })).stdout.split('\n')[0];
    await exec('ip', ['link', 'add', 'dnsfixture', 'type', 'dummy']);
    await exec('ip', ['addr', 'add', '192.0.2.1/32', 'dev', 'dnsfixture']);
    await exec('ip', ['link', 'set', 'dnsfixture', 'up']);
    await start();
    const identity = async () => {
      const [link] = JSON.parse((await exec('ip', ['-j', 'link', 'show', 'dev', 'dnsfixture'])).stdout);
      return { ifindex: link.ifindex, ifname: link.ifname, address: link.address };
    };
    const ifindex = (await identity()).ifindex, owner = await bus.owner();
    for (const [key, setting] of Object.entries({ DNSEx: [[2, [127, 0, 0, 55], 53, '']], Domains: [['.', true], ['baseline.test', false]], DefaultRoute: true })) {
      await bus.set(owner, resolvedMethod(key, setting, ifindex));
    }
    await bindText('/etc/resolv.conf', 'nameserver 127.0.0.53\noptions timeout:1 attempts:1\n');
    const resolverBefore = await readFile('/etc/resolv.conf', 'utf8');
    // Permit the application->stub hop; the existing guard still blocks other UDP/TCP53 destinations.
    for (const protocol of ['udp', 'tcp']) await exec('iptables', ['-w', '2', '-I', 'OUTPUT', '1', '-d', '127.0.0.53', '-p', protocol, '--dport', '53', '-j', 'ACCEPT']);
    await lookup('resolved-baseline-udp', '203.0.113.8');
    await lookup('resolved-baseline-tcp', '203.0.113.8', true);
    const probe = async () => { const q = makeDnsQuery('resolved-readiness.test'); assert.equal(validateDnsResponse(await queryLabDns(lab.adapter.port, q), q).flags & 15, 0); };
    const create = () => createResolvedBackend({ bus, ifindex, identity, ensureGuard: () => setGuard(true), removeGuard: () => setGuard(false), probe });
    const backend = await create(), baseline = backend.snapshot(), before = hits();
    await backend.apply(lab.adapter.port);
    await lookup('resolved-managed-a', '192.0.2.123');
    await lookup('resolved-managed-aaaa', '2001:db8::12', true, 6);
    await lab.stopExit(); await lookup('resolved-exit-down', null); await backend.verify(); await lab.restartExit();
    await lookup('resolved-exit-recovered', '192.0.2.123');
    await bus.set(owner, resolvedMethod('Domains', [['foreign.test', true]], ifindex));
    await assert.rejects(backend.disable(), /ownership conflict/);
    assert.deepEqual(await bus.property(owner, ifindex, 'Domains'), [['foreign.test', true]]);
    // Explicit operator repair in the fixture, not automatic overwrite by backend.
    await bus.set(owner, resolvedMethod('Domains', [['.', true]], ifindex));
    assert.equal(hits(), before);
    await backend.disable();
    for (const key of ['DNSEx', 'Domains', 'DefaultRoute']) assert.deepEqual(await bus.property(owner, ifindex, key), baseline[key]);
    await lookup('resolved-explicit-restore', '203.0.113.8');
    assert.equal(await readFile('/etc/resolv.conf', 'utf8'), resolverBefore, 'backend must never rewrite resolv.conf');
    const second = await create(); await second.apply(lab.adapter.port); const restartBefore = hits();
    await resolved.stop('SIGKILL'); await lookup('resolved-daemon-down', null);
    await start(); await assert.rejects(second.disable(), /owner changed/);
    assert.deepEqual(await bus.property(await bus.owner(), ifindex, 'DNSEx'), [[2, [127, 0, 0, 1], lab.adapter.port, '']]);
    await lookup('resolved-restart-protected-but-not-adopted', '192.0.2.123');
    assert.equal(hits(), restartBefore);
    // Finish isolated fixture under explicit operator control; not production recovery.
    await setGuard(false);
    const journalReport = journal ? await runResolvedCrashLab({ directory, bus, ifindex, identity, setGuard, probe,
      port: lab.adapter.port, lookup, hits, lab, restartDaemon: async () => { await resolved.stop('SIGKILL'); await start(); } }) : undefined;
    const adapterReport = adapterProcess ? await runAdapterCrashLab({ directory, lab, bus, ifindex, identity, setGuard, lookup, hits }) : undefined;
    assert.equal(await readFile('/etc/resolv.conf', 'utf8'), resolverBefore);
    return { status: 'passed', version, privateBus: true, backend: 'resolved-owned-link-experimental',
      resolvConfRewrittenByBackend: false, daemonSigkill: true, ownerChangeRefused: true,
      runtimeSettingsSurvivedRestart: true, baselineQueriesDuringProtection: 0, durableResolvedRecoveryImplemented: journal || adapterProcess,
      ...(journalReport ? { journal: journalReport } : {}), ...(adapterReport ? { adapterProcess: adapterReport } : {}) };
  } finally { await resolved?.stop(); await dbus?.stop(); }
}
