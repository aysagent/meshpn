/** Linux namespace fixture ONLY. Not a reusable system DNS/firewall backend. */
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import { once } from 'node:events';
import { readFile, realpath, writeFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { namespaceResources } from './browser-soak.mjs';
import { exec } from './browser-lab-driver.mjs';
import { runCommand, cleanEnvironment } from './transparent-acceptance.mjs';
import { startAdapterSoakLab } from './dns-adapter-soak-lab.mjs';
import { drainAdapter, assertAdapterIdle } from './dns-adapter-soak.mjs';
import { makeDnsQuery, fixtureDnsAnswer, validateDnsResponse } from './lab-dns-wire.mjs';
import { queryLabDns } from './transparent-dns-lab.mjs';
import { dnsLifecycle } from './dns-lifecycle.mjs';
import { runDnsCrashLab } from './dns-lifecycle-crash-lab.mjs';
import { runResolvedLab } from './dns-resolved-lab.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
export { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';

async function sentinel(address) {
  const udp = dgram.createSocket(address.includes(':') ? 'udp6' : 'udp4');
  const sockets = new Set(); let hits = 0;
  const answer = (query) => { hits++; return fixtureDnsAnswer(query, { rdata: Buffer.from([203, 0, 113, 8]) }); };
  const tcp = net.createServer((socket) => {
    sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket));
    socket.setTimeout(2000, () => socket.destroy()); let data = Buffer.alloc(0), replied = false;
    socket.on('data', (chunk) => {
      if (replied || data.length + chunk.length > 4096) { socket.destroy(); return; }
      data = Buffer.concat([data, chunk]);
      if (data.length < 2 || data.length < data.readUInt16BE(0) + 2) return;
      try {
        assert.equal(data.length, data.readUInt16BE(0) + 2);
        const reply = answer(data.subarray(2)), prefix = Buffer.alloc(2); prefix.writeUInt16BE(reply.length);
        replied = true; socket.end(Buffer.concat([prefix, reply]));
      } catch { socket.destroy(); }
    });
  });
  udp.on('message', (query, peer) => {
    try { udp.send(answer(query), peer.port, peer.address, () => {}); } catch { /* malformed fixture query */ }
  });
  const close = async () => {
    for (const socket of sockets) socket.destroy();
    await Promise.all([
      new Promise((resolve) => { try { udp.close(resolve); } catch { resolve(); } }),
      new Promise((resolve) => tcp.listening ? tcp.close(resolve) : resolve()),
    ]);
  };
  try {
    udp.bind(53, address); await once(udp, 'listening');
    tcp.listen(53, address); await once(tcp, 'listening');
    return { hits: () => hits, close };
  } catch (error) { await close(); throw error; }
}

export async function runDnsLifecycleLab(directory, family, { crash = false, resolved = false } = {}) {
  await assertDnsMountNamespace();
  assert.ok([4, 6].includes(family));
  assert.deepEqual(JSON.parse((await exec('ip', ['-j', 'link', 'show'])).stdout).map((l) => l.ifname), ['lo']);
  await exec('ip', ['link', 'set', 'lo', 'up']);
  // Never edit a host inode: mount new synthetic files over namespace-local paths.
  // Hide nscd Unix sockets too: network namespaces do not isolate pathname sockets.
  const targets = await Promise.all(['/etc/resolv.conf', '/etc/nsswitch.conf'].map((path) => realpath(path)));
  const empty = join(directory, 'empty-run'); await mkdir(empty);
  await exec('mount', ['--bind', empty, '/run']);
  for (const target of targets) if (target.startsWith('/run/')) {
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, '', { flag: 'wx', mode: 0o600 });
  }
  const baseline = 'nameserver 127.0.0.55\noptions timeout:1 attempts:1\n';
  const managed = 'nameserver 127.0.0.53\noptions timeout:1 attempts:1\n';
  const foreign = 'nameserver ::1\noptions timeout:1 attempts:1\n';
  let fileId = 0;
  async function bindText(target, contents) {
    const path = join(directory, `mount-${fileId++}`);
    await writeFile(path, contents, { flag: 'wx', mode: 0o600 });
    await exec('mount', ['--bind', path, target]);
    assert.equal(await readFile(target, 'utf8'), contents);
  }
  await bindText('/etc/resolv.conf', baseline);
  await bindText('/etc/nsswitch.conf', 'hosts: dns\n');
  const observers = []; let lab, state = 'idle', snapshot, guard = false, selected = false;
  const steps = [], checks = []; let lookupNumber = 0;
  const hits = () => observers.reduce((n, server) => n + server.hits(), 0);
  const env = cleanEnvironment(process.env);
  for (const key of ['RES_OPTIONS', 'LOCALDOMAIN', 'HOSTALIASES', 'LD_PRELOAD', 'LD_AUDIT']) delete env[key];
  async function lookup(label, expected, tcp = false, queryFamily = 4) {
    const result = await runCommand('getent', ['-A', '-s', 'dns', `ahostsv${queryFamily}`, `lifecycle-${++lookupNumber}.test`],
      { env: { ...env, RES_OPTIONS: `timeout:1 attempts:1${tcp ? ' use-vc' : ''}` }, timeoutMs: 5000 });
    assert.equal(result.reason, null, label);
    assert.equal(result.code, expected ? 0 : 2, `${label}: ${result.stderr}`);
    if (expected) assert.ok(result.stdout.split('\n').filter(Boolean).every((line) => line.startsWith(`${expected} `)), label);
    else assert.equal(result.stdout, '', label);
    checks.push(label);
  }
  async function setGuard(enabled) {
    if (guard === enabled) return;
    for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
      await exec(tool, ['-w', '2', enabled ? '-A' : '-D', 'OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT']);
    }
    guard = enabled;
  }
  async function redirect(enabled) {
    for (const protocol of ['udp', 'tcp']) await exec('iptables', ['-w', '2', '-t', 'nat', enabled ? '-A' : '-D', 'OUTPUT',
      '-d', '127.0.0.53', '-p', protocol, '--dport', '53', '-j', 'DNAT', '--to-destination', `127.0.0.1:${lab.adapter.port}`]);
  }
  async function event(name) {
    const current = await readFile('/etc/resolv.conf', 'utf8');
    const owned = snapshot !== undefined && current === (selected ? managed : snapshot);
    const result = dnsLifecycle(state, name, { optIn: true, owned });
    steps.push({ from: state, event: name, ...result }); state = result.state;
    for (const action of result.actions) {
      if (action === 'snapshot') { assert.equal(snapshot, undefined); snapshot = current; }
      if (action === 'install-guard') await setGuard(true);
      if (action === 'probe-protected-dns') {
        const query = makeDnsQuery('readiness.test');
        const reply = await queryLabDns(lab.adapter.port, query);
        assert.equal(validateDnsResponse(reply, query).flags & 15, 0, 'protected readiness probe failed');
      }
      if (action === 'select-managed-dns') { assert.ok(owned && guard); await bindText('/etc/resolv.conf', managed); selected = true; }
      if (action === 'restore-snapshot') { assert.ok(owned && guard); await bindText('/etc/resolv.conf', snapshot); selected = false; }
      if (action === 'remove-guard') await setGuard(false);
      if (action === 'forget-snapshot') snapshot = undefined;
      // Adapter lifetime is fixture-owned; start/stop actions are proposals only.
    }
  }
  try {
    observers.push(await sentinel('127.0.0.55'));
    observers.push(await sentinel('::1'));
    lab = await startAdapterSoakLab({ family, modeTag: 'combo-tls', concurrency: 4 }, directory);
    await redirect(true);
    await lookup('baseline-udp-positive-control', '203.0.113.8');
    await lookup('baseline-tcp-positive-control', '203.0.113.8', true);
    await bindText('/etc/resolv.conf', foreign);
    await lookup('ipv6-resolver-udp-positive-control', '203.0.113.8');
    await lookup('ipv6-resolver-tcp-positive-control', '203.0.113.8', true);
    await bindText('/etc/resolv.conf', baseline);
    const before = hits(); assert.ok(before >= 4);
    await event('enable');
    // Baseline remains selected during preparation, but the guard already blocks it.
    await lookup('pre-selection-baseline-blocked', null);
    await event('ready'); await event('selected');
    await lookup('managed-udp', '192.0.2.123'); await lookup('managed-tcp', '192.0.2.123', true);
    await lookup('managed-aaaa-udp', '2001:db8::12', false, 6); await lookup('managed-aaaa-tcp', '2001:db8::12', true, 6);
    await lab.stopExit(); await event('failure');
    await lookup('exit-down-udp-no-fallback', null); await lookup('exit-down-tcp-no-fallback', null, true);
    assert.equal(await readFile('/etc/resolv.conf', 'utf8'), managed);
    await lab.restartExit(); await event('recover'); await event('ready'); await event('selected');
    await lookup('exit-recovered', '192.0.2.123');
    // Loss of the namespace-only port-53 mapping models an unavailable listener.
    await redirect(false); await event('failure');
    await lookup('listener-unavailable-udp', null); await lookup('listener-unavailable-tcp', null, true);
    await redirect(true); await event('recover'); await event('ready'); await event('selected');
    await lookup('listener-recovered', '192.0.2.123');
    await bindText('/etc/resolv.conf', foreign); await event('external-change'); await event('disable');
    assert.equal(state, 'conflict'); assert.equal(await readFile('/etc/resolv.conf', 'utf8'), foreign);
    await lookup('foreign-ipv6-udp-blocked', null); await lookup('foreign-ipv6-tcp-blocked', null, true);
    await bindText('/etc/resolv.conf', baseline);
    await lookup('foreign-ipv4-udp-blocked', null); await lookup('foreign-ipv4-tcp-blocked', null, true);
    assert.equal(hits(), before, 'plaintext DNS reached a baseline resolver while opted in');
    // Simulated operator resolves conflict; never automatically overwrite foreign config.
    await bindText('/etc/resolv.conf', managed);
    await event('disable');
    assert.equal(await readFile('/etc/resolv.conf', 'utf8'), baseline);
    await lookup('restored-but-still-guarded', null);
    assert.equal(hits(), before);
    await event('restored'); await event('released');
    await lookup('explicit-disable-restores-baseline', '203.0.113.8');
    assert.ok(hits() > before);
    // Failed readiness before takeover also retains guard until explicit disable.
    await lab.stopExit();
    await assert.rejects(event('enable'), /protected readiness probe failed/); await event('failure');
    const failedBefore = hits(); await lookup('startup-failure-blocked', null); assert.equal(hits(), failedBefore);
    await event('disable'); await event('restored'); await event('released');
    await lookup('startup-failure-explicit-disable', '203.0.113.8');
    let crashReport;
    if (crash) {
      await lab.restartExit();
      crashReport = await runDnsCrashLab({ directory, baseline, managed, bindText, setGuard, lookup, hits, lab,
        async probe() {
          const query = makeDnsQuery('crash-readiness.test');
          assert.equal(validateDnsResponse(await queryLabDns(lab.adapter.port, query), query).flags & 15, 0);
        } });
    }
    await drainAdapter(lab);
    await redirect(false);
    let resolvedReport;
    if (resolved) {
      await lab.restartExit();
      resolvedReport = await runResolvedLab({ directory, lab, bindText, setGuard, lookup, hits });
      await drainAdapter(lab);
    }
    await lab.close(); assertAdapterIdle(lab.stats());
    await Promise.all(observers.map((server) => server.close())); observers.length = 0;
    await new Promise((resolve) => setTimeout(resolve, 20));
    const resources = namespaceResources();
    assert.equal(resources.tree.live, 1); assert.equal(resources.tree.zombies, 0);
    for (const kind of ['TCPSocketWrap', 'TCPServerWrap', 'UDPWrap', 'ProcessWrap', 'Timeout']) {
      assert.equal(resources.worker.active[kind] ?? 0, 0, kind);
    }
    assert.equal(state, 'idle'); assert.equal(guard, false); assert.equal(snapshot, undefined);
    return { schema: 1, status: 'passed', kind: 'dns-lifecycle-lab', family, modeTag: 'combo-tls',
      backend: 'namespace-resolv.conf-fixture', hostDnsChanged: false, persistentRecoveryImplemented: false,
      ...(crashReport ? { crash: crashReport } : {}),
      ...(resolvedReport ? { resolved: resolvedReport } : {}),
      checks, steps, baselineQueriesDuringProtection: 0, dnsCalls: lab.stats().dnsCalls,
      final: { state, resources } };
  } finally { await lab?.close(); await Promise.all(observers.map((server) => server.close())); }
}
