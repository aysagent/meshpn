#!/usr/bin/env node
/** Namespace-only execution of the reusable client guard; never a host installer. */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import dgram from 'node:dgram';
import net from 'node:net';
import { readlink, readFile } from 'node:fs/promises';
import { randomBytes, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { namespaceArgs } from './lib/browser-soak.mjs';
import { assertDnsMountNamespace } from './lib/dns-lifecycle-namespace.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';
import { compileDnsClientGuard, createDnsClientGuard } from './lib/dns-client-guard.mjs';
import { sentinel } from './lib/dns-lifecycle-lab.mjs';
import { child } from './lib/browser-lab-driver.mjs';
import { makeDnsQuery, validateDnsResponse } from './lib/lab-dns-wire.mjs';
import { startDnsmasqUsbPeer, startDnsmasqUpstreamPeer } from './lib/dnsmasq-usb-peer.mjs';

async function isolated() {
  await assertDnsMountNamespace();
  const run = (file, args, input) => {
    const result = spawnSync(file, args, { input, encoding: 'utf8', timeout: 5000, maxBuffer: 262144,
      env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' } });
    assert.equal(result.error, undefined); assert.equal(result.status, 0, result.stderr); return result.stdout;
  };
  assert.deepEqual(JSON.parse(run('/usr/bin/ip', ['-j', 'link'])).map((l) => l.ifname), ['lo']);
  run('/usr/bin/ip', ['link', 'set', 'lo', 'up']);
  const binaries = (family, suffix = '') => `/usr/sbin/${family === 4 ? 'iptables' : 'ip6tables'}${suffix}`;
  const read = async (family) => run(binaries(family), ['-w', '2', '-S']);
  const restore = async (family, batch) => run(binaries(family, '-restore'), ['--wait', '2', '--noflush'], batch);
  const versions = [4, 6].map((family) => run(binaries(family), ['--version']).trim());
  const observers = [], checks = []; let peer, upstream, dhcp;
  const check = (name) => checks.push(name);
  const query = async (address, tcp, allowed) => {
    const packet = makeDnsQuery('guard-fixture.test');
    assert.ok(['127.0.0.53', '127.0.0.1', '127.0.0.55', '::1'].includes(address));
    const socket = tcp ? net.connect({ host: address, port: 53 }) : dgram.createSocket(address.includes(':') ? 'udp6' : 'udp4');
    let timer;
    try {
      const request = new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error('DNS deadline'), { code: 'DNS_CLIENT_TIMEOUT' })), allowed ? 1000 : 200);
        socket.once('error', reject);
        if (tcp) {
          let buffer = Buffer.alloc(0);
          socket.once('connect', () => { const length = Buffer.alloc(2); length.writeUInt16BE(packet.length); socket.write(Buffer.concat([length, packet])); });
          socket.on('end', () => reject(new Error('DNS EOF')));
          socket.on('data', (data) => {
            buffer = Buffer.concat([buffer, data]);
            if (buffer.length > 65537) return reject(new Error('DNS size'));
            if (buffer.length >= 2 && buffer.length === buffer.readUInt16BE(0) + 2) resolve(buffer.subarray(2));
          });
        } else socket.connect(53, address, () => { socket.once('message', resolve); socket.send(packet); });
      });
      if (allowed) assert.equal(validateDnsResponse(await request, packet).rcode, 0);
      else await assert.rejects(request, { code: 'DNS_CLIENT_TIMEOUT' });
    } finally { clearTimeout(timer); if (tcp) socket.destroy(); else socket.close(); }
  };
  try {
    for (const address of ['127.0.0.53', '127.0.0.1', '127.0.0.55', '::1']) observers.push(await sentinel(address));
    for (const tcp of [false, true]) for (const addr of ['127.0.0.53', '127.0.0.55', '::1']) await query(addr, tcp, true);
    check('positive-baseline-udp-tcp-ipv4-ipv6');
    // Foreign unrelated policy must survive install/release byte-for-byte.
    run(binaries(4), ['-A', 'OUTPUT', '-p', 'tcp', '--dport', '45678', '-j', 'ACCEPT']);
    const before = await Promise.all([4, 6].map(read));
    const input = { schema: 1, client: 'vps2', id: randomBytes(16).toString('hex') };
    let fail6 = true, injectReleaseConflict = false, conflictingSnapshot;
    const ownedChain = compileDnsClientGuard(input).families[0].chains[0].name;
    const guard = createDnsClientGuard({ input, read, assertContext: assertDnsMountNamespace,
      restore: async (family, batch) => {
        if (family === 6 && fail6) throw new Error('injected family failure');
        if (family === 4 && injectReleaseConflict && !batch.includes('\n-N ')) {
          injectReleaseConflict = false;
          run(binaries(4), ['-A', ownedChain, '-p', 'udp', '--dport', '5353', '-j', 'RETURN']);
          conflictingSnapshot = await read(4);
        }
        await restore(family, batch);
      } });
    await assert.rejects(guard.ensure(), /injected family/);
    assert.deepEqual(await guard.inspect(), ['present', 'absent']);
    for (const tcp of [false, true]) await query('127.0.0.55', tcp, false);
    check('partial-family-install-retains-ipv4-deny');
    fail6 = false; await guard.ensure(); await guard.ensure();
    assert.deepEqual(await guard.inspect(), ['present', 'present']);
    const blockedBefore = observers[2].hits() + observers[3].hits();
    for (const tcp of [false, true]) {
      await query('127.0.0.53', tcp, true);
      await query('127.0.0.55', tcp, false); await query('::1', tcp, false);
    }
    assert.equal(observers[2].hits() + observers[3].hits(), blockedBefore);
    check('vps2-stub-allowed-direct-dns-both-families-blocked');
    run(binaries(4), ['-A', 'OUTPUT', '-d', '127.0.0.53', '-p', 'udp', '--dport', '53', '-j', 'DROP']);
    await query('127.0.0.53', false, false);
    run(binaries(4), ['-D', 'OUTPUT', '-d', '127.0.0.53', '-p', 'udp', '--dport', '53', '-j', 'DROP']);
    check('local-return-does-not-bypass-existing-firewall');
    run(binaries(4), ['-I', 'OUTPUT', '1', '-p', 'udp', '--dport', '53', '-j', 'ACCEPT']);
    const conflict = await read(4);
    await assert.rejects(guard.ensure(), /not first/); await assert.rejects(guard.release(async () => true), /not first/);
    assert.equal(await read(4), conflict);
    run(binaries(4), ['-D', 'OUTPUT', '-p', 'udp', '--dport', '53', '-j', 'ACCEPT']); // explicit fixture repair
    check('foreign-preceding-rule-refused-not-overwritten');
    await assert.rejects(guard.release(async () => false));
    injectReleaseConflict = true;
    await assert.rejects(guard.release(async () => true));
    assert.equal(await read(4), conflictingSnapshot, 'failed release batch must not partially delete hooks/rules');
    run(binaries(4), ['-D', ownedChain, '-p', 'udp', '--dport', '5353', '-j', 'RETURN']);
    assert.deepEqual(await guard.inspect(), ['present', 'present']);
    check('concurrent-chain-edit-aborts-release-batch-without-flush');
    await guard.release(async () => true);
    assert.deepEqual(await Promise.all([4, 6].map(read)), before);
    for (const tcp of [false, true]) await query('::1', tcp, true);
    check('explicit-release-preserves-unrelated-firewall');

    peer = await startDnsmasqUsbPeer(); upstream = await startDnsmasqUpstreamPeer();
    const executable = process.env.MESHPN_DNSMASQ;
    assert.ok(executable?.startsWith('/'), 'absolute MESHPN_DNSMASQ required for isolated USB DHCP fixture');
    dhcp = child(executable, ['--no-daemon', '--conf-file=/dev/null', '--port=0', '--no-resolv', '--no-hosts', '--bind-interfaces', '--interface=usb0',
      '--dhcp-range=192.168.7.10,192.168.7.50,255.255.255.0,12h', '--dhcp-option=3,192.168.7.1', '--dhcp-option=6,192.168.7.1',
      '--dhcp-leasefile=/dev/null', '--pid-file=', '--log-facility=-']);
    await dhcp.waitFor(/DHCP, IP range/, 5000);
    assert.deepEqual((await peer.acquire()).stages, ['DISCOVER', 'OFFER', 'REQUEST', 'ACK']);
    run('/usr/bin/ip', ['-6', 'addr', 'add', '2001:db8:53::1/128', 'dev', 'lo', 'nodad']);
    run('/usr/bin/ip', ['addr', 'add', '1.1.1.1/32', 'dev', 'lo']);
    observers.push(await sentinel('192.168.7.1'), await sentinel('2001:db8:53::1'), await sentinel('1.1.1.1'));
    for (const tcp of [false, true]) for (const family of [4, 6]) {
      const answer = await peer.lookup({ direct: true, forwarded: true, family, tcp }); assert.equal(answer.outcome, 'dns-response');
    }
    for (const tcp of [false, true]) for (const family of [4, 6]) assert.equal((await peer.lookup({ direct: true, family, tcp })).outcome, 'dns-response');
    check('usb-forward-positive-controls-both-families');
    const radxa = createDnsClientGuard({ input: { ...input, client: 'radxa', id: randomBytes(16).toString('hex'), usbInterface: 'usb0', usbAddress: '192.168.7.1' },
      read, restore, assertContext: assertDnsMountNamespace });
    await radxa.ensure();
    assert.deepEqual((await peer.acquire()).stages, ['DISCOVER', 'OFFER', 'REQUEST', 'ACK']);
    check('usb-dhcp-dora-preserved-under-guard');
    const hits = await upstream.hits(), inputHits = observers[5].hits() + observers[6].hits(), directHits = observers[2].hits();
    for (const tcp of [false, true]) {
      for (const address of ['127.0.0.1', '::1']) await query(address, tcp, true);
      await query('127.0.0.55', tcp, false);
      assert.equal((await peer.lookup({ tcp })).outcome, 'dns-response');
      for (const options of [{ forwarded: true, family: 4 }, { forwarded: true, family: 6 }, { family: 4 }, { family: 6 }]) {
        const answer = await peer.lookup({ ...options, direct: true, tcp }); assert.equal(answer.outcome, 'client-deadline');
      }
    }
    assert.deepEqual(await upstream.hits(), hits); assert.equal(observers[5].hits() + observers[6].hits(), inputHits); assert.equal(observers[2].hits(), directHits);
    check('radxa-localhost-usb-dns-preserved-direct-output-input-forward-blocked');
    await radxa.release(async () => true);
    assert.deepEqual(await Promise.all([4, 6].map(read)), before);
    for (const tcp of [false, true]) assert.equal((await peer.lookup({ direct: true, forwarded: true, family: 6, tcp })).outcome, 'dns-response');
    check('radxa-release-restores-forwarding-baseline');
    return { schema: 1, kind: 'clean-vpn-dns-client-guard-lab', status: 'passed', checks, versions,
      hostNetworkChanged: false, durableGuardJournalImplemented: false, liveInstaller: false };
  } finally { await dhcp?.stop(); await peer?.close(); await upstream?.close(); await Promise.all(observers.map((s) => s.close())); }
}

async function main() {
  const args = process.argv.slice(2);
  assert.ok(args.length === 0 || args.length === 1 && args[0] === '--isolated', 'no host apply option');
  if (args[0] === '--isolated') { console.log(JSON.stringify(await isolated())); return; }
  const env = { ...cleanEnvironment(process.env), MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'),
    MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid'), MESHPN_PARENT_MNTNS: await readlink('/proc/self/ns/mnt') };
  assert.ok(env.MESHPN_DNSMASQ?.startsWith('/'), 'absolute MESHPN_DNSMASQ required');
  const snapshot = () => Promise.all(['/etc/resolv.conf', '/etc/nsswitch.conf', '/proc/sys/net/ipv4/ip_forward', '/proc/sys/net/ipv6/conf/all/forwarding']
    .map(async (path) => createHash('sha256').update(await readFile(path)).digest('hex')));
  const before = await snapshot();
  const controller = new AbortController(), abort = () => controller.abort();
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  let result;
  try {
    result = await runCommand('unshare', [...namespaceArgs.map((arg) => arg === '--map-current-user' ? '--map-root-user' : arg),
      '--propagation', 'private', process.execPath, fileURLToPath(import.meta.url), '--isolated'], { env, signal: controller.signal, timeoutMs: 60000 });
  } finally { process.off('SIGINT', abort); process.off('SIGTERM', abort); assert.deepEqual(await snapshot(), before); }
  assert.equal(result.reason, null); assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout); assert.equal(report.status, 'passed');
  report.hostDnsFilesAndForwardingUnchanged = true;
  console.log(JSON.stringify(report, null, 2));
}
main().catch((error) => { console.error(`DNS_CLIENT_GUARD_LAB_FAILED ${error.stack}`); process.exitCode = 1; });
