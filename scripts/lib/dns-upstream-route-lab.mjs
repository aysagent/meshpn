/** Real pinned-IP DoH in a private namespace, never on a host uplink. */
import assert from 'node:assert/strict';
import net from 'node:net';
import https from 'node:https';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { exec } from './browser-lab-driver.mjs';
import { assertBrowserNamespace, namespaceResources } from './browser-soak.mjs';
import { compileDnsUpstream, dnsUpstreamTlsOptions, dnsUpstreamExitPolicy } from './dns-upstream-config.mjs';
import { attachTransparentTlsClientSession, wireTransparentTlsEncSniSession } from './transparent-tls-runtime.mjs';
import { EncSniReplayGuard } from './transparent-tls-replay.mjs';
import { makeDnsQuery, fixtureDnsAnswer, validateDnsResponse, DNS_MAX_BYTES } from './lab-dns-wire.mjs';
import { sizedTxtAnswer, paddedDnsQuery, negativeSoaAnswer } from './dns-wire-fixtures.mjs';
import { startDnsExitAdapter } from './dns-exit-adapter.mjs';
import { queryLabDns } from './transparent-dns-lab.mjs';

export async function runPinnedDnsRouteLab(directory, modeTag, family, { adapter = false } = {}) {
  assertBrowserNamespace();
  assert.ok(['transparent-tls', 'combo-tls'].includes(modeTag)); assert.ok([4, 6].includes(family));
  const links = JSON.parse((await exec('ip', ['-j', 'link', 'show'])).stdout);
  assert.deepEqual(links.map((x) => x.ifname), ['lo']);
  // These addresses exist only inside this net namespace. No default route/NIC.
  const addresses = family === 4 ? ['93.184.216.34', '93.184.216.35'] : ['2606:4700::1112', '2606:4700::1111'];
  const exitAddress = adapter ? (family === 4 ? '93.184.216.36' : '2606:4700::1113') : '127.0.0.1';
  for (const ip of [...addresses, ...(adapter ? [exitAddress] : [])]) await exec('ip', [family === 6 ? '-6' : '-4', 'addr', 'add', `${ip}/${family === 6 ? 128 : 32}`, 'dev', 'lo', ...(family === 6 ? ['nodad'] : [])]);
  const keyPath = join(directory, 'key.pem'), certPath = join(directory, 'cert.pem');
  await exec('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-x509', '-days', '1',
    '-subj', '/CN=resolver.test', '-addext', 'subjectAltName=DNS:resolver.test', '-keyout', keyPath, '-out', certPath]);
  const key = await readFile(keyPath), cert = await readFile(certPath, 'utf8');
  const sockets = new Set(), sessions = [], servers = [], attempts = [], errors = [];
  const track = (socket) => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); return socket; };
  const listen = async (server, port, address) => { if (!servers.includes(server)) servers.push(server); server.listen(port, address); await once(server, 'listening'); return server.address().port; };
  let bodies = 0, mode = 'normal', dnsCalls = 0, result;
  const forbiddenLookup = () => { dnsCalls++; throw new Error('DNS_FORBIDDEN'); };
  const secret = randomBytes(32), publicName = 'relay.test';
  const origin = https.createServer({ key, cert, minVersion: 'TLSv1.3' }, (req, res) => {
    req.on('error', () => {}); res.on('error', () => {});
    const chunks = []; let size = 0;
    req.on('data', (data) => { size += data.length; if (size > DNS_MAX_BYTES) req.destroy(); else chunks.push(data); });
    req.on('end', () => {
      bodies++;
      assert.equal(req.method, 'POST'); assert.equal(req.url, '/dns-query'); assert.equal(req.socket.servername, 'resolver.test');
      if (mode === 'reset') { res.socket.destroy(); return; }
      const packet = Buffer.concat(chunks), headers = { 'content-type': 'application/dns-message' };
      if (mode === 'age') headers.age = '250';
      if (mode === 'negative-age') headers.age = '30';
      const body = mode === 'large' ? sizedTxtAnswer(packet, DNS_MAX_BYTES)
        : mode === 'negative-age' ? negativeSoaAnswer(packet) : fixtureDnsAnswer(packet, { ttl: mode === 'age' ? 600 : 30 });
      res.writeHead(200, headers).end(body);
    });
  });
  origin.on('connection', track); origin.on('tlsClientError', () => {});
  try {
    const port = await listen(origin, 0, addresses[1]);
    const input = { schema: 1, transport: 'doh', hostname: 'resolver.test', port, path: '/dns-query',
      bootstrap: { addresses }, trust: { mode: 'custom', certificates: [cert] } };
    const profile = compileDnsUpstream(input), policy = dnsUpstreamExitPolicy(profile, { lookup: forbiddenLookup });
    const replayGuard = new EncSniReplayGuard();
    const exit = net.createServer((socket) => {
      sessions.push(wireTransparentTlsEncSniSession(track(socket), { vpnSecretBuf: secret, publicName, destinationPolicy: policy,
        replayGuard, modeTag, onSessionError: (error) => errors.push(error.code),
        connectOrigin(address, port, ipFamily) {
          assert.ok(addresses.includes(address)); assert.equal(ipFamily, family);
          attempts.push(address);
          // Exactly the runtime's numeric connect options; real peer checked by runtime.
          return track(net.connect({ host: address, port, family: ipFamily, autoSelectFamily: false }));
        } }));
    });
    const exitPort = await listen(exit, 0, exitAddress);
    const client = net.createServer((socket) => {
      attachTransparentTlsClientSession(track(socket), { vpnSecretBuf: secret, publicName,
        upstreamHost: '127.0.0.1', upstreamPort: exitPort, explicitDestination: { address: addresses[1], port },
      }).then((session) => sessions.push(session), () => {});
    });
    const clientPort = adapter ? null : await listen(client, 0, '127.0.0.1');
    async function query(identity = profile, tcp = false, type = 1, packet = makeDnsQuery('private-pinned.dns-lab.test', type, 1234)) {
      if (adapter) {
        const instance = await startDnsExitAdapter({ profile: identity, exitAddress, exitPort, publicName, secret, timeoutMs: 2000 });
        try {
          const bytes = await queryLabDns(instance.port, packet, { tcp, fragment: tcp });
          const reply = validateDnsResponse(bytes, packet);
          assert.notEqual(reply.flags & 15, 2, 'adapter SERVFAIL'); return { ...reply, wireBytes: bytes.length };
        } finally {
          await instance.close();
          for (const field of ['sockets', 'jobs']) assert.equal(instance.stats().transport[field], 0);
          for (const field of ['inflight', 'tcpSockets', 'tlsSockets', 'requests', 'jobs', 'timers']) assert.equal(instance.stats().stub[field], 0);
        }
      }
      return new Promise((resolve, reject) => {
        const request = https.request({ host: '127.0.0.1', port: clientPort, ...dnsUpstreamTlsOptions(identity),
          path: identity.path, method: 'POST', agent: false, lookup: forbiddenLookup,
          headers: { host: identity.authority, 'content-type': 'application/dns-message', 'content-length': packet.length },
        }, (response) => {
          const chunks = []; let size = 0;
          response.on('error', reject); response.on('aborted', () => reject(new Error('aborted')));
          response.on('data', (data) => { size += data.length; if (size > 4096) request.destroy(new Error('size')); else chunks.push(data); });
          response.on('end', () => {
            try { assert.equal(response.statusCode, 200); resolve(validateDnsResponse(Buffer.concat(chunks), packet)); }
            catch (error) { reject(error); }
          });
        });
        request.on('socket', track); request.on('error', reject);
        request.setTimeout(2000, () => request.destroy(new Error('timeout'))); request.end(packet);
      });
    }
    assert.equal((await query()).counts[0], 1); assert.deepEqual(attempts, addresses);
    assert.equal(bodies, 1);
    const untrusted = compileDnsUpstream({ ...input, trust: { mode: 'bundled' } });
    await assert.rejects(query(untrusted)); assert.equal(bodies, 1);
    mode = 'reset'; const before = attempts.length;
    await assert.rejects(query()); await delay(30);
    assert.equal(attempts.length, before + 2, 'no retry after TCP selection / DNS body'); assert.equal(bodies, 2);
    // Close only the resolver listener; existing request sockets have drained.
    await new Promise((resolve) => origin.close(resolve));
    const failedBefore = attempts.length;
    await assert.rejects(query()); assert.equal(attempts.length, failedBefore + 2);
    assert.ok(errors.includes('TLS_RELAY_CONNECT_EXHAUSTED')); assert.equal(dnsCalls, 0);
    mode = 'normal'; await listen(origin, port, addresses[1]);
    assert.equal((await query()).counts[0], 1); assert.equal(bodies, 3); assert.equal(dnsCalls, 0);
    if (adapter) for (const [tcp, type] of [[true, 1], [false, 28], [true, 28]]) assert.equal((await query(profile, tcp, type)).counts[0], 1);
    if (adapter) {
      const packet = makeDnsQuery('private-pinned.dns-lab.test', 16, 1234, 65535);
      mode = 'large';
      assert.equal((await query(profile, false, 16, packet)).flags & 0x200, 0x200);
      assert.equal((await query(profile, true, 16, packet)).wireBytes, DNS_MAX_BYTES);
      mode = 'normal';
      assert.equal((await query(profile, true, 16, paddedDnsQuery(packet, DNS_MAX_BYTES))).counts[0], 1);
      const version = Buffer.from(packet); version.writeUInt32BE(0xff0000, version.length - 6);
      const before = attempts.length;
      for (const tcp of [false, true]) assert.equal((await query(profile, tcp, 16, version)).rcode, 16);
      assert.equal(attempts.length, before, 'local BADVERS must not dial exit');
      mode = 'age'; assert.equal((await query()).records[0].ttl, 350);
      mode = 'negative-age'; assert.equal((await query()).records[0].ttl, 30);
    }
    result = { status: 'passed', modeTag, family, adapter, requests: adapter ? 15 : 5, resolverBodies: bodies,
      tcpAttempts: attempts.length, dnsCalls, exhausted: true, noRetryAfterBody: true, recovered: true };
  } finally {
    for (const s of sockets) s.destroy();
    await Promise.all(sessions.filter(Boolean).map((s) => s.closed));
    await Promise.all(servers.map((server) => new Promise((resolve) => server.listening ? server.close(resolve) : resolve())));
    await delay(30); assert.equal(sockets.size, 0);
    for (const s of sessions.filter(Boolean)) assert.equal(s.timers.size, 0);
  }
  const resources = namespaceResources(); assert.equal(resources.tree.live, 1); assert.equal(resources.tree.zombies, 0);
  for (const name of ['Timeout', 'TCPSocketWrap', 'TCPServerWrap', 'ProcessWrap']) assert.equal(resources.worker.active[name] ?? 0, 0);
  return { ...result, resources };
}
