/** Persistent real adapter and public pinned route on namespace-local IP aliases. */
import assert from 'node:assert/strict';
import net from 'node:net';
import https from 'node:https';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { exec } from './browser-lab-driver.mjs';
import { assertBrowserNamespace } from './browser-soak.mjs';
import { compileDnsUpstream, dnsUpstreamExitPolicy } from './dns-upstream-config.mjs';
import { startDnsExitAdapter } from './dns-exit-adapter.mjs';
import { wireTransparentTlsEncSniSession } from './transparent-tls-runtime.mjs';
import { EncSniReplayGuard } from './transparent-tls-replay.mjs';
import { fixtureDnsAnswer, parseDnsQuery } from './lab-dns-wire.mjs';
import { createNamespaceDnsAdapter } from './dns-adapter-process.mjs';
import { assertSystemdDnsVm } from './dns-systemd-vm-safety.mjs';

export async function startAdapterSoakLab({ family, modeTag, concurrency, timeoutMs = 250 }, directory) {
  assertBrowserNamespace(); assert.ok([4, 6].includes(family)); assert.ok(['transparent-tls', 'combo-tls'].includes(modeTag));
  const links = JSON.parse((await exec('ip', ['-j', 'link', 'show'])).stdout);
  assert.deepEqual(links.map((l) => l.ifname), ['lo']);
  return startFixture({ family, modeTag, concurrency, timeoutMs }, directory);
}

export async function startSystemdVmAdapterFixture(directory) {
  await assertSystemdDnsVm();
  const links = JSON.parse((await exec('ip', ['-j', 'link', 'show'])).stdout);
  assert.deepEqual(links.map((l) => l.ifname).sort(), ['dnsfixture', 'lo']);
  return startFixture({ family: 4, modeTag: 'combo-tls', concurrency: 4, timeoutMs: 5000, port: 2053, replace: true }, directory);
}

async function startFixture({ family, modeTag, concurrency, timeoutMs, port = 0, replace = false }, directory) {
  const addresses = family === 4 ? ['93.184.216.34', '93.184.216.35', '93.184.216.36']
    : ['2606:4700::1112', '2606:4700::1111', '2606:4700::1113'];
  for (const ip of addresses) await exec('ip', [family === 4 ? '-4' : '-6', 'addr', replace ? 'replace' : 'add', `${ip}/${family === 4 ? 32 : 128}`,
    'dev', 'lo', ...(family === 6 ? ['nodad'] : [])]);
  const keyPath = join(directory, 'key.pem'), certPath = join(directory, 'cert.pem');
  await exec('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-x509', '-days', '1', '-subj', '/CN=resolver.test',
    '-addext', 'subjectAltName=DNS:resolver.test', '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', keyPath, '-out', certPath]);
  const key = await readFile(keyPath), cert = await readFile(certPath, 'utf8');
  const resolverSockets = new Set(), exitSockets = new Set(), sessions = new Set();
  const track = (set, socket) => { set.add(socket); socket.on('error', () => {}); socket.once('close', () => set.delete(socket)); return socket; };
  let mode = 'normal', exitMode = 'normal', bodies = 0, dnsCalls = 0, attempts = 0, adapter, processAdapter, closePromise;
  const replayGuard = new EncSniReplayGuard(), secret = randomBytes(32), publicName = 'relay.test';
  const origin = https.createServer({ key, cert, minVersion: 'TLSv1.3', maxHeaderSize: 8192 }, (req, res) => {
    req.on('error', () => {}); res.on('error', () => {});
    const chunks = []; let length = 0;
    req.on('data', (chunk) => { length += chunk.length; if (length > 4096) req.destroy(); else chunks.push(chunk); });
    req.on('end', () => {
      const packet = Buffer.concat(chunks); parseDnsQuery(packet); bodies++;
      assert.equal(req.method, 'POST'); assert.equal(req.url, '/dns-query');
      assert.equal(req.headers.host, `resolver.test:${origin.address().port}`); assert.equal(req.socket.servername, 'resolver.test');
      if (mode === 'hold') return;
      if (mode === 'reset') { res.socket.destroy(); return; }
      if (mode === 'redirect') { res.writeHead(302, { location: 'http://resolver.test:53' }).end(); return; }
      res.writeHead(200, { 'content-type': 'application/dns-message' }).end(fixtureDnsAnswer(packet, {
        count: mode === 'large' ? 40 : 1, rcode: mode === 'nxdomain' ? 3 : 0,
      }));
    });
  });
  origin.on('connection', (s) => track(resolverSockets, s)); origin.on('tlsClientError', () => {});
  let policy, originPort, exitPort;
  const exit = net.createServer((socket) => {
    track(exitSockets, socket);
    if (exitMode === 'hold') { socket.resume(); return; }
    const session = wireTransparentTlsEncSniSession(socket, { vpnSecretBuf: secret, publicName, destinationPolicy: policy, replayGuard, modeTag,
      connectOrigin(address, port, ipFamily) {
        attempts++; assert.ok(addresses.slice(0, 2).includes(address)); assert.equal(port, originPort); assert.equal(ipFamily, family);
        return track(exitSockets, net.connect({ host: address, port, family, autoSelectFamily: false }));
      } });
    if (session) { sessions.add(session); session.closed.then(() => sessions.delete(session)); }
  });
  const listen = async (server, port, address) => { server.listen(port, address); await once(server, 'listening'); return server.address().port; };
  const stop = async (server, sockets) => {
    const closed = new Promise((resolve) => server.listening ? server.close(resolve) : resolve());
    for (const socket of sockets) socket.destroy(); await closed;
  };
  async function close() {
    closePromise ??= (async () => {
      await processAdapter?.close(); await adapter?.close(); await stop(exit, exitSockets); await Promise.all([...sessions].map((s) => s.closed));
      await stop(origin, resolverSockets); secret.fill(0);
    })(); return closePromise;
  }
  try {
    originPort = await listen(origin, 0, addresses[1]);
    const profileConfig = { schema: 1, transport: 'doh', hostname: 'resolver.test', port: originPort, path: '/dns-query',
      bootstrap: { addresses: addresses.slice(0, 2) }, trust: { mode: 'custom', certificates: [cert] } };
    const profile = compileDnsUpstream(profileConfig);
    policy = dnsUpstreamExitPolicy(profile, { lookup: () => { dnsCalls++; throw new Error('lookup forbidden'); } });
    exitPort = await listen(exit, 0, addresses[2]);
    adapter = await startDnsExitAdapter({ profile, secret, publicName, exitAddress: addresses[2], exitPort,
      port, timeoutMs, maxInflight: concurrency, maxTcpConnections: concurrency, tcpLifetimeMs: Math.max(3000, timeoutMs) });
    const stats = () => ({ ...adapter.stats(), resolverSockets: resolverSockets.size, resolverBodies: bodies,
      exitSockets: exitSockets.size, sessions: sessions.size, relayTimers: [...sessions].reduce((n, s) => n + s.timers.size, 0),
      dnsCalls, attempts, replay: replayGuard.stats() });
    return { adapter, stub: { port: adapter.port, stats: () => adapter.stats().stub }, stats, close,
      async createProcessAdapter() {
        assert.equal(processAdapter, undefined); await adapter.close();
        processAdapter = await createNamespaceDnsAdapter({ profile: profileConfig, secretHex: secret.toString('hex'),
          publicName, exitAddress: addresses[2], exitPort, port: adapter.port });
        return processAdapter;
      },
      relay: { stats: () => ({ sockets: exitSockets.size, pendingClients: 0, relaySessions: sessions.size,
        relayTimers: stats().relayTimers, cleanupFailures: 0 }) },
      setMode(value) { assert.ok(['normal', 'nxdomain', 'large', 'hold', 'reset', 'redirect'].includes(value)); mode = value; },
      setExitMode(value) { assert.ok(['normal', 'hold'].includes(value)); exitMode = value; },
      cutExit() { for (const s of exitSockets) s.destroy(); },
      stopExit: () => stop(exit, exitSockets), restartExit: () => listen(exit, exitPort, addresses[2]),
      stopOrigin: () => stop(origin, resolverSockets), restartOrigin: () => listen(origin, originPort, addresses[1]),
      endpoints: { stub: { address: '127.0.0.1', port: adapter.port }, exit: { address: addresses[2], port: exitPort },
        resolver: { address: addresses[1], port: originPort }, refused: { address: addresses[0], port: originPort } },
    };
  } catch (error) { await close(); throw error; }
}
