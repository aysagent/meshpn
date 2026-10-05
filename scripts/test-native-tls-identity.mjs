// Real TLS/H2 against the legacy endpoint. Loopback only, generated test keys.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import net from 'node:net';
import http2 from 'node:http2';
import { loadTlsDateFixture } from './lib/vpn-http-date-fixture.mjs';

async function certificateExit({ secret, cert, key }) {
  const api = loadTlsDateFixture(), sockets = new Set(); let bridges = 0;
  const h2 = http2.createSecureServer({ cert, key, minVersion: 'TLSv1.3', ALPNProtocols: ['h2'] });
  h2.on('sessionError', () => {});
  const server = net.createServer(sock => {
    sockets.add(sock); sock.once('close', () => sockets.delete(sock));
    api.wireExitHttp2VpnInjected(sock, Buffer.alloc(0), { vpnSecret: secret, tlsExitHttp2Server: h2,
      startBridge: () => { bridges++; } });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return { port: server.address().port, bridges: () => bridges,
    async close() { for (const sock of sockets) sock.destroy(); await new Promise(r => server.close(r)); h2.close(); } };
}

const build = path.resolve(process.env.CVPN_BUILD ?? 'native/clean_vpn/build');
test('native TLS identity compatibility and fail-closed verification', { timeout: 60000 }, async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cvpn-identity-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  function openssl(...args) {
    const r = spawnSync('openssl', args, { cwd: dir, encoding: 'utf8', timeout: 10000 });
    assert.equal(r.status, 0, r.stderr);
  }
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem',
    '-days', '2', '-subj', '/CN=trial-identity-ca', '-addext', 'basicConstraints=critical,CA:TRUE');
  openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=clean-vpn');
  openssl('req', '-new', '-key', 'leaf.key', '-out', 'public.csr', '-subj', '/CN=other.example');
  fs.writeFileSync(path.join(dir, 'index'), '');
  fs.writeFileSync(path.join(dir, 'serial'), '01\n');
  const ca = fs.readFileSync(path.join(dir, 'ca.pem')), key = fs.readFileSync(path.join(dir, 'leaf.key'));
  const secret = randomBytes(32);
  fs.writeFileSync(path.join(dir, 'psk'), secret, { mode: 0o600 });
  for (const [name, san, verifyName, expected, dates] of [
    ['CN-only legacy', '', 'clean-vpn', null],
    ['DNS SAN', 'DNS:clean-vpn', 'clean-vpn', null],
    ['SAN takes precedence over matching CN', 'DNS:other.example', 'clean-vpn', 'tls_verify_name'],
    ['wrong CN', '', 'wrong.example', 'tls_verify_name'],
    ['wrong legacy CN', '', 'clean-vpn', 'tls_verify_name'],
    ['public CN-only still requires SAN', '', 'other.example', 'tls_verify_name'],
    ['expired', '', 'clean-vpn', 'tls_verify_expired', ['20200101000000Z', '20200102000000Z']],
    ['not yet valid', '', 'clean-vpn', 'tls_verify_not_yet_valid', ['20990101000000Z', '20990102000000Z']],
    ['untrusted CA', '', 'clean-vpn', 'tls_verify_untrusted'],
  ]) await t.test(name, async () => {
    fs.writeFileSync(path.join(dir, 'ca.cnf'), `[ca]\ndefault_ca=local\n[local]\ndatabase=index\nserial=serial\nnew_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\ndefault_md=sha256\ndefault_days=1\npolicy=policy\nunique_subject=no\nx509_extensions=leaf\n[policy]\ncommonName=supplied\n[leaf]\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n${san ? 'subjectAltName=' + san + '\n' : ''}`);
    const csr = ['DNS SAN', 'wrong legacy CN', 'public CN-only still requires SAN'].includes(name) ? 'public.csr' : 'leaf.csr';
    openssl('ca', '-batch', '-notext', '-config', 'ca.cnf', '-in', csr, '-out', 'leaf.pem',
      ...(dates ? ['-startdate', dates[0], '-enddate', dates[1]] : []));
    const server = await certificateExit({ secret, cert: fs.readFileSync(path.join(dir, 'leaf.pem')), key });
    try {
      if (!expected) {
        const wire = await loadTlsDateFixture().connectCleanVpnTlsClient({ host: '127.0.0.1', port: server.port,
          ca, servername: 'cover.example', verifyServername: verifyName, vpnSecret: secret });
        wire.on('error', () => {}); wire.destroy();
      }
      const config = path.join(dir, 'client.json');
      fs.writeFileSync(config, JSON.stringify({ version: 1, role: 'client', address: '127.0.0.1', port: server.port,
        tun: 'cvtest0', secret_path: path.join(dir, 'psk'), server_name: verifyName, sni: 'cover.example',
        ca: name === 'untrusted CA' ? path.resolve('scripts/fixtures/boring-tls-local.cert.pem') : path.join(dir, 'ca.pem') }));
      const child = spawn(path.join(build, 'integration-test'), [path.join(build, 'clean-vpn-engine-fixture'), config,
        expected ? 'client-reject:' + expected : 'client-handshake']);
      let output = ''; for (const stream of [child.stdout, child.stderr]) stream.on('data', b => { output += b; });
      const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
      try { const [code] = await once(child, 'close'); assert.equal(code, 0, output); }
      finally { clearTimeout(timer); child.kill('SIGKILL'); }
      if (expected) { assert.doesNotMatch(output, /"state":"ready"/); assert.equal(server.bridges(), 0); }
      else assert.equal(server.bridges(), 2, 'both legacy and native authenticated');
    } finally { await server.close(); }
  });
});
