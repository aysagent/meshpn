// Loopback session endurance, not a throughput benchmark or a real TUN test.
// C++ generates/verifies all packets. Node runs the legacy reference endpoint
// only in that variant, where it echoes opaque bytes through the old H2 stream.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { startDateExit } from './lib/vpn-http-date-fixture.mjs';

const build = path.resolve(process.env.CVPN_BUILD ?? 'native/clean_vpn/build');
const seconds = Number(process.env.CVPN_SOAK_SECONDS ?? 180);
assert.ok(Number.isInteger(seconds) && seconds >= 10 && seconds <= 600, 'CVPN_SOAK_SECONDS must be 10..600');
test('native session endurance', { concurrency: 2, timeout: (seconds + 30) * 1000 }, async t => {
  await Promise.all(['native-exit', 'legacy-exit'].map(mode => t.test(mode, { timeout: (seconds + 25) * 1000 }, async t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cvpn-soak-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const secret = randomBytes(32), secretPath = path.join(dir, 'psk');
    fs.writeFileSync(secretPath, secret, { mode: 0o600 });
    let endpoint, port;
    if (mode === 'legacy-exit') {
      endpoint = await startDateExit({ protocol: 'h2', secret, onBridge: sock => { sock.on('error', () => {}); sock.pipe(sock); } });
      t.after(() => endpoint.close()); port = endpoint.port;
    } else {
      const listener = net.createServer(); listener.listen(0, '127.0.0.1'); await once(listener, 'listening');
      port = listener.address().port; await new Promise(r => listener.close(r));
    }
    const cert = path.resolve('scripts/fixtures/boring-tls-local.cert.pem'), key = path.resolve('scripts/fixtures/boring-tls-local.key.pem');
    const base = { version: 1, address: '127.0.0.1', port, tun: 'cvtest0', secret_path: secretPath };
    const client = path.join(dir, 'client.json'), server = path.join(dir, 'exit.json');
    fs.writeFileSync(client, JSON.stringify({ ...base, role: 'client', ca: cert, server_name: 'localhost' }));
    fs.writeFileSync(server, JSON.stringify({ ...base, role: 'exit', cert, key }));
    const args = mode === 'legacy-exit' ? [client, 'client-soak', String(seconds)] : [client, server, 'soak', String(seconds)];
    const child = spawn(path.join(build, 'integration-test'), [path.join(build, 'clean-vpn-engine-fixture'), ...args]);
    let output = ''; for (const stream of [child.stdout, child.stderr]) stream.on('data', b => { output += b; });
    const timer = setTimeout(() => child.kill('SIGKILL'), (seconds + 20) * 1000);
    t.after(() => { clearTimeout(timer); child.kill('SIGKILL'); });
    const [status] = await once(child, 'close'); clearTimeout(timer);
    assert.equal(status, 0, output);
    const match = /^soak (.+) PASS$/m.exec(output); assert.ok(match, output);
    const report = JSON.parse(match[1]);
    assert.ok(report.seconds >= seconds && report.bytes > 1024 * 1024);
    assert.equal(report.unexpected_reconnects, 0); assert.equal(report.dropped_packets, 0);
    assert.equal(report.payload_verified, true);
    if (endpoint) assert.equal(endpoint.bridges(), 1, 'one authenticated legacy session for entire soak');
    t.diagnostic(JSON.stringify({ mode, ...report }));
  })));
});
