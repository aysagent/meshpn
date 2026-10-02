import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { createHttpDateRecovery } from './lib/vpn-http-date.mjs';
import { loadTlsDateFixture, startDateExit, fixtureCert } from './lib/vpn-http-date-fixture.mjs';

// Real loopback TLS/HTTP/Bearer; only the JS client clock and clock setter are injected.
// OpenSSL continues checking certificates against the real workstation time.
for (const protocol of ['h2', 'http/1.1']) {
  for (const days of [-1, -2, -30, 30]) {
    test(`${protocol}: ${days} days skew, Date restores time, fresh TLS and Bearer succeed`, { timeout: 10000 }, async () => {
      const secret = randomBytes(32), exit = await startDateExit({ protocol, secret });
      let offset = days * 86400000, corrections = 0;
      const wall = () => Date.now() + offset;
      const recovery = createHttpDateRecovery({ windowMs: 900000, wall, mono: () => performance.now(),
        setClock: ms => { offset = ms - Date.now(); corrections++; }, log() {} });
      const client = loadTlsDateFixture({ wall, recovery });
      try {
        const sock = await client.connectCleanVpnTlsClient({ host: '127.0.0.1', port: exit.port, ca: fixtureCert,
          servername: 'localhost', vpnSecret: secret, tlsHttpVers: protocol === 'http/1.1' ? '1.1' : null });
        assert.equal(corrections, 1); assert.equal(exit.accepts(), 2); assert.equal(exit.bridges(), 1);
        assert.ok(exit.logs.some(s => s.includes('cover_bad_bearer')));
        sock.destroy();
      } finally { await exit.close(); }
    });
  }
  test(`${protocol}: wrong PSK plus skew corrects clock once but never authorizes VPN`, { timeout: 10000 }, async () => {
    const exit = await startDateExit({ protocol, secret: randomBytes(32) });
    let offset = -2 * 86400000, corrections = 0;
    const wall = () => Date.now() + offset;
    const recovery = createHttpDateRecovery({ windowMs: 900000, wall, setClock: ms => { offset = ms - Date.now(); corrections++; }, log() {} });
    const client = loadTlsDateFixture({ wall, recovery });
    const opts = { host: '127.0.0.1', port: exit.port, ca: fixtureCert, servername: 'localhost',
      vpnSecret: randomBytes(32), tlsHttpVers: protocol === 'http/1.1' ? '1.1' : null };
    try {
      await assert.rejects(client.connectCleanVpnTlsClient(opts), /within-Bearer-window/);
      await assert.rejects(client.connectCleanVpnTlsClient(opts), /within-Bearer-window/);
      assert.equal(corrections, 1); assert.equal(exit.bridges(), 0); assert.equal(exit.accepts(), 3);
    } finally { await exit.close(); }
  });
  test(`${protocol}: certificate hostname failure never reaches Date or clock setter`, { timeout: 10000 }, async () => {
    const exit = await startDateExit({ protocol, secret: randomBytes(32) }); let calls = 0;
    const client = loadTlsDateFixture({ recovery: createHttpDateRecovery({ windowMs: 900000, setClock: () => calls++, log() {} }) });
    try {
      await assert.rejects(client.connectCleanVpnTlsClient({ host: '127.0.0.1', port: exit.port, ca: fixtureCert,
        servername: 'wrong.invalid', vpnSecret: randomBytes(32), tlsHttpVers: protocol === 'http/1.1' ? '1.1' : null }), /Hostname\/IP does not match/);
      assert.equal(calls, 0); assert.equal(exit.bridges(), 0);
    } finally { await exit.close(); }
  });
}
