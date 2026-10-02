/** DESTRUCTIVE CLOCK TEST: only in a marked, NIC-less, disposable QEMU guest. */
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { createHttpDateRecovery } from './vpn-http-date.mjs';
import { loadTlsDateFixture, startDateExit, fixtureCert } from './vpn-http-date-fixture.mjs';

assert.ok(fs.readFileSync('/proc/cmdline', 'utf8').split(/\s+/).includes('meshpn.http-date-lab=1'));
assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
assert.deepEqual(JSON.parse(execFileSync('ip', ['-j', 'link'], { encoding: 'utf8' })).map(l => l.ifname), ['lo']);
execFileSync('ip', ['link', 'set', 'lo', 'up']);
const baseline = Date.now(), start = performance.now();
// An independent logical exit clock: Linux netns do NOT isolate CLOCK_REALTIME.
const exitWall = () => baseline + performance.now() - start;
const set = ms => execFileSync('/usr/bin/date', ['-u', '-s', `@${Math.floor(ms / 1000)}`], { timeout: 3000, stdio: 'pipe' });
const check = (name, ok) => { assert.ok(ok, name); console.log('HTTP_DATE_CHECK ' + name); };
try {
  for (const protocol of ['h2', 'http/1.1']) {
    for (const days of [-1, -2, -30, 30, 365]) {
      set(exitWall());
      const secret = randomBytes(32), exit = await startDateExit({ protocol, secret, wall: exitWall });
      // Use the production setter, not a mock. A fresh controller models a fresh client process.
      const client = loadTlsDateFixture({ recovery: createHttpDateRecovery({ windowMs: 900000 }) });
      try {
        set(exitWall() + days * 86400000);
        check(`${protocol} actual kernel clock skew ${days} days`, Math.abs(Date.now() - exitWall() - days * 86400000) < 3000);
        const sock = await client.connectCleanVpnTlsClient({ host: '127.0.0.1', port: exit.port, ca: fixtureCert,
          servername: 'localhost', vpnSecret: secret, tlsHttpVers: protocol === 'http/1.1' ? '1.1' : null });
        check(`${protocol} kernel clock restored from Date ${days} days`, Math.abs(Date.now() - exitWall()) < 5000);
        check(`${protocol} new TLS handshake and valid Bearer ${days} days`, exit.accepts() === 2 && exit.bridges() === 1);
        sock.destroy();
      } finally { await exit.close(); set(exitWall()); }
    }
    for (const year of [2017, 2040]) {
      const exit = await startDateExit({ protocol, secret: randomBytes(32), wall: exitWall });
      const client = loadTlsDateFixture({ recovery: createHttpDateRecovery({ windowMs: 900000 }) });
      try {
        set(Date.UTC(year, 7, 4));
        await assert.rejects(client.connectCleanVpnTlsClient({ host: '127.0.0.1', port: exit.port, ca: fixtureCert,
          servername: 'localhost', vpnSecret: randomBytes(32), tlsHttpVers: protocol === 'http/1.1' ? '1.1' : null }), /certificate/i);
        check(`${protocol} ${year} certificate failure does not bypass validation or change time`, new Date().getUTCFullYear() === year && exit.bridges() === 0);
      } finally { await exit.close(); set(exitWall()); }
    }
  }
  console.log('HTTP_DATE_PASS');
} catch (error) {
  console.error('HTTP_DATE_FAIL ' + error.stack);
  process.exitCode = 1;
} finally { set(exitWall()); }
