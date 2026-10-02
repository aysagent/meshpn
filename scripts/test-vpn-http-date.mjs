import test from 'node:test';
import assert from 'node:assert/strict';
import { createHttpDateRecovery, parseHttpDate, responseHeaders, vpnResponseAccepted, CLOCK_UPDATED } from './lib/vpn-http-date.mjs';

const windowMs = 900000, epoch = Date.UTC(2026, 9, 2, 20, 1, 22);
const date = new Date(epoch).toUTCString();
function fixture(skew = -86400000, overrides = {}) {
  let now = epoch + skew, monotonic = 100, calls = 0;
  const cert = { raw: Buffer.from('test'), valid_from: 'Jan 1 00:00:00 2020 GMT', valid_to: 'Jan 1 00:00:00 2036 GMT' };
  cert.issuerCertificate = cert;
  const socket = { encrypted: true, authorized: true, getPeerCertificate: () => cert };
  const recovery = createHttpDateRecovery({ windowMs, wall: () => now, mono: () => monotonic,
    setClock: ms => { calls++; now = ms; }, log() {}, ...overrides });
  return { recovery, socket, cert, calls: () => calls, now: () => now,
    tick: ms => { now += ms; monotonic += ms; }, jump: ms => { now += ms; },
    reject: () => recovery.begin(socket)({ date }, 'VPN rejected') };
}
test('HTTP Date uses seconds, UTC, canonical syntax and calendar validation', () => {
  assert.equal(parseHttpDate(date), epoch);
  for (const v of [undefined, null, [date], date + ', ' + date, '2026-10-02T20:01:22Z', date.replace('Fri', 'Mon'), date.replace('GMT', 'UTC'), date.replace('02 Oct', '32 Oct'), date.replace('20:01:22', '20:01:60')])
    assert.equal(parseHttpDate(v), null);
});
test('200 cover is not a VPN; duplicate content-type/Date preserved and rejected', () => {
  assert.equal(vpnResponseAccepted(200, 'application/octet-stream'), true);
  for (const [s, t] of [[200, 'text/plain'], [403, 'application/octet-stream'], [200, undefined], [200, ['application/octet-stream']]])
    assert.equal(vpnResponseAccepted(s, t), false);
  const h = responseHeaders(`HTTP/1.1 200 OK\r\nDate: ${date}\r\ndate: ${date}\r\nContent-Type: text/plain`);
  assert.equal(parseHttpDate(h.date), null);
});
for (const skew of [-86400000, -2 * 86400000, -30 * 86400000, -365 * 86400000, 365 * 86400000]) {
  test(`clock skew ${skew / 86400000} days: one adjustment, no day-count restriction`, () => {
    const f = fixture(skew);
    assert.equal(f.reject().code, CLOCK_UPDATED); assert.equal(f.now(), epoch); assert.equal(f.calls(), 1);
    f.jump(skew);
    assert.match(f.reject().message, /attempt-already-used/); assert.equal(f.calls(), 1);
  });
}
test('near clocks / wrong-key-like rejection never set time', () => {
  for (const skew of [-600000, 0, 600000]) { const f = fixture(skew); assert.match(f.reject().message, /within-Bearer-window/); assert.equal(f.calls(), 0); }
});
test('boundary uncertainty (second precision + RTT) does not force a time step', () => {
  const server = Math.floor(epoch / windowMs) * windowMs + windowMs - 1000;
  const f = fixture(); f.jump(server + windowMs + 1000 - f.now());
  const reject = f.recovery.begin(f.socket); f.tick(2000);
  assert.match(reject({ date: new Date(server).toUTCString() }, 'rejected').message, /within-Bearer-window/);
  assert.equal(f.calls(), 0);
});
test('plaintext, unverified TLS, missing certificate and helper pipes cannot set time', () => {
  for (const change of [{ encrypted: false }, { authorized: false }, { authorizationError: 'bad cert' }, { getPeerCertificate: () => ({}) }]) {
    const f = fixture(); Object.assign(f.socket, change);
    assert.match(f.reject().message, /verified-native-TLS-required/); assert.equal(f.calls(), 0);
  }
});
test('late, cached, duplicate, missing Date, reused response and concurrent clock change refused', () => {
  const f = fixture(); const late = f.recovery.begin(f.socket); f.tick(5001);
  assert.match(late({ date }, 'reject').message, /stale-response/);
  for (const headers of [{}, { date: [date, date] }, { date, age: '0' }]) {
    assert.match(f.recovery.begin(f.socket)(headers, 'reject').message, /missing-invalid-or-cached-Date/);
  }
  const concurrent = f.recovery.begin(f.socket); f.jump(10000);
  assert.match(concurrent({ date }, 'reject').message, /clock-changed-during-request/);
  assert.match(concurrent({ date }, 'reject').message, /response-already-used/);
  assert.equal(f.calls(), 0);
});
test('Date must fit certificate validity, including intermediates', () => {
  for (const field of ['valid_from', 'valid_to']) {
    const f = fixture(); f.cert.issuerCertificate = { ...f.cert, issuerCertificate: null,
      [field]: new Date(epoch + (field === 'valid_from' ? 86400000 : -86400000)).toUTCString() };
    assert.match(f.reject().message, /Date-outside-certificate-validity/); assert.equal(f.calls(), 0);
  }
});
test('failed or ineffective clock setter consumes attempt without breaking retry loop', () => {
  for (const setter of [() => { throw Error('EPERM'); }, () => {}]) {
    const f = fixture(-86400000, { setClock: setter });
    assert.match(f.reject().message, /set-failed/);
    assert.match(f.reject().message, /attempt-already-used/);
  }
});
