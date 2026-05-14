/**
 * Печать JA3 от текущего boring-tls-helper (для обновления эталона в smoke-тесте).
 * Запуск из корня репо: node scripts/dev-print-boring-tls-ja3.mjs
 */
import { spawn } from 'child_process';
import fs from 'fs';
import net from 'net';
import path from 'path';
import { once } from 'events';
import { fileURLToPath } from 'url';
import { ja3FromTcpBuf } from './lib/tls-clienthello-ja3.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const helper = path.join(root, 'native/boring_tls/build/boring-tls-helper');

const MIN_CA_PEM = `-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUAORrqMrVwEGP4iAuleDLqi9kLU4wDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHdGVzdC1jYTAeFw0yNjA1MTMyMTIxMzNaFw0yNjA1MTQy
MTIxMzNaMBIxEDAOBgNVBAMMB3Rlc3QtY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDIvcq5U4pYfhnUbJc9Sv5OpE4+EWVu7GpGQhBI+C8AU7YwqL32
xp9cb0g9VFB2nkKUCrepzS/YvPHNczhcWUGk4HwJ3Gano2JE09Pl1st958j3cdQk
y4+G/mGTO1gb/kG3G3CtZEn+SJ5LjEbd+C2ScfLrKZj1KL74NTvwucAReD2Yg+54
Laz9cOs9ShFVtSl3gcY1SM5La455y2E/3rkD2Z9/HqT54YtHKVRGT18wkVZf1kXy
SLuyqgMLoeulc0JPxkdtqnfrlY2NZDV5YEnfnXqiuwWn/kokwX9DkGMeOCtPm00l
61972KWvxy5LTwFVGBwknV3htC+d+u4UcAojAgMBAAGjUzBRMB0GA1UdDgQWBBS5
t77zDx2ADSX6Kq7CCs7mUQgxTTAfBgNVHSMEGDAWgBS5t77zDx2ADSX6Kq7CCs7m
UQgxTTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAFa8J4MEZh
RxZ05eEs5ivugCWIXchwzO3IEtOy0EC1W7yuuRkgHR5ONcndsu5UicLK9m+fUhXD
q0fJPOYtE6mS7Ew+0oWT1GXzsrlVD6hpvJaDH0MlPBMuwvbiag6ek6N8zYj8Lqyt
GFM0xqK72kitvVo7KGoAsPgt8GtW87p5vjFb1HRL7WY3jqcvwG+BX++tRk5su7F0
76K/31FjcBoAQhQnpnj+tNZHgZSntLPMPM2/ggXStsJ3tK3b/sx0GLg2gMnYMWoy
bmzyQS9U7ptNTLbcDhdLue3GQo9BWtrLo68WxEokrDenzuahEY86P6hgfNORSZR/
ZZp3qSYtd2O7
-----END CERTIFICATE-----
`;

if (!fs.existsSync(helper)) {
  console.error('missing', helper);
  process.exit(1);
}

const server = net.createServer((sock) => {
  /** @type {Buffer[]} */
  const acc = [];
  sock.on('data', (d) => {
    acc.push(d);
    const buf = Buffer.concat(acc);
    const r = ja3FromTcpBuf(buf);
    if (r) {
      console.log('digest', r.ja3Digest);
      console.log('string', r.ja3String);
      sock.destroy();
    }
  });
});

await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});
const port = /** @type {import('net').AddressInfo} */ (server.address()).port;

const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
await once(child, 'spawn');
const payload = Buffer.from(
  JSON.stringify({
    host: '127.0.0.1',
    port,
    ca_pem: MIN_CA_PEM,
    servername: 'test-ca',
    verify_host: 'test-ca',
    alpn: ['h2', 'http/1.1'],
    handshake_timeout_ms: 5000,
    profile: 'ja3-capture',
  }),
  'utf8',
);
const hdr = Buffer.alloc(4);
hdr.writeUInt32BE(payload.length, 0);
child.stdin.write(hdr);
child.stdin.write(payload);

await Promise.race([
  once(child, 'exit'),
  new Promise((r) => setTimeout(r, 8000)),
]);
server.close();
child.kill('SIGKILL');
