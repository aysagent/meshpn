/**
 * Дымовый тест boring-tls-helper (после npm run build:boring-tls-helper).
 * Запуск: node scripts/test-boring-tls-smoke.mjs
 */
import { spawn } from 'child_process';
import fs from 'fs';
import net from 'net';
import path from 'path';
import tls from 'tls';
import assert from 'node:assert/strict';
import { once } from 'events';
import test from 'node:test';
import { fileURLToPath } from 'url';
import { ja3ComponentsFromClientHelloBody, ja3FromTcpBuf } from './lib/tls-clienthello-ja3.mjs';
import { ja4FromTcpBuf } from './lib/tls-clienthello-ja4.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const helper = path.join(root, 'native/boring_tls/build/boring-tls-helper');
const LOCAL_KEY = path.join(root, 'scripts/fixtures/boring-tls-local.key.pem');
const LOCAL_CERT = path.join(root, 'scripts/fixtures/boring-tls-local.cert.pem');

/** Эталон JA3 (MD5): pinned BoringSSL + порядок cipher/group в helper; ALPN как clean-vpn (`h2`,`http/1.1`). Обновление: node scripts/dev-print-boring-tls-ja3.mjs */
const EXPECTED_JA3_DIGEST = 'e29d030d028f5cfe3fb65f4e96924e01';

/** Порядок-инвариантный JA3 (сортировка списков после GREASE-filter). Обновление: node scripts/dev-print-boring-tls-ja3.mjs */
const EXPECTED_JA3_SORTED_DIGEST = '3cea5676764a1ee8269a4c66081cc049';

test('ja3_sorted: перестановка типов расширений — разный wire JA3, один sorted MD5', () => {
  /** @param {number[]} extOrder */
  function minimalClientHelloBody(extOrder) {
    const legacy = Buffer.from([0x03, 0x03]);
    const random = Buffer.alloc(32, 0);
    const sid = Buffer.from([0]);
    const ciphers = Buffer.from([0x00, 0x02, 0x13, 0x01]);
    const comp = Buffer.from([1, 0]);
    const ext10 = Buffer.from([0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);
    const ext11 = Buffer.from([0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    /** @type {Buffer[]} */
    const parts = [];
    for (const typ of extOrder) {
      if (typ === 10) parts.push(ext10);
      else if (typ === 11) parts.push(ext11);
    }
    const extBlock = Buffer.concat(parts);
    const extLen = Buffer.alloc(2);
    extLen.writeUInt16BE(extBlock.length, 0);
    return Buffer.concat([legacy, random, sid, ciphers, comp, extLen, extBlock]);
  }
  const a = ja3ComponentsFromClientHelloBody(minimalClientHelloBody([10, 11]));
  const b = ja3ComponentsFromClientHelloBody(minimalClientHelloBody([11, 10]));
  assert.notStrictEqual(a.ja3Digest, b.ja3Digest);
  assert.strictEqual(a.ja3SortedDigest, b.ja3SortedDigest);
});

/** Минимальный валидный PEM (один X509), чтобы helper прошёл LoadCaFromPem; TCP может не установиться. */
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

/**
 * @param {import('stream').Readable} readable
 * @param {number} n
 */
async function readExact(readable, n) {
  /** @type {Buffer[]} */
  const chunks = [];
  let have = 0;
  while (have < n) {
    const chunk = readable.read();
    if (chunk) {
      chunks.push(chunk);
      have += chunk.length;
      continue;
    }
    await once(readable, 'readable');
  }
  const all = Buffer.concat(chunks);
  const head = all.subarray(0, n);
  if (all.length > n) readable.unshift(all.subarray(n));
  return head;
}

/** Один кадр BE u32 + JSON (как у boring-tls-helper). */
async function readJsonFrame(readable) {
  const rh = await readExact(readable, 4);
  const len = rh.readUInt32BE(0);
  assert.ok(len > 0 && len < 512 * 1024);
  const body = await readExact(readable, len);
  return JSON.parse(body.toString('utf8'));
}

/** @template T
 * @param {Promise<T>} promise
 * @param {number} ms
 * @param {string} label
 */
async function raceMs(promise, ms, label) {
  let id;
  try {
    return await Promise.race([
      promise,
      new Promise((_, rej) => {
        id = setTimeout(() => rej(new Error(`${label} (${ms}ms)`)), ms);
      }),
    ]);
  } finally {
    if (id !== undefined) clearTimeout(id);
  }
}

function sendConfigFrame(stdin, jsonObj) {
  const payload = Buffer.from(JSON.stringify(jsonObj), 'utf8');
  const hdr = Buffer.alloc(4);
  hdr.writeUInt32BE(payload.length, 0);
  stdin.write(hdr);
  stdin.write(payload);
}

test('бинарь boring-tls-helper существует после сборки', (t) => {
  if (!fs.existsSync(helper)) {
    t.skip(`нет ${helper} — npm run build:boring-tls-helper`);
    return;
  }
  const st = fs.statSync(helper);
  if (!st.isFile()) {
    t.fail('не файл');
  }
});

test('helper возвращает JSON ok:false на неполный config', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }
  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');
  sendConfigFrame(child.stdin, { host: '127.0.0.1', port: 443 });

  const j = await readJsonFrame(child.stdout);
  assert.strictEqual(j.ok, false);
  const [code] = await once(child, 'exit');
  assert.notStrictEqual(code, 0);
});

test('helper код 2 если stdin закрыт до кадра конфига', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }
  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');
  child.stdin.destroy();
  const [code] = await once(child, 'exit');
  assert.strictEqual(code, 2);
});

test('helper ok:false при отказе TCP (порт без слушателя)', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }
  const closedPort = await new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address();
      const p = typeof addr === 'object' && addr ? addr.port : null;
      s.close((err) => (err ? reject(err) : resolve(p)));
    });
  });

  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');
  sendConfigFrame(child.stdin, {
    host: '127.0.0.1',
    port: closedPort,
    ca_pem: MIN_CA_PEM,
    servername: 'test-ca',
    verify_host: 'test-ca',
    alpn: ['http/1.1'],
    handshake_timeout_ms: 3000,
  });

  const j = await readJsonFrame(child.stdout);
  assert.strictEqual(j.ok, false);
  assert.match(j.error, /tcp connect failed/i);
  const [code] = await once(child, 'exit');
  assert.strictEqual(code, 4);
});

test('helper: TLS 1.3 handshake и ALPN к локальному tls.Server', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }
  if (!fs.existsSync(LOCAL_KEY) || !fs.existsSync(LOCAL_CERT)) {
    t.skip(`нет ${LOCAL_CERT} (fixtures для локального handshake)`);
    return;
  }

  const certPem = fs.readFileSync(LOCAL_CERT, 'utf8');
  const keyPem = fs.readFileSync(LOCAL_KEY, 'utf8');

  const server = tls.createServer({
    key: keyPem,
    cert: certPem,
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    ALPNProtocols: ['http/1.1', 'h2'],
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : null;
  assert.ok(port);

  const connPromise = once(server, 'secureConnection').then(([sock]) => {
    sock.destroy();
  });

  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');

  try {
    sendConfigFrame(child.stdin, {
      host: '127.0.0.1',
      port,
      ca_pem: certPem,
      servername: 'localhost',
      verify_host: 'localhost',
      alpn: ['http/1.1'],
      handshake_timeout_ms: 15000,
    });

    const j = await raceMs(readJsonFrame(child.stdout), 20000, 'ответ helper');
    assert.strictEqual(j.ok, true, JSON.stringify(j));
    assert.strictEqual(j.alpn, 'http/1.1');

    await raceMs(connPromise, 5000, 'secureConnection на сервере');

    child.stdin.destroy();
    const [code] = await raceMs(once(child, 'exit'), 10000, 'выход helper после stdin EOF');
    assert.strictEqual(code, 0);
  } finally {
    server.close();
  }
});

test('helper: JA3 ClientHello (ALPN как у clean-vpn)', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }

  const server = net.createServer();
  const ja3Promise = new Promise((resolve, reject) => {
    server.once('error', reject);
    server.once('connection', (sock) => {
      /** @type {Buffer[]} */
      const acc = [];
      sock.on('data', (d) => {
        acc.push(d);
        const r = ja3FromTcpBuf(Buffer.concat(acc));
        if (r) {
          resolve(r);
          sock.destroy();
        }
      });
      sock.on('error', () => {});
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : null;
  assert.ok(port);

  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');

  try {
    sendConfigFrame(child.stdin, {
      host: '127.0.0.1',
      port,
      ca_pem: MIN_CA_PEM,
      servername: 'test-ca',
      verify_host: 'test-ca',
      alpn: ['h2', 'http/1.1'],
      handshake_timeout_ms: 8000,
    });

    const j = await raceMs(ja3Promise, 15000, 'JA3 из потока');
    assert.strictEqual(
      j.ja3Digest,
      EXPECTED_JA3_DIGEST,
      `обновите эталон (node scripts/dev-print-boring-tls-ja3.mjs) или CMake; ja3String=${j.ja3String}`,
    );
    assert.strictEqual(
      j.ja3SortedDigest,
      EXPECTED_JA3_SORTED_DIGEST,
      `ja3SortedString=${j.ja3SortedString}`,
    );
  } finally {
    try {
      child.kill('SIGKILL');
    } catch {
      /* ignore */
    }
    server.close();
  }
});

test('helper: без log_ja3 на stderr нет ja3_md5', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }
  const closedPort = await new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address();
      const p = typeof addr === 'object' && addr ? addr.port : null;
      s.close((err) => (err ? reject(err) : resolve(p)));
    });
  });

  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');
  let stderr = '';
  child.stderr?.on('data', (b) => {
    stderr += b.toString();
  });

  try {
    sendConfigFrame(child.stdin, {
      host: '127.0.0.1',
      port: closedPort,
      ca_pem: MIN_CA_PEM,
      servername: 'test-ca',
      verify_host: 'test-ca',
      alpn: ['http/1.1'],
      handshake_timeout_ms: 3000,
    });

    await readJsonFrame(child.stdout);
    await once(child, 'exit');
    assert.ok(!stderr.includes('ja3_md5='), stderr);
    assert.ok(!stderr.includes('ja3_sorted_md5='), stderr);
    assert.ok(!stderr.includes('ja4='), stderr);
  } finally {
    try {
      child.kill('SIGKILL');
    } catch {
      /* ignore */
    }
  }
});

test('helper: log_ja3=true — stderr содержит эталонный ja3_md5', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }

  const server = net.createServer();
  const ja3Promise = new Promise((resolve, reject) => {
    server.once('error', reject);
    server.once('connection', (sock) => {
      /** @type {Buffer[]} */
      const acc = [];
      sock.on('data', (d) => {
        acc.push(d);
        const buf = Buffer.concat(acc);
        const j3 = ja3FromTcpBuf(buf);
        const j4 = ja4FromTcpBuf(buf);
        if (j3 && j4) {
          resolve({ j3, j4 });
          sock.destroy();
        }
      });
      sock.on('error', () => {});
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : null;
  assert.ok(port);

  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');
  let stderr = '';
  child.stderr?.on('data', (b) => {
    stderr += b.toString();
  });

  try {
    sendConfigFrame(child.stdin, {
      host: '127.0.0.1',
      port,
      ca_pem: MIN_CA_PEM,
      servername: 'test-ca',
      verify_host: 'test-ca',
      alpn: ['h2', 'http/1.1'],
      handshake_timeout_ms: 8000,
      log_ja3: true,
    });

    const { j4 } = await raceMs(ja3Promise, 15000, 'JA3/JA4 из потока');
    assert.match(stderr, new RegExp(`ja3_md5=${EXPECTED_JA3_DIGEST}`));
    assert.match(stderr, new RegExp(`ja3_sorted_md5=${EXPECTED_JA3_SORTED_DIGEST}`));
    assert.ok(stderr.includes(`ja4=${j4.fingerprint}`), stderr);
  } finally {
    try {
      child.kill('SIGKILL');
    } catch {
      /* ignore */
    }
    server.close();
  }
});

test('helper: SIGTERM после успешного handshake', async (t) => {
  if (process.platform === 'win32') {
    t.skip();
    return;
  }
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }
  if (!fs.existsSync(LOCAL_KEY) || !fs.existsSync(LOCAL_CERT)) {
    t.skip(`нет ${LOCAL_CERT}`);
    return;
  }

  const certPem = fs.readFileSync(LOCAL_CERT, 'utf8');
  const keyPem = fs.readFileSync(LOCAL_KEY, 'utf8');

  const server = tls.createServer({
    key: keyPem,
    cert: certPem,
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    ALPNProtocols: ['http/1.1', 'h2'],
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : null;
  assert.ok(port);

  let heldSock = null;
  const connPromise = once(server, 'secureConnection').then(([sock]) => {
    heldSock = sock;
  });

  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');

  try {
    sendConfigFrame(child.stdin, {
      host: '127.0.0.1',
      port,
      ca_pem: certPem,
      servername: 'localhost',
      verify_host: 'localhost',
      alpn: ['http/1.1'],
      handshake_timeout_ms: 15000,
    });

    const j = await raceMs(readJsonFrame(child.stdout), 20000, 'ответ helper');
    assert.strictEqual(j.ok, true, JSON.stringify(j));
    await raceMs(connPromise, 5000, 'secureConnection на сервере');

    child.kill('SIGTERM');
    const [code, sig] = await raceMs(once(child, 'exit'), 5000, 'выход после SIGTERM');
    assert.strictEqual(sig, 'SIGTERM');
    assert.strictEqual(code, null);
    if (heldSock) heldSock.destroy();
  } finally {
    server.close();
    try {
      child.kill('SIGKILL');
    } catch {
      /* ignore */
    }
  }
});

test('helper: client_hello_profile с дефолтными cipher/groups — тот же JA3', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }

  const server = net.createServer();
  const ja3Promise = new Promise((resolve, reject) => {
    server.once('error', reject);
    server.once('connection', (sock) => {
      /** @type {Buffer[]} */
      const acc = [];
      sock.on('data', (d) => {
        acc.push(d);
        const r = ja3FromTcpBuf(Buffer.concat(acc));
        if (r) {
          resolve(r);
          sock.destroy();
        }
      });
      sock.on('error', () => {});
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : null;
  assert.ok(port);

  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');

  try {
    sendConfigFrame(child.stdin, {
      host: '127.0.0.1',
      port,
      ca_pem: MIN_CA_PEM,
      servername: 'test-ca',
      verify_host: 'test-ca',
      alpn: ['h2', 'http/1.1'],
      handshake_timeout_ms: 8000,
      client_hello_profile: {
        cipher_suites: [4865, 4866, 4867],
        supported_groups: [29, 23, 24],
        ec_point_formats: [0],
        /** Эталон EXPECTED_JA3_DIGEST зафиксирован при фиксированном порядке расширений. */
        permute_extensions: false,
      },
    });

    const j = await raceMs(ja3Promise, 15000, 'JA3 из потока');
    assert.strictEqual(
      j.ja3Digest,
      EXPECTED_JA3_DIGEST,
      `ja3String=${j.ja3String}`,
    );
    assert.strictEqual(
      j.ja3SortedDigest,
      EXPECTED_JA3_SORTED_DIGEST,
      `ja3SortedString=${j.ja3SortedString}`,
    );
  } finally {
    try {
      child.kill('SIGKILL');
    } catch {
      /* ignore */
    }
    server.close();
  }
});

test('helper: client_hello_profile ja3_strict при неверном ja3_md5 — отказ', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }
  if (!fs.existsSync(LOCAL_KEY) || !fs.existsSync(LOCAL_CERT)) {
    t.skip(`нет ${LOCAL_CERT}`);
    return;
  }

  const server = tls.createServer({
    key: fs.readFileSync(LOCAL_KEY, 'utf8'),
    cert: fs.readFileSync(LOCAL_CERT, 'utf8'),
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    ALPNProtocols: ['http/1.1', 'h2'],
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : null;
  assert.ok(port);

  const certPem = fs.readFileSync(LOCAL_CERT, 'utf8');

  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');

  try {
    sendConfigFrame(child.stdin, {
      host: '127.0.0.1',
      port,
      ca_pem: certPem,
      servername: 'localhost',
      verify_host: 'localhost',
      alpn: ['http/1.1'],
      handshake_timeout_ms: 12000,
      client_hello_profile: {
        cipher_suites: [4865, 4866, 4867],
        supported_groups: [29, 23, 24],
        ec_point_formats: [0],
        permute_extensions: false,
        ja3_md5: '00000000000000000000000000000000',
        ja3_strict: true,
      },
      log_ja3: true,
    });

    const j = await raceMs(readJsonFrame(child.stdout), 20000, 'ответ helper');
    assert.strictEqual(j.ok, false);
    assert.match(String(j.error || ''), /ja3 profile mismatch/i);
  } finally {
    server.close();
    try {
      child.kill('SIGKILL');
    } catch {
      /* ignore */
    }
  }
});

test('helper: ja3_strict несовместим с permute_extensions — отказ конфигурации', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }

  const dummy = net.createServer((c) => {
    c.on('error', () => {});
  });
  await new Promise((resolve, reject) => {
    dummy.once('error', reject);
    dummy.listen(0, '127.0.0.1', resolve);
  });
  const addr = dummy.address();
  const port = typeof addr === 'object' && addr ? addr.port : null;
  assert.ok(port);

  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');

  try {
    sendConfigFrame(child.stdin, {
      host: '127.0.0.1',
      port,
      ca_pem: MIN_CA_PEM,
      servername: 'test-ca',
      verify_host: 'test-ca',
      alpn: ['http/1.1'],
      handshake_timeout_ms: 2000,
      client_hello_profile: {
        cipher_suites: [4865, 4866, 4867],
        supported_groups: [29, 23, 24],
        ec_point_formats: [0],
        permute_extensions: true,
        ja3_strict: true,
      },
    });

    const j = await raceMs(readJsonFrame(child.stdout), 8000, 'ответ helper');
    assert.strictEqual(j.ok, false);
    assert.match(String(j.error || ''), /incompatible|permute_extensions/i);
  } finally {
    dummy.close();
    try {
      child.kill('SIGKILL');
    } catch {
      /* ignore */
    }
  }
});

test('helper: permute_extensions — разный wire JA3, один ja3_sorted_md5 за несколько коннектов', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }

  const profile = {
    cipher_suites: [4865, 4866, 4867],
    supported_groups: [29, 23, 24],
    ec_point_formats: [0],
    permute_extensions: true,
  };

  /** @type {Set<string>} */
  const wireDigests = new Set();
  /** @type {string | null} */
  let sortedDigest = null;

  const rounds = 8;
  for (let i = 0; i < rounds; i++) {
    const server = net.createServer();
    const ja3Promise = new Promise((resolve, reject) => {
      server.once('error', reject);
      server.once('connection', (sock) => {
        /** @type {Buffer[]} */
        const acc = [];
        sock.on('data', (d) => {
          acc.push(d);
          const r = ja3FromTcpBuf(Buffer.concat(acc));
          if (r) {
            resolve(r);
            sock.destroy();
          }
        });
        sock.on('error', () => {});
      });
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : null;
    assert.ok(port);

    const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
    await once(child, 'spawn');

    try {
      sendConfigFrame(child.stdin, {
        host: '127.0.0.1',
        port,
        ca_pem: MIN_CA_PEM,
        servername: 'test-ca',
        verify_host: 'test-ca',
        alpn: ['h2', 'http/1.1'],
        handshake_timeout_ms: 8000,
        client_hello_profile: profile,
      });

      const j = await raceMs(ja3Promise, 15000, `JA3 из потока (раунд ${i})`);
      wireDigests.add(j.ja3Digest);
      if (sortedDigest === null) sortedDigest = j.ja3SortedDigest;
      assert.strictEqual(
        j.ja3SortedDigest,
        sortedDigest,
        `ja3SortedString=${j.ja3SortedString}`,
      );
    } finally {
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
      server.close();
    }
  }

  assert.ok(
    wireDigests.size >= 2,
    `ожидались ≥2 различных wire JA3 за ${rounds} попыток, получено: ${[...wireDigests].join(', ')}`,
  );
});

test('helper: дубликат cipher id в client_hello_profile — отказ', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }

  const dummy = net.createServer((c) => {
    c.on('error', () => {});
  });
  await new Promise((resolve, reject) => {
    dummy.once('error', reject);
    dummy.listen(0, '127.0.0.1', resolve);
  });
  const addr = dummy.address();
  const port = typeof addr === 'object' && addr ? addr.port : null;
  assert.ok(port);

  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');

  try {
    sendConfigFrame(child.stdin, {
      host: '127.0.0.1',
      port,
      ca_pem: MIN_CA_PEM,
      servername: 'test-ca',
      verify_host: 'test-ca',
      alpn: ['http/1.1'],
      handshake_timeout_ms: 2000,
      client_hello_profile: {
        cipher_suites: [4865, 4865],
        supported_groups: [29],
        ec_point_formats: [0],
      },
    });

    const j = await raceMs(readJsonFrame(child.stdout), 8000, 'ответ helper');
    assert.strictEqual(j.ok, false);
    assert.match(String(j.error || ''), /SSL_CTX_set_tls13_client_cipher_order/i);
  } finally {
    dummy.close();
    try {
      child.kill('SIGKILL');
    } catch {
      /* ignore */
    }
  }
});

test('helper: cipher_suites с префиксом TLS 1.2 (как в JA3) — TLS 1.3 порядок сохраняется, handshake OK', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }
  if (!fs.existsSync(LOCAL_KEY) || !fs.existsSync(LOCAL_CERT)) {
    t.skip(`нет ${LOCAL_CERT}`);
    return;
  }

  const certPem = fs.readFileSync(LOCAL_CERT, 'utf8');
  const server = tls.createServer({
    key: fs.readFileSync(LOCAL_KEY, 'utf8'),
    cert: certPem,
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    ALPNProtocols: ['http/1.1', 'h2'],
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : null;
  assert.ok(port);

  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');

  try {
    sendConfigFrame(child.stdin, {
      host: '127.0.0.1',
      port,
      ca_pem: certPem,
      servername: 'localhost',
      verify_host: 'localhost',
      alpn: ['http/1.1'],
      handshake_timeout_ms: 15000,
      client_hello_profile: {
        cipher_suites: [
          49195,
          49196,
          4865,
          4867,
          4866,
        ],
        supported_groups: [29, 23, 24],
        ec_point_formats: [0],
      },
    });

    const j = await raceMs(readJsonFrame(child.stdout), 20000, 'ответ helper');
    assert.strictEqual(j.ok, true, JSON.stringify(j));
  } finally {
    server.close();
    try {
      child.kill('SIGKILL');
    } catch {
      /* ignore */
    }
  }
});

test('helper: неизвестный named group id в client_hello_profile — отказ', async (t) => {
  if (!fs.existsSync(helper)) {
    t.skip();
    return;
  }

  const dummy = net.createServer((c) => {
    c.on('error', () => {});
  });
  await new Promise((resolve, reject) => {
    dummy.once('error', reject);
    dummy.listen(0, '127.0.0.1', resolve);
  });
  const addr = dummy.address();
  const port = typeof addr === 'object' && addr ? addr.port : null;
  assert.ok(port);

  const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  await once(child, 'spawn');

  try {
    sendConfigFrame(child.stdin, {
      host: '127.0.0.1',
      port,
      ca_pem: MIN_CA_PEM,
      servername: 'test-ca',
      verify_host: 'test-ca',
      alpn: ['http/1.1'],
      handshake_timeout_ms: 2000,
      client_hello_profile: {
        cipher_suites: [4865, 4866, 4867],
        supported_groups: [11111],
        ec_point_formats: [0],
      },
    });

    const j = await raceMs(readJsonFrame(child.stdout), 8000, 'ответ helper');
    assert.strictEqual(j.ok, false);
    assert.match(String(j.error || ''), /named group id/i);
  } finally {
    dummy.close();
    try {
      child.kill('SIGKILL');
    } catch {
      /* ignore */
    }
  }
});
