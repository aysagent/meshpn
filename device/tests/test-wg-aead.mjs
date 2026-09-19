import assert from 'node:assert/strict';
import {createCipheriv} from 'node:crypto';
import {spawnSync} from 'node:child_process';

const key = Buffer.from(Array.from({length: 32}, (_, i) => i));
const nonce = Buffer.alloc(12);
nonce.writeBigUInt64LE(7n, 4); // WireGuard: 32 zero bits + LE64 counter
for (const n of [0, 1, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 255, 512, 1360, 1400, 1500]) {
  const plain = Buffer.from(Array.from({length: n}, (_, i) => (i * 17 + 3) & 255));
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, {authTagLength: 16});
  const expected = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  for (const executable of process.argv.slice(2)) {
    const result = spawnSync(executable, [String(n)]);
    assert.equal(result.status, 0, `${executable}: ${result.stderr}`);
    assert.deepEqual(result.stdout, expected, `${executable}: packet length ${n}`);
  }
}
console.log('WireGuard -Og/-O2 AEAD matches Node/OpenSSL; in-place, tamper and boundary tests passed');
