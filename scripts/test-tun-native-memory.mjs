import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { instrumentTunMemory } from './lib/usb-native-diagnostics.mjs';

test('real native TUN packet ownership, failure cleanup and bounded slabs without GC', { skip: process.platform !== 'linux' }, async t => {
  const headers = process.env.MESHPN_LAB_NODE_HEADERS ?? path.join(os.homedir(), '.cache/node-gyp', process.versions.node, 'include/node');
  assert.ok(fs.existsSync(path.join(headers, 'node_api.h')), 'Node headers required; set MESHPN_LAB_NODE_HEADERS');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'meshpn-tun-packets-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const source = instrumentTunMemory(fs.readFileSync('native/tun_linux/tun_linux.cc', 'utf8'));
  const anchor = 'static napi_value init(napi_env env, napi_value exports) {';
  assert.equal(source.split(anchor).length, 2);
  fs.writeFileSync(path.join(dir, 'tun.cc'), source.replace(anchor, anchor + '\n  napi_value inject; napi_create_function(env, "labInject", NAPI_AUTO_LENGTH, lab_inject, nullptr, &inject); napi_set_named_property(env, exports, "labInject", inject);'));
  const addon = path.join(dir, 'tun.node');
  execFileSync('g++', ['-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-DNAPI_VERSION=8', '-DNODE_GYP_MODULE_NAME=tun_linux',
    '-I', headers, `-DMESHPN_TUN_SOURCE="${path.join(dir, 'tun.cc')}"`, 'scripts/lib/tun-packet-test-fixture.cc', '-o', addon]);
  const tun = createRequire(import.meta.url)(addon);
  const clean = () => {
    const n = tun.labMemoryStats();
    assert.equal(n.inUse, 0); assert.ok(n.pool <= 33); assert.ok(n.backingBytes <= 33 * 65535);
    assert.equal(n.externalCreated, 0); assert.equal(n.externalFinalized, 0);
  };
  const inject = (packets, mode = 0, at = -1, callback) => {
    let calls = 0, held;
    tun.labInject(packets, items => {
      calls++; held = items;
      assert.equal(items.length, packets.length);
      items.forEach((ab, i) => { assert.ok(ab instanceof ArrayBuffer); assert.equal(ab.byteLength, packets[i].length); assert.deepEqual(Buffer.from(ab), packets[i]); });
      callback?.(items);
    }, mode, at);
    clean(); return { calls, held };
  };
  await t.test('exact packet lengths, maximum packet, empty read and retained data after pool reuse', () => {
    for (const size of [1, 40, 64, 1400, 1500, 8192, 65535]) {
      const expected = Buffer.alloc(size, size % 251), { calls, held } = inject([expected]);
      assert.equal(calls, 1);
      for (let i = 0; i < 10; i++) inject([Buffer.alloc(size, 0xa5)]);
      assert.deepEqual(Buffer.from(held[0]), expected);
    }
    assert.equal(inject([]).calls, 0);
  });
  const batch = Array.from({ length: 32 }, (_, i) => Buffer.alloc(64 + i, i));
  await t.test('every allocation and array-insertion failure returns each slab exactly once', () => {
    for (const mode of [1, 2]) for (let at = 0; at < batch.length; at++) {
      assert.equal(inject(batch, mode, at).calls, 0);
      assert.equal(inject(batch).calls, 1);
    }
  });
  await t.test('throwing JS callback cannot retain or double-return native slabs', () => {
    assert.throws(() => inject(batch, 0, -1, () => { throw Error('callback fault'); }), /callback fault/);
    clean(); assert.equal(inject(batch).calls, 1);
  });
  await t.test('100000 retained small JS packets do not retain 65535-byte slabs', () => {
    const held = [];
    for (let i = 0; i < 3125; i++) held.push(...inject(batch).held);
    assert.equal(held.length, 100000);
    for (const index of [0, 31, 99999]) assert.deepEqual(Buffer.from(held[index]), batch[index % 32]);
    const n = tun.labMemoryStats();
    assert.ok(n.copiedPackets >= 100000); clean();
  });
});
