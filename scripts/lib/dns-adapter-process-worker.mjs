/** Private namespace child only. Configuration/secrets arrive over inherited IPC. */
import assert from 'node:assert/strict';
import { readlink, readdir } from 'node:fs/promises';
import { startDnsExitAdapter } from './dns-exit-adapter.mjs';
import { validateAdapterProcessConfig } from './dns-adapter-process.mjs';

let adapter, busy = false, initialized = false, closing = false;
const fail = () => { process.stderr.write('DNS_ADAPTER_WORKER_REFUSED\n'); process.exitCode = 2; };
async function close() {
  closing = true; await adapter?.close();
  await new Promise((resolve) => setImmediate(resolve));
}
async function snapshot() {
  assert.ok(adapter);
  return { owned: adapter.stats(), resources: { fds: (await readdir('/proc/self/fd')).length,
    rss: process.memoryUsage().rss, heapUsed: process.memoryUsage().heapUsed,
    active: process.getActiveResourcesInfo().reduce((counts, key) => ({ ...counts, [key]: (counts[key] ?? 0) + 1 }), {}) } };
}
try {
  assert.equal(process.ppid, 1); assert.notEqual(process.pid, 1); assert.equal(typeof process.send, 'function');
  assert.equal(await readlink('/proc/self'), String(process.pid));
  for (const key of ['net', 'mnt', 'pid']) {
    const scope = await readlink(`/proc/self/ns/${key}`);
    assert.equal(scope, await readlink(`/proc/1/ns/${key}`));
    const parent = process.env[`MESHPN_PARENT_${key === 'mnt' ? 'MNT' : key === 'net' ? 'NET' : 'PID'}NS`];
    assert.ok(parent); assert.notEqual(scope, parent);
  }
  process.on('message', async (message) => {
    let secret;
    try {
      assert.ok(!busy && !closing); busy = true;
      assert.ok(Buffer.byteLength(JSON.stringify(message)) <= 16384);
      assert.ok(Number.isSafeInteger(message.id) && message.id > 0);
      assert.ok(['init', 'stats', 'close'].includes(message.operation));
      if (message.operation === 'init') {
        assert.equal(initialized, false); initialized = true;
        assert.deepEqual(Object.keys(message).sort(), ['config', 'id', 'operation']);
        const config = message.config;
        const profile = validateAdapterProcessConfig(config);
        secret = Buffer.from(config.secretHex, 'hex');
        adapter = await startDnsExitAdapter({ profile, secret,
          publicName: config.publicName, exitAddress: config.exitAddress, exitPort: config.exitPort,
          port: config.port, timeoutMs: 1000, maxInflight: 4, maxTcpConnections: 4, tcpLifetimeMs: 3000 });
        assert.equal(adapter.port, config.port);
      } else { assert.deepEqual(Object.keys(message).sort(), ['id', 'operation']); assert.ok(adapter); }
      if (message.operation === 'close') await close();
      const reply = { id: message.id, port: adapter.port, snapshot: await snapshot() };
      busy = false;
      process.send(reply, (error) => {
        if (error) fail();
        if ((error || closing) && process.connected) process.disconnect();
      });
    } catch {
      fail(); await close().catch(() => {}); if (process.connected) process.disconnect();
    } finally { secret?.fill(0); if (message?.config) message.config.secretHex = ''; }
  });
  process.once('disconnect', () => { close().catch(fail); });
  process.once('SIGTERM', () => { close().then(() => { if (process.connected) process.disconnect(); }).catch(fail); });
} catch { fail(); if (process.connected) process.disconnect(); }
