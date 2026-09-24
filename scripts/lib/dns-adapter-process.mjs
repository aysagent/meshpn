/** Explicit, bounded process lifetime for the namespace lab; no automatic restart or host service. */
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { cleanEnvironment } from './transparent-acceptance.mjs';
import { compileDnsUpstream } from './dns-upstream-config.mjs';
import { isPublicRelayAddress } from './transparent-tls-destination.mjs';

export function validateAdapterProcessConfig(config) {
  assert.ok(config && typeof config === 'object' && !Array.isArray(config));
  assert.deepEqual(Object.keys(config).sort(), ['exitAddress', 'exitPort', 'port', 'profile', 'publicName', 'secretHex']);
  assert.ok(Buffer.byteLength(JSON.stringify(config)) <= 15000);
  assert.match(config.secretHex, /^[a-f0-9]{64}$/);
  assert.ok(Number.isInteger(config.port) && config.port >= 1024 && config.port <= 65535);
  assert.ok(Number.isInteger(config.exitPort) && config.exitPort >= 1 && config.exitPort <= 65535);
  assert.ok(typeof config.exitAddress === 'string' && isPublicRelayAddress(config.exitAddress));
  assert.ok(typeof config.publicName === 'string' && !isIP(config.publicName) && config.publicName.length <= 253 && config.publicName.includes('.'));
  assert.ok(config.publicName.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)));
  return compileDnsUpstream(config.profile);
}

export async function createNamespaceDnsAdapter(config) {
  await assertDnsMountNamespace();
  validateAdapterProcessConfig(config);
  const saved = structuredClone(config);
  let current, cached, starts = 0, sequence = 0, closed = false, busy = false;
  const exclusive = (fn) => async (...args) => {
    assert.equal(busy, false, 'adapter operation already running'); busy = true;
    try { return await fn(...args); } finally { busy = false; }
  };
  const running = () => current && current.proc.exitCode === null && current.proc.signalCode === null;
  const call = (child, operation, extra = {}) => new Promise((resolve, reject) => {
    assert.equal(child.pending, undefined); assert.ok(sequence < 256, 'adapter RPC budget');
    const id = ++sequence;
    const timer = setTimeout(() => { child.pending = undefined; child.proc.kill('SIGKILL'); reject(new Error('adapter RPC deadline')); }, 5000);
    child.pending = { id, resolve: (value) => { clearTimeout(timer); resolve(value); }, reject: (error) => { clearTimeout(timer); reject(error); } };
    child.proc.send({ id, operation, ...extra }, (error) => {
      if (error && child.pending?.id === id) { const pending = child.pending; child.pending = undefined; pending.reject(new Error('adapter IPC unavailable')); }
    });
  });
  async function reap(child, signal) {
    if (signal && child.proc.exitCode === null && child.proc.signalCode === null) child.proc.kill(signal);
    const timer = setTimeout(() => child.proc.kill('SIGKILL'), 5000);
    try { return await child.done; } finally { clearTimeout(timer); }
  }
  return {
    port: saved.port, running: () => Boolean(running()), stats: () => structuredClone(cached),
    start: exclusive(async () => {
      assert.equal(closed, false); assert.ok(!running(), 'adapter already running'); assert.ok(starts < 12, 'adapter restart budget');
      starts++; cached = undefined;
      const proc = fork(fileURLToPath(new URL('./dns-adapter-process-worker.mjs', import.meta.url)), [], {
        execArgv: ['--max-old-space-size=96'], env: cleanEnvironment(process.env), stdio: ['ignore', 'pipe', 'pipe', 'ipc'], serialization: 'json' });
      const child = { proc, pending: undefined }; current = child;
      let bytes = 0;
      for (const stream of [proc.stdout, proc.stderr]) stream.on('data', (chunk) => { bytes += chunk.length; if (bytes > 4096) proc.kill('SIGKILL'); });
      proc.on('message', (reply) => {
        try {
          assert.ok(Buffer.byteLength(JSON.stringify(reply)) <= 16384);
          assert.equal(reply.id, child.pending?.id); assert.equal(reply.port, saved.port);
          const pending = child.pending; child.pending = undefined; pending.resolve(reply.snapshot);
        } catch { proc.kill('SIGKILL'); }
      });
      proc.on('error', () => { if (child.pending) { child.pending.reject(new Error('adapter spawn/IPC failed')); child.pending = undefined; } });
      child.done = new Promise((resolve) => proc.once('close', (code, signal) => {
        if (current === child && !child.graceful) cached = undefined;
        if (child.pending) { child.pending.reject(new Error('adapter exited before reply')); child.pending = undefined; }
        resolve({ code, signal });
      }));
      try { cached = await call(child, 'init', { config: saved }); return structuredClone(cached); }
      catch (error) { await reap(child, 'SIGKILL'); throw error; }
    }),
    refresh: exclusive(async () => { assert.ok(running(), 'adapter is not running'); cached = await call(current, 'stats'); return structuredClone(cached); }),
    stop: exclusive(async (signal) => {
      assert.ok(signal === undefined || signal === 'SIGKILL'); assert.ok(running(), 'adapter is not running');
      if (signal) { cached = undefined; return reap(current, signal); }
      try { cached = await call(current, 'close'); current.graceful = true; return await reap(current); }
      catch (error) { await reap(current, 'SIGKILL'); throw error; }
    }),
    async close() {
      closed = true; saved.secretHex = '';
      if (current) await reap(current, 'SIGKILL');
    },
  };
}
