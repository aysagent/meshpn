/** Shared lifecycle for client integration, exercised by the private packet-path lab.
 * Caller opens/parks the same-boot journal before creating a replacement TUN.
 * activate() is delayed until the transport's TUN handlers are installed. */
import assert from 'node:assert/strict';
import { startTunnelDnsStub } from './dns-tunnel-stub.mjs';
import { createTunnelDnsForwarder } from './dns-tunnel-forwarder.mjs';

export async function startTunnelDnsRuntime({ journal, config, timeoutMs = 1200 }, {
  startStub = startTunnelDnsStub, createForwarder = createTunnelDnsForwarder,
} = {}) {
  assert.ok(journal && typeof journal.begin === 'function');
  let stub, forwarder;
  try {
    journal.begin(config); journal.applyStage('guard'); journal.applyStage('route');
    forwarder = createForwarder({ primary: config.primary, timeoutMs });
    stub = await startStub({ forwarder });
  } catch (error) {
    // A failed start does not silently restore direct DNS. Retained journal and
    // rules are recoverable on the next start or an explicit rollback.
    try { await (stub ? stub.close() : forwarder?.close()); } finally { journal.release(); }
    throw error;
  }
  let active = false, closing = false, closePromise;
  return {
    activate() {
      assert.ok(!closing && !active, 'DNS runtime activation state');
      journal.applyStage('activate'); journal.activate(); active = true;
    },
    stats: () => ({ active, closing, stub: stub.stats(), forwarder: forwarder.stats() }),
    close({ restore = true } = {}) {
      assert.equal(typeof restore, 'boolean');
      if (closePromise) return closePromise;
      closing = true;
      closePromise = (async () => {
        try { await stub.close(); if (restore) journal.restore(); }
        finally { journal.release(); active = false; }
      })();
      return closePromise;
    },
  };
}
