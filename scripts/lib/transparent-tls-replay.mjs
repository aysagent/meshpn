/** Process-local, bounded enc-SNI admission memory. No timers, raw tokens or PSKs. */
import { ENC_SNI_TS_WINDOW_MS } from './transparent-tls-enc-sni.mjs';
import { relayError } from './transparent-tls-io.mjs';

export const ENC_SNI_REPLAY_MAX_ENTRIES = 65536;
// A token first admitted 5 minutes ahead remains valid for up to another 5
// minutes. Include the decoder's inclusive whole-second timestamp boundary.
export const ENC_SNI_REPLAY_RETENTION_MS = 2 * ENC_SNI_TS_WINDOW_MS + 1000;

export class EncSniReplayGuard {
  #entries = new Map();
  #lastNow = 0;
  #now;
  #maxEntries;
  constructor({ maxEntries = ENC_SNI_REPLAY_MAX_ENTRIES, now = () => Date.now() } = {}) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > ENC_SNI_REPLAY_MAX_ENTRIES || typeof now !== 'function') {
      throw relayError('TLS_RELAY_CONFIG', 'invalid replay guard bounds');
    }
    this.#now = now; this.#maxEntries = maxEntries;
  }
  consume({ replayId, issuedAtSeconds }) {
    if (typeof replayId !== 'string' || !/^[0-9a-f]{64}$/.test(replayId) ||
        !Number.isInteger(issuedAtSeconds) || issuedAtSeconds < 0 || issuedAtSeconds > 0xffffffff) {
      throw relayError('TLS_RELAY_CONFIG', 'authenticated replay metadata required');
    }
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < this.#lastNow || !Number.isSafeInteger(now + ENC_SNI_REPLAY_RETENTION_MS)) {
      throw relayError('TLS_RELAY_REPLAY_CLOCK');
    }
    // Never reopen an expired admission window after a backward wall-clock step.
    this.#lastNow = now;
    if (Math.abs(Math.floor(now / 1000) - issuedAtSeconds) > ENC_SNI_TS_WINDOW_MS / 1000) {
      throw relayError('TLS_RELAY_REPLAY_STALE');
    }
    // Equal fixed retention + nondecreasing clock => insertion order is expiry
    // order. Amortized O(1) pruning, no sweep/timer per connection or LRU eviction.
    for (const [id, expiry] of this.#entries) {
      if (expiry > now) break;
      this.#entries.delete(id);
    }
    if (this.#entries.has(replayId)) throw relayError('TLS_RELAY_REPLAY');
    if (this.#entries.size >= this.#maxEntries) throw relayError('TLS_RELAY_REPLAY_FULL');
    // Synchronous reservation BEFORE connectOrigin, never released on failure.
    this.#entries.set(replayId, now + ENC_SNI_REPLAY_RETENTION_MS);
  }
  stats() { return { entries: this.#entries.size, maxEntries: this.#maxEntries, retentionMs: ENC_SNI_REPLAY_RETENTION_MS }; }
}

// Shared by all transparent/combo listeners using this runtime in one process.
// Worker processes/hosts and process restarts have independent admission memory.
export const defaultEncSniReplayGuard = new EncSniReplayGuard();
