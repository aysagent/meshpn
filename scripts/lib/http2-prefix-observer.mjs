/** Read-only first-request H2 evidence; never retains HPACK blocks or DATA. */
import assert from 'node:assert/strict';
const magic = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
export const publicHeaderValues = new Set([':method', ':scheme', 'user-agent', 'accept', 'accept-encoding',
  'accept-language', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-fetch-dest',
  'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user', 'upgrade-insecure-requests', 'priority', 'content-type']);
const knownNames = new Set([...publicHeaderValues, ':path', ':authority', 'authorization', 'cookie',
  'referer', 'origin', 'content-length', 'cache-control', 'pragma']);
export function headerEvidence(raw) {
  assert.ok(Array.isArray(raw) && raw.length <= 64 && raw.length % 2 === 0, 'h2_header_count');
  const names = [], values = []; let bytes = 0;
  for (let i = 0; i < raw.length; i += 2) {
    const name = raw[i], value = raw[i + 1];
    assert.ok(typeof name === 'string' && typeof value === 'string', 'h2_header_type');
    bytes += Buffer.byteLength(name) + Buffer.byteLength(value); assert.ok(bytes <= 8192, 'h2_headers_limit');
    names.push(knownNames.has(name) ? name : '<other>');
    // Public fingerprint values only. No URL, authority, cookies or bearer token.
    if (publicHeaderValues.has(name)) {
      assert.ok(/^[\x20-\x7e]{0,512}$/.test(value), 'h2_header_value'); values.push([name, value]);
    }
  }
  return { names, publicValues: values, redactedValues: names.length - values.length };
}
export class Http2PrefixObserver {
  #pending = Buffer.alloc(0); #preface = 0; #bytes = 0; #done = false; #error = null;
  #frames = []; #settings = []; #windows = []; #first = null; #continuation = false;
  feed(chunk) {
    if (this.#done) return;
    try {
      // Consume incrementally: a TLS read may also contain arbitrary DATA after
      // the first HEADERS. Never concatenate or retain that suffix.
      for (let offset = 0; offset < chunk.length && !this.#done;) {
        if (this.#preface < magic.length) {
          assert.equal(chunk[offset++], magic[this.#preface++], 'h2_preface'); continue;
        }
        const wanted = this.#pending.length < 9 ? 9 : 9 + this.#pending.readUIntBE(0, 3);
        const n = Math.min(wanted - this.#pending.length, chunk.length - offset);
        this.#bytes += n; assert.ok(this.#bytes <= 65536, 'h2_prefix_limit');
        this.#pending = Buffer.concat([this.#pending, chunk.subarray(offset, offset + n)]); offset += n;
        if (this.#pending.length < 9) continue;
        const size = this.#pending.readUIntBE(0, 3); assert.ok(size <= 16384, 'h2_frame_limit');
        if (this.#pending.length !== 9 + size) continue;
        this.#frame(this.#pending); this.#pending = Buffer.alloc(0);
      }
    } catch (error) {
      this.#error = error.code === 'ERR_ASSERTION' ? 'invalid-or-over-limit-prefix' : 'observer-error';
      this.#done = true; this.#pending = Buffer.alloc(0);
    }
  }
  #frame(bytes) {
    const type = bytes[3], flags = bytes[4], stream = bytes.readUInt32BE(5) & 0x7fffffff, body = bytes.subarray(9);
    assert.ok(this.#frames.length < 32, 'h2_frame_count');
    if (!this.#frames.length) assert.ok(type === 4 && flags === 0 && stream === 0, 'h2_initial_settings');
    if (this.#continuation) assert.ok(type === 9 && stream === this.#first.streamId, 'h2_continuation');
    this.#frames.push({ type, flags, streamId: stream, payloadBytes: body.length });
    if (type === 4) {
      assert.ok(stream === 0 && (flags === 0 || flags === 1) && body.length % 6 === 0 && body.length <= 192, 'h2_settings');
      assert.ok(flags !== 1 || body.length === 0, 'h2_settings_ack');
      if (flags === 0) {
        const entries = []; for (let i = 0; i < body.length; i += 6) entries.push([body.readUInt16BE(i), body.readUInt32BE(i + 2)]);
        this.#settings.push(entries); // Includes order, duplicates and unknown IDs as observed.
      }
    } else if (type === 8) {
      assert.equal(body.length, 4); const increment = body.readUInt32BE(0) & 0x7fffffff;
      assert.ok(increment > 0); this.#windows.push({ streamId: stream, increment });
    } else if (type === 1 || type === 9) {
      assert.ok(stream > 0 && (type !== 9 || this.#continuation));
      let start = 0, end = body.length;
      if (type === 1) {
        assert.ok(!this.#first); this.#first = { streamId: stream, blockBytes: 0, paddingBytes: 0, priority: null };
        if (flags & 8) { assert.ok(body.length > 0); this.#first.paddingBytes = body[0]; start++; end -= body[0]; }
        if (flags & 32) {
          assert.ok(end - start >= 5); const dependency = body.readUInt32BE(start);
          this.#first.priority = { dependency: dependency & 0x7fffffff, exclusive: !!(dependency & 0x80000000), weight: body[start + 4] + 1 }; start += 5;
        }
      }
      assert.ok(end >= start); this.#first.blockBytes += end - start;
      this.#continuation = !(flags & 4); if (!this.#continuation) this.#done = true;
    }
  }
  snapshot(rawHeaders, streamId) {
    if (this.#error || !this.#done || !this.#first || this.#first.streamId !== streamId)
      return { schema: 1, kind: 'clean-vpn-http2-prefix', status: 'unavailable',
        reason: this.#error ?? (!this.#done || !this.#first ? 'incomplete-prefix' : 'accepted-request-is-not-first') };
    return structuredClone({ schema: 1, kind: 'clean-vpn-http2-prefix', status: 'complete',
      scope: 'client-preface-through-first-END_HEADERS', settingsFrames: this.#settings,
      windowUpdates: this.#windows, frames: this.#frames, firstHeaders: this.#first,
      headers: headerEvidence(rawHeaders), alps: 'not-negotiated-by-capture-endpoint',
      limitations: ['HPACK-block-size-not-encoder-strategy', 'not-later-stream-or-timing-evidence'] });
  }
}
