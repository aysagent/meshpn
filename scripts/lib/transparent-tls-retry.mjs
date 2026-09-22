/** TLS 1.3 HRR guard. No TLS termination, key derivation, or new route token. */
import { relayError } from './transparent-tls-io.mjs';
import { parseFirstTlsClientHelloFromTcpBuf } from './tls-clienthello-ja3.mjs';
import { replaceFirstSniInTcpBuffer, restoreFirstSniInTcpBuffer } from './transparent-tls-ch-rebuild.mjs';

// RFC 8446 §4.1.3 / §4.1.4; CCS handling follows §5 / Appendix D.4.
export const HELLO_RETRY_RANDOM_HEX = 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c';
const HRR_RANDOM = Buffer.from(HELLO_RETRY_RANDOM_HEX, 'hex');
const EMPTY = Buffer.alloc(0);
const fail = (suffix) => { throw relayError(`TLS_RELAY_${suffix}`); };

/** A bounded handshake collector preserving the original record bytes. */
class HelloRecords {
  constructor(limit, type) {
    this.limit = limit;
    this.type = type;
    this.records = [];
    this.payloads = [];
    this.bytes = 0;
    this.payloadBytes = 0;
    this.header = Buffer.alloc(4);
    this.headerBytes = 0;
  }
  add(record) {
    if (this.bytes + record.length > this.limit) fail('HANDSHAKE_LIMIT');
    this.records.push(record);
    this.bytes += record.length;
    const payload = record.subarray(5);
    this.payloads.push(payload);
    this.payloadBytes += payload.length;
    const take = Math.min(4 - this.headerBytes, payload.length);
    payload.copy(this.header, this.headerBytes, 0, take);
    this.headerBytes += take;
    if (this.headerBytes < 4) return null;
    if (this.header[0] !== this.type) fail('RETRY_SEQUENCE');
    const length = 4 + this.header.readUIntBE(1, 3);
    if (length > this.limit) fail('HANDSHAKE_LIMIT');
    if (this.payloadBytes < length) return null;
    const payloads = Buffer.concat(this.payloads, this.payloadBytes);
    return { wire: Buffer.concat(this.records, this.bytes), body: payloads.subarray(4, length),
      extraBytes: this.payloadBytes - length };
  }
}

function serverHello(body) {
  if (body.length < 38) fail('SERVER_HELLO');
  const sidLength = body[34];
  let offset = 35 + sidLength + 3; // session id, cipher suite, compression
  if (sidLength > 32 || offset > body.length || body[offset - 1] !== 0) fail('SERVER_HELLO');
  let version = body.readUInt16BE(0);
  if (offset < body.length) {
    if (offset + 2 > body.length) fail('SERVER_HELLO');
    const length = body.readUInt16BE(offset);
    offset += 2;
    if (offset + length !== body.length) fail('SERVER_HELLO');
    const seen = new Set();
    while (offset < body.length) {
      if (offset + 4 > body.length) fail('SERVER_HELLO');
      const type = body.readUInt16BE(offset);
      const size = body.readUInt16BE(offset + 2);
      offset += 4;
      if (offset + size > body.length || seen.has(type)) fail('SERVER_HELLO');
      seen.add(type);
      if (type === 43) {
        if (size !== 2) fail('SERVER_HELLO');
        version = body.readUInt16BE(offset);
      }
      offset += size;
    }
  }
  const retry = body.subarray(2, 34).equals(HRR_RANDOM);
  if (retry && (version !== 0x0304 || body.readUInt16BE(0) !== 0x0303)) fail('SERVER_HELLO');
  return { retry, version };
}

/** Only TLS 1.3 offers need the HRR gate. TLS 1.2 keeps the existing raw bridge. */
export function createHelloRetryGuard(session, { parsed, prefix, role, relayHost, originHost }) {
  if (!parsed.supportedVersions.includes(0x0304)) return undefined;
  if (parsed.sni.length !== 1) fail('RETRY_IDENTITY');
  let payloadBytes = 0;
  for (let at = 0; at < prefix.length;) {
    const size = prefix.readUInt16BE(at + 3);
    payloadBytes += size;
    at += 5 + size;
  }
  // TLS 1.3 ClientHello must end at a record boundary (RFC 8446 §5.1).
  // Otherwise a coalesced plaintext CH2 could bypass the post-CH1 gate.
  if (payloadBytes !== 4 + parsed.clientHelloBody.length) fail('RETRY_SEQUENCE');
  const identity = Buffer.from(parsed.clientHelloBody.subarray(0, 35 + parsed.clientHelloBody[34]));
  const inputSni = parsed.sni[0];
  const streams = {
    client: { pending: EMPTY, hello: null },
    server: { pending: EMPTY, hello: null },
  };
  let phase = 'server-first';
  let started = false;
  let cancelDeadline;
  const deadline = () => {
    cancelDeadline?.();
    if (started && phase !== 'done') cancelDeadline = session.timer(session.limits.helloTimeoutMs,
      () => session.fail(relayError('TLS_RELAY_HANDSHAKE_TIMEOUT')));
  };
  session.signal.addEventListener('abort', () => {
    cancelDeadline?.();
    for (const stream of Object.values(streams)) { stream.pending = EMPTY; stream.hello = null; }
  }, { once: true });

  function record(direction, bytes) {
    const stream = streams[direction];
    const type = bytes[0];
    if (type !== 0x16) {
      if (stream.hello) fail('RETRY_SEQUENCE'); // no records interleaved in a fragmented hello
      if (type === 0x14) {
        if (bytes.length !== 6 || bytes[5] !== 1) fail('RETRY_CCS');
        return bytes; // dummy CCS never disables the gate
      }
      if (type === 0x15) return bytes; // alerts remain end-to-end
      // Early records can still be in flight when HRR crosses the other direction
      // (RFC 8446 §4.2.10). Forward until CH2 starts; never disable its inspection
      // or refresh the deadline. Only the TLS origin accepts/discards early data.
      if (type === 0x17 && direction === 'client' &&
          (phase === 'server-first' || phase === 'client-retry')) return bytes;
      fail('RETRY_SEQUENCE');
    }
    if (direction === 'client' && phase !== 'client-retry') fail('RETRY_SEQUENCE');
    if (direction === 'server' && phase !== 'server-first' && phase !== 'server-final') fail('RETRY_SEQUENCE');
    stream.hello ??= new HelloRecords(session.limits.maxHelloBytes, direction === 'client' ? 1 : 2);
    const hello = stream.hello.add(bytes);
    if (!hello) return EMPTY;
    stream.hello = null;
    if (direction === 'server') {
      const message = serverHello(hello.body);
      if (message.retry) {
        if (phase !== 'server-first' || hello.extraBytes) fail('RETRY_SEQUENCE');
        phase = 'client-retry';
      } else {
        if (phase === 'server-final' && message.version !== 0x0304) fail('RETRY_SEQUENCE');
        phase = 'done';
      }
      deadline();
      return hello.wire;
    }
    const next = parseFirstTlsClientHelloFromTcpBuf(hello.wire);
    if (!next.ok || hello.extraBytes) fail('RETRY_SEQUENCE');
    if (next.sni.length !== 1 || next.sni[0] !== inputSni || !next.supportedVersions.includes(0x0304) ||
        !next.clientHelloBody.subarray(0, 35 + next.clientHelloBody[34]).equals(identity)) fail('RETRY_IDENTITY');
    const rebuilt = role === 'client' ? replaceFirstSniInTcpBuffer(hello.wire, relayHost)
      : restoreFirstSniInTcpBuffer(hello.wire, relayHost, originHost);
    if (!rebuilt.ok) fail('REBUILD');
    if (rebuilt.prefixBuf.length > session.limits.maxPendingBytes) fail('PENDING_LIMIT');
    phase = 'server-final';
    deadline();
    return rebuilt.prefixBuf;
  }

  function feed(direction, chunk) {
    session.check();
    const stream = streams[direction];
    if (phase === 'done' && !stream.pending.length) return chunk;
    if (stream.pending.length + chunk.length > session.limits.maxHelloBytes + session.limits.maxPendingBytes) {
      fail('PENDING_LIMIT');
    }
    stream.pending = Buffer.concat([stream.pending, chunk]);
    const output = [];
    while (stream.pending.length) {
      if (phase === 'done') {
        output.push(stream.pending);
        stream.pending = EMPTY;
        break;
      }
      if (stream.pending.length < 5) break;
      const type = stream.pending[0];
      const size = stream.pending.readUInt16BE(3);
      if (!size || size > (type === 0x17 ? 16640 : 16384) ||
          (type === 0x16 && size + 5 > session.limits.maxHelloBytes)) fail('HANDSHAKE_LIMIT');
      if (stream.pending.length < size + 5) break;
      const bytes = stream.pending.subarray(0, size + 5);
      stream.pending = stream.pending.subarray(size + 5);
      const transformed = record(direction, bytes);
      if (transformed.length) output.push(transformed);
    }
    return output.length === 1 ? output[0] : Buffer.concat(output);
  }

  return {
    start() { started = true; deadline(); },
    forward: (chunk) => feed('client', chunk),
    reverse: (chunk) => feed('server', chunk),
    end(direction) {
      if (streams[direction].pending.length || streams[direction].hello) fail('HANDSHAKE_EOF');
    },
  };
}
