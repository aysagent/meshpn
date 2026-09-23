/** Opt-in, fixed-size HTTP/1 test streams. No caller-selected size or destination. */
import { createHash } from 'node:crypto';

export const STREAM_BYTES = 32 * 1024 * 1024;
export const STREAM_CHUNK = Buffer.alloc(64 * 1024, 0x5a);
const hash = createHash('sha256');
for (let n = 0; n < STREAM_BYTES; n += STREAM_CHUNK.length) hash.update(STREAM_CHUNK);
export const STREAM_HASH = hash.digest('hex');

export function drain(stream) {
  return new Promise((resolve, reject) => {
    const cleanup = () => { stream.off('drain', done); stream.off('error', fail); stream.off('close', closed); };
    const done = () => { cleanup(); resolve(); };
    const fail = (error) => { cleanup(); reject(error); };
    const closed = () => fail(new Error('stream closed before drain'));
    stream.once('drain', done); stream.once('error', fail); stream.once('close', closed);
    if (stream.destroyed) closed();
  });
}
export async function writeStream(stream) {
  for (let size = 0; size < STREAM_BYTES; size += STREAM_CHUNK.length) {
    if (stream.destroyed) throw new Error('stream closed during write');
    if (!stream.write(STREAM_CHUNK)) await drain(stream);
  }
}

export function slowStreamOrigin() {
  const active = new Map();
  return {
    stats: () => ({ slowStreams: active.size, slowStreamTimers: active.size }),
    resumeUploads() { for (const [req, state] of active) if (state.upload) req.resume(); },
    handle(req, res) {
      if (!['/slow-upload', '/slow-download'].includes(req.url)) return false;
      const upload = req.url === '/slow-upload';
      if (active.size >= 2 || req.httpVersion !== '1.1' || req.method !== (upload ? 'POST' : 'GET') ||
          (upload && req.headers['content-length'] !== String(STREAM_BYTES))) {
        res.writeHead(400, req.httpVersion === '1.1' ? { connection: 'close' } : {}); res.end(); return true;
      }
      const timer = setTimeout(() => req.socket.destroy(), 15_000);
      active.set(req, { upload });
      res.once('close', () => { clearTimeout(timer); active.delete(req); });
      if (upload) {
        let bytes = 0;
        const digest = createHash('sha256');
        req.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > STREAM_BYTES) { req.destroy(); return; }
          digest.update(chunk);
        });
        req.on('end', () => {
          const body = Buffer.from(JSON.stringify({ bytes, sha256: digest.digest('hex') }));
          res.writeHead(200, { 'content-length': body.length, connection: 'close' }); res.end(body);
        });
        req.pause(); // IncomingMessage backpressure eventually pauses its TLS socket.
      } else {
        req.resume();
        res.writeHead(200, { 'content-length': STREAM_BYTES, connection: 'close' });
        void writeStream(res).then(() => res.end()).catch(() => res.destroy());
      }
      return true;
    },
  };
}
