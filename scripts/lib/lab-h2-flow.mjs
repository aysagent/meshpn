/** Opt-in HTTP/2 stream flow-control fixture. Never closes a session to cancel a stream. */
import { createHash } from 'node:crypto';
import { constants } from 'node:http2';
import { drain } from './lab-slow-streams.mjs';

export const H2_BYTES = 4 * 1024 * 1024;
const CHUNK = Buffer.alloc(16 * 1024, 0x6b);
const expected = createHash('sha256');
for (let n = 0; n < H2_BYTES; n += CHUNK.length) expected.update(CHUNK);
export const H2_HASH = expected.digest('hex');
export async function writeH2Body(stream) {
  for (let n = 0; n < H2_BYTES; n += CHUNK.length) {
    if (stream.destroyed) throw new Error('H2 stream closed');
    if (!stream.write(CHUNK)) await drain(stream);
  }
  stream.end();
}

export function h2FlowOrigin() {
  const active = new Map();
  let cancels = 0, deadlines = 0;
  return {
    stats: () => ({ h2FlowStreams: active.size, h2FlowTimers: active.size, h2FlowCancels: cancels, h2FlowDeadlines: deadlines }),
    snapshots: () => [...active].map(([req, { upload }]) => ({ id: req.stream.id, upload,
      localWindow: req.stream.state.localWindowSize, readable: req.readableLength,
      writable: req.stream.writableLength, needDrain: req.stream.writableNeedDrain,
      connectionWindow: req.stream.session?.state.remoteWindowSize })),
    resumeUploads() { for (const [req, { upload }] of active) if (upload) req.resume(); },
    handle(req, res) {
      if (!['/h2-flow-upload', '/h2-flow-download'].includes(req.url)) return false;
      const upload = req.url === '/h2-flow-upload';
      if (active.size >= 2 || req.httpVersionMajor !== 2 || req.method !== (upload ? 'POST' : 'GET') ||
          (upload && req.headers['content-length'] !== String(H2_BYTES))) {
        res.writeHead(400, req.httpVersionMajor === 2 ? {} : { connection: 'close' }); res.end(); return true;
      }
      const timer = setTimeout(() => { deadlines++; req.stream.close(constants.NGHTTP2_CANCEL); }, 15_000);
      active.set(req, { upload });
      req.stream.once('close', () => {
        clearTimeout(timer); active.delete(req);
        if (req.stream.rstCode === constants.NGHTTP2_CANCEL) cancels++;
      });
      if (upload) {
        let bytes = 0;
        const digest = createHash('sha256');
        req.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > H2_BYTES) { req.stream.close(constants.NGHTTP2_PROTOCOL_ERROR); return; }
          digest.update(chunk);
        });
        req.on('end', () => {
          if (req.stream.destroyed) return;
          const body = Buffer.from(JSON.stringify({ bytes, sha256: digest.digest('hex') }));
          res.writeHead(200, { 'content-length': body.length }); res.end(body);
        });
        req.pause();
      } else {
        req.resume(); res.writeHead(200, { 'content-length': H2_BYTES });
        void writeH2Body(res).catch(() => res.destroy());
      }
      return true;
    },
  };
}
