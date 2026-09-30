/** Bounded, synthetic HTTPS workload for the isolated host VPN lab. */
import assert from 'node:assert/strict';
import https from 'node:https';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

export async function hostWorkload(directory) {
  const body = Buffer.alloc(32768, 0x61), response = Buffer.alloc(65536, 0x62);
  const hash = b => createHash('sha256').update(b).digest('hex');
  const ca = readFileSync(`${directory}/fullchain.pem`);
  const agent = new https.Agent({ keepAlive: true, maxSockets: 4 });
  const started = Date.now(), deadline = started + 60000;
  let requests = 0, completed = 0, uploadBytes = 0, downloadBytes = 0;
  const failures = [];
  async function request() {
    await new Promise((resolve, reject) => {
      const began = Date.now(), events = [];
      let received = 0, socketInfo;
      const fail = error => {
        if (failures.length < 4) failures.push({ reason: error.code || error.message,
          elapsedMs: Date.now() - began, reusedSocket: q.reusedSocket, received, socketInfo, events: events.slice(-12) });
        reject(error);
      };
      const q = https.request({ host: '1.0.0.1', port: 19443, servername: 'origin.test',
        method: 'POST', ca, agent, headers: { 'content-length': body.length } }, r => {
        events.push('response');
        const chunks = []; let size = 0;
        r.on('data', b => { size += b.length; received = size; if (size > response.length) q.destroy(Error('response overflow')); else chunks.push(b); });
        r.on('aborted', () => events.push('response-aborted'));
        r.on('error', fail);
        r.on('end', () => {
          try {
            assert.equal(r.statusCode, 200); assert.equal(r.headers['x-upload-sha256'], hash(body));
            assert.equal(r.headers['x-peer'], '198.51.100.2');
            assert.equal(size, response.length); assert.equal(hash(Buffer.concat(chunks)), hash(response));
            completed++; uploadBytes += body.length; downloadBytes += size; resolve();
          } catch (e) { fail(e); }
        });
      });
      q.on('socket', socket => {
        events.push('socket');
        const info = () => { socketInfo = { localAddress: socket.localAddress, localPort: socket.localPort,
          remoteAddress: socket.remoteAddress, remotePort: socket.remotePort }; };
        info();
        if (socket.connecting) socket.once('connect', info);
      });
      q.on('finish', () => events.push('request-finished'));
      const timer = setTimeout(() => q.destroy(Error('request deadline')), 10000);
      q.on('error', fail); q.on('close', () => clearTimeout(timer)); q.end(body);
    });
  }
  try {
    await Promise.all(Array.from({ length: 4 }, async () => {
      while (Date.now() < deadline && requests < 1024) { requests++; await request(); await delay(250); }
    }));
    assert.ok(completed >= 8); assert.equal(completed, requests);
    assert.ok(Date.now() - started >= 60000, 'request cap reached before soak interval');
    return { seconds: (Date.now() - started) / 1000, concurrency: 4, completed, uploadBytes, downloadBytes,
      integrity: 'sha256-both-directions', tlsVerified: true, source: 'exit' };
  } catch (error) {
    console.error(JSON.stringify({ status: 'failed', seconds: (Date.now() - started) / 1000,
      requests, completed, uploadBytes, downloadBytes, reason: error.code || error.message, failures }));
    throw error;
  } finally { agent.destroy(); }
}
