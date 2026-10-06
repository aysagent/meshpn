// Authenticated legacy reference endpoint, local-only fault injection. This is
// test-only legacy stream I/O, not a Node bridge in the native data plane.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import tls from 'node:tls';
import { startDateExit } from './lib/vpn-http-date-fixture.mjs';

const build = path.resolve(process.env.CVPN_BUILD ?? 'native/clean_vpn/build');
function h2frame(type, flags, stream, data = Buffer.alloc(0)) {
  const h = Buffer.alloc(9); h.writeUIntBE(data.length, 0, 3); h[3] = type; h[4] = flags; h.writeUInt32BE(stream, 5);
  return Buffer.concat([h, data]);
}
// Node's stream.close() sends END_STREAM before RST_STREAM. To test an isolated
// reset/invalid frame/TLS close, use this deliberately scripted trusted peer.
// It is not a VPN exit and does not test bearer authentication (covered above).
async function scriptedPeer(code) {
  const sockets = new Set(), timers = new Set(); let connections = 0;
  const server = tls.createServer({ cert: fs.readFileSync('scripts/fixtures/boring-tls-local.cert.pem'),
    key: fs.readFileSync('scripts/fixtures/boring-tls-local.key.pem'), ALPNProtocols: ['h2'], minVersion: 'TLSv1.3' }, socket => {
    sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket));
    const fault = ++connections === 1;
    let pending = Buffer.alloc(0), preface = false, answered = false;
    socket.write(h2frame(4, 0, 0));
    socket.on('data', data => {
      pending = Buffer.concat([pending, data]);
      if (!preface) { if (pending.length < 24) return; pending = pending.subarray(24); preface = true; }
      while (pending.length >= 9) {
        const n = pending.readUIntBE(0, 3); if (pending.length < n + 9) return;
        const type = pending[3], flags = pending[4], payload = pending.subarray(9, 9 + n);
        pending = pending.subarray(9 + n);
        if (type === 4 && !(flags & 1)) socket.write(h2frame(4, 1, 0));
        if (type === 1 && !answered) {
          answered = true;
          socket.write(h2frame(1, 4, 1, Buffer.concat([Buffer.from([0x88, 0x0f, 0x10, 24]), Buffer.from('application/octet-stream')])));
          if (fault) {
            const timer = setTimeout(() => {
              timers.delete(timer); if (socket.destroyed) return;
              if (code === 'tls_peer_closed') socket.end();
              else if (code === 'h2_invalid_frame') socket.write(h2frame(8, 0, 0, Buffer.alloc(4))); // WINDOW_UPDATE cannot be zero.
              else if (code === 'h2_local_goaway_error') socket.write(h2frame(6, 0, 0)); // PING must be 8 bytes.
              else { const error = Buffer.alloc(4); error.writeUInt32BE(code === 'h2_reset_error' ? 8 : 0); socket.write(h2frame(3, 0, 1, error)); }
            }, 100);
            timers.add(timer);
          }
        }
        if (type === 0 && !fault) socket.write(h2frame(0, 0, 1, payload));
        if (type === 6 && !(flags & 1)) socket.write(h2frame(6, 1, 0, payload));
      }
    });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return { port: server.address().port, connections: () => connections,
    async close() { for (const timer of timers) clearTimeout(timer); for (const s of sockets) s.destroy(); await new Promise(r => server.close(r)); } };
}
function badAddressPacket() {
  const packet = Buffer.from('450000140000000040110000010101010a630003', 'hex');
  let sum = 0; for (let i = 0; i < packet.length; i += 2) sum += packet.readUInt16BE(i);
  while (sum >>> 16) sum = (sum & 65535) + (sum >>> 16);
  packet.writeUInt16BE((~sum) & 65535, 10);
  return Buffer.concat([Buffer.from([0, 0, 0, 20]), packet]);
}
for (const [code, inject] of [
  ['invalid_frame_length', sock => sock.write(Buffer.from([255, 255, 255, 255]))],
  ['invalid_ipv4', sock => sock.write(Buffer.concat([Buffer.from([0, 0, 0, 20]), Buffer.alloc(20)]))],
  ['peer_address', sock => sock.write(badAddressPacket())],
  ['h2_peer_end_stream', sock => sock.end()],
  ['h2_goaway_no_error', sock => sock.session.goaway(0, 1, Buffer.from('PRIVATE DEBUG'))],
  ['h2_goaway_error', sock => sock.session.goaway(11, 1, Buffer.from('PRIVATE DEBUG'))],
  ['h2_reset_no_error', null], ['h2_reset_error', null], ['h2_invalid_frame', null], ['tls_peer_closed', null],
  ['h2_local_goaway_error', null],
  ['idle_cycles', sock => sock.end()],
]) test(`native reports ${code}, blocks bad injection and reconnects`, { timeout: 15000 }, async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cvpn-session-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const secret = randomBytes(32), secretPath = path.join(dir, 'psk');
  fs.writeFileSync(secretPath, secret, { mode: 0o600 });
  let connections = 0;
  const timers = new Set();
  const server = inject ? await startDateExit({ protocol: 'h2', secret, onBridge: sock => {
    sock.on('error', () => {});
    ++connections;
    if (code === 'idle_cycles') sock.pipe(sock);
    if (connections === 1 || code === 'idle_cycles') {
      const timer = setTimeout(() => { timers.delete(timer); if (!sock.destroyed) inject(sock); }, 100);
      timers.add(timer);
    } else sock.pipe(sock); // Opaque reference echo; C++ generates/checks bytes.
  } }) : await scriptedPeer(code);
  t.after(async () => { for (const timer of timers) clearTimeout(timer); await server.close(); });
  const config = path.join(dir, 'client.json');
  fs.writeFileSync(config, JSON.stringify({ version: 1, role: 'client', address: '127.0.0.1', port: server.port,
    tun: 'cvtest0', secret_path: secretPath, server_name: 'localhost', ca: path.resolve('scripts/fixtures/boring-tls-local.cert.pem') }));
  const child = spawn(path.join(build, 'integration-test'), [path.join(build, 'clean-vpn-engine-fixture'), config,
    code === 'idle_cycles' ? 'client-idle' : `client-event:${code}`]);
  let output = ''; for (const stream of [child.stdout, child.stderr]) stream.on('data', b => { output += b; });
  const timer = setTimeout(() => child.kill('SIGKILL'), 13000);
  t.after(() => { clearTimeout(timer); child.kill('SIGKILL'); });
  const [status] = await once(child, 'close'); clearTimeout(timer);
  assert.equal(status, 0, output);
  assert.match(output, code === 'idle_cycles' ? /idle cycles wake packet, uplink, invalid traffic and stop PASS/ : /classified session failure and reconnect PASS/);
  assert.equal(inject ? connections : server.connections(), code === 'idle_cycles' ? 4 : 2);
  assert.doesNotMatch(output, /PRIVATE|http2_receive|session_rejected_or_closed/);
  if (code === 'peer_address') assert.match(output, /"event":"peer_address_rejected"/);
});
