// Bounded synthetic IPv4 peer for device acceptance tests. No TUN, NAT, host
// routes, DNS changes or internet forwarding. Only 198.18.0.1 and the board's
// fixed probe/DNS address 1.1.1.1 are answered. Never use as a production exit.
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';

export const testAddress = '198.18.0.1';
export const testBody = 'MeshPN synthetic local VPN peer\n';
const ip = s => Buffer.from(s.split('.').map(Number));
const address = b => [...b].join('.');
export function checksum(b) {
  let sum = 0;
  for (let i = 0; i < b.length; i += 2) sum += (b[i] << 8) | (b[i + 1] ?? 0);
  while (sum >>> 16) sum = (sum & 65535) + (sum >>> 16);
  return (~sum) & 65535;
}
export function packet(src, dst, protocol, body, fragment = 0) {
  const p = Buffer.alloc(20 + body.length);
  p[0] = 0x45; p.writeUInt16BE(p.length, 2); p.writeUInt16BE(fragment, 6);
  p[8] = 64; p[9] = protocol; ip(src).copy(p, 12); ip(dst).copy(p, 16); body.copy(p, 20);
  if (!(fragment & 0x3fff)) {
    const offset = protocol === 6 ? 16 : protocol === 17 ? 6 : 2;
    if (body.length >= offset + 2) {
      p.writeUInt16BE(0, 20 + offset);
      let bytes = p.subarray(20);
      if (protocol !== 1) {
        const pseudo = Buffer.alloc(12);
        p.copy(pseudo, 0, 12, 20); pseudo[9] = protocol; pseudo.writeUInt16BE(body.length, 10);
        bytes = Buffer.concat([pseudo, bytes]);
      }
      p.writeUInt16BE(checksum(bytes) || (protocol === 17 ? 65535 : 0), 20 + offset);
    }
  }
  p.writeUInt16BE(checksum(p.subarray(0, 20)), 10);
  return p;
}
function tcp(src, dst, sport, dport, seq, ack, flags, data = Buffer.alloc(0), syn = false) {
  const b = Buffer.alloc((syn ? 24 : 20) + data.length);
  b.writeUInt16BE(sport, 0); b.writeUInt16BE(dport, 2);
  b.writeUInt32BE(seq >>> 0, 4); b.writeUInt32BE(ack >>> 0, 8);
  b[12] = syn ? 0x60 : 0x50; b[13] = flags; b.writeUInt16BE(32768, 14);
  if (syn) { b[20] = 2; b[21] = 4; b.writeUInt16BE(1360, 22); }
  data.copy(b, syn ? 24 : 20);
  return packet(src, dst, 6, b);
}
function udp(src, dst, sport, dport, data) {
  const b = Buffer.alloc(8 + data.length);
  b.writeUInt16BE(sport); b.writeUInt16BE(dport, 2); b.writeUInt16BE(b.length, 4); data.copy(b, 8);
  return packet(src, dst, 17, b);
}
function dns(query) {
  if (query.length < 17 || query[2] & 0x80) return null;
  let end = 12;
  while (end < query.length && query[end]) {
    const length = query[end]; if (length > 63 || end + 1 + length >= query.length) return null;
    end += length + 1;
  }
  if (end + 5 > query.length) return null;
  end += 5;
  const a = query.readUInt16BE(end - 4) === 1;
  const out = Buffer.alloc(end + (a ? 16 : 0)); query.copy(out, 0, 0, end);
  out[2] = 0x81; out[3] = 0x80; out.writeUInt16BE(a ? 1 : 0, 6);
  out.writeUInt32BE(0, 8);
  if (a) {
    out.writeUInt16BE(0xc00c, end); out.writeUInt16BE(1, end + 2); out.writeUInt16BE(1, end + 4);
    out.writeUInt32BE(2, end + 6); out.writeUInt16BE(4, end + 10); ip(testAddress).copy(out, end + 12);
  }
  return out;
}

export async function startPeer({host = '127.0.0.1', port = 0, type = 'tcp', key, cert, fragmentFrames = false} = {}) {
  if (!['tcp', 'udp', 'tls'].includes(type)) throw Error('Unknown local peer transport');
  const stats = {connections: 0, packets_in: 0, packets_out: 0, invalid: 0, dns: 0, http: 0, mss: [], errors: []};
  const sockets = new Set(), flows = new Map();
  let server, nextSequence = 10000, closing = false;
  function answer(p, emit) {
    if (p.length < 20 || p[0] !== 0x45 || p.readUInt16BE(2) !== p.length || checksum(p.subarray(0, 20))) {
      stats.invalid++; return;
    }
    stats.packets_in++;
    if (p.readUInt16BE(6) & 0x3fff) return; // Fragment handling is tested independently.
    const src = address(p.subarray(12, 16)), dst = address(p.subarray(16, 20));
    if (dst !== testAddress && dst !== '1.1.1.1') return;
    const send = b => { stats.packets_out++; emit(b); };
    if (p[9] === 1 && p.length >= 28 && p[20] === 8) {
      const body = Buffer.from(p.subarray(20)); body[0] = 0; send(packet(dst, src, 1, body)); return;
    }
    if (p[9] === 17 && p.length >= 28) {
      const sport = p.readUInt16BE(20), dport = p.readUInt16BE(22);
      if (dport === 53) {
        const result = dns(p.subarray(28));
        if (result) { stats.dns++; send(udp(dst, src, dport, sport, result)); }
      } else if (dport === 7) send(udp(dst, src, dport, sport, p.subarray(28)));
      else if (dport === 9 || dport === 10) {
        const body = Buffer.alloc(36); body[0] = 3; body[1] = dport === 9 ? 4 : 3;
        body.writeUInt16BE(dport === 9 ? 1280 : 0, 6); p.copy(body, 8, 0, 28);
        send(packet(dst, src, 1, body));
      }
      return;
    }
    if (p[9] !== 6 || p.length < 40) return;
    const sport = p.readUInt16BE(20), dport = p.readUInt16BE(22);
    const seq = p.readUInt32BE(24), ack = p.readUInt32BE(28), flags = p[33], h = (p[32] >>> 4) * 4;
    if (h < 20 || 20 + h > p.length) return;
    const id = `${src}:${sport}/${dst}:${dport}`;
    let f = flows.get(id);
    if (flags & 4) { flows.delete(id); return; }
    if (flags & 2) {
      if (!f) {
        if (flows.size >= 128) flows.delete(flows.keys().next().value);
        f = {initial: nextSequence += 100000, received: (seq + 1) >>> 0, request: Buffer.alloc(0), sent: 0, acked: 0};
        flows.set(id, f);
        for (let i = 40; i < 20 + h;) {
          const kind = p[i]; if (!kind) break; if (kind === 1) { i++; continue; }
          const n = p[i + 1]; if (n < 2 || i + n > 20 + h) break;
          if (kind === 2 && n === 4) { const m = p.readUInt16BE(i + 2); if (stats.mss.length < 64) stats.mss.push(m); }
          i += n;
        }
      }
      send(tcp(dst, src, dport, sport, f.initial, f.received, 0x12, undefined, true)); return;
    }
    if (!f) return;
    if (flags & 16) {
      const count = (ack - f.initial - 1) >>> 0;
      if (count <= f.sent) f.acked = Math.max(f.acked, count);
    }
    const data = p.subarray(20 + h);
    if (data.length && seq === f.received) {
      f.received = (f.received + data.length) >>> 0;
      if (f.request.length + data.length < 8192) f.request = Buffer.concat([f.request, data]);
      if (!f.response && f.request.includes('\r\n\r\n')) {
        const m = /^GET \/bytes\/(\d+) /.exec(f.request.toString());
        const body = m ? Buffer.alloc(Math.min(Number(m[1]), 1024 * 1024), 0x5a) : Buffer.from(testBody);
        f.response = Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`), body]);
        stats.http++;
      }
    }
    if (flags & 1) { f.received = (seq + data.length + 1) >>> 0; }
    if (data.length || flags & 1) send(tcp(dst, src, dport, sport, f.initial + 1 + f.sent, f.received, 0x10));
    if (f.response) {
      let budget = 12;
      while (budget-- && f.sent < f.response.length && f.sent - f.acked < 12000) {
        const b = f.response.subarray(f.sent, f.sent + 1200);
        send(tcp(dst, src, dport, sport, f.initial + 1 + f.sent, f.received, 0x18, b)); f.sent += b.length;
      }
      if (f.acked === f.response.length && !f.fin) {
        f.fin = true; send(tcp(dst, src, dport, sport, f.initial + 1 + f.sent, f.received, 0x11));
      }
    }
  }
  function stream(socket) {
    stats.connections++; sockets.add(socket); socket.setNoDelay(true);
    let input = Buffer.alloc(0), pending = Promise.resolve();
    const emit = p => {
      const header = Buffer.alloc(4); header.writeUInt32BE(p.length);
      const b = Buffer.concat([header, p]);
      if (!fragmentFrames) { socket.write(b); return; }
      pending = pending.then(async () => {
        for (let i = 0; i < b.length && !socket.destroyed; i += 17) {
          socket.write(b.subarray(i, i + 17)); await new Promise(resolve => setTimeout(resolve, 1));
        }
      }).catch(() => {});
    };
    socket.on('data', b => {
      input = Buffer.concat([input, b]);
      while (input.length >= 4) {
        const length = input.readUInt32BE(0);
        if (length < 20 || length > 1400) { stats.invalid++; socket.destroy(); return; }
        if (input.length < length + 4) break;
        const p = input.subarray(4, length + 4); input = input.subarray(length + 4); answer(p, emit);
      }
      if (input.length > 1404) socket.destroy();
    });
    socket.on('error', e => { if (!closing && stats.errors.length < 32) stats.errors.push(e.code ?? e.message); });
    socket.on('close', () => sockets.delete(socket));
  }
  if (type === 'udp') {
    server = dgram.createSocket('udp4');
    server.on('message', (p, r) => answer(p, b => server.send(b, r.port, r.address)));
    await new Promise((resolve, reject) => { server.once('error', reject); server.bind(port, host, resolve); });
  } else {
    server = type === 'tls' ? tls.createServer({key, cert, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2', handshakeTimeout: 5000}, stream) : net.createServer(stream);
    server.on('connection', raw => { sockets.add(raw); raw.once('close', () => sockets.delete(raw)); });
    server.on('tlsClientError', e => { if (!closing && stats.errors.length < 32) stats.errors.push(e.code ?? e.message); });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  }
  return {port: server.address().port, stats, drop() { for (const s of sockets) s.destroy(); flows.clear(); },
    async close() { closing = true; for (const s of sockets) s.destroy(); await new Promise(resolve => server.close(resolve)); }};
}
