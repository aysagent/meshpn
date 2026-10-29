// Private .mpn authoritative answers. Deliberately has no upstream resolver.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import dgram from 'node:dgram';
import net from 'node:net';
import { parseDnsQuery, dnsFailure } from './lab-dns-wire.mjs';

const requireValue = (value, code) => assert.ok(value, code);
const MAX_REGISTRY = 128 * 1024, MAX_QUERY = 4096;
const asciiKey = name => name.split('.').map(l => Buffer.from(l).toString('hex')).join('.');
const zoneKey = asciiKey('mpn'), reverseKey = asciiKey('0.99.10.in-addr.arpa');
const inZone = (name, zone) => name === zone || name.endsWith('.' + zone);
export const PEER_DNS_LIMITS = Object.freeze({ registryBytes: MAX_REGISTRY, queryBytes: MAX_QUERY,
  tcpConnections: 16, tcpQueries: 32, tcpBufferedBytes: 8196, idleMs: 5000, ttl: 5,
  queriesPerSecond: 256, queryBurst: 512, udpPending: 32 });

export function peerDnsSnapshot(registry) {
  requireValue(registry?.version === 1 && Number.isSafeInteger(registry.revision) && registry.revision >= 0, 'peer_dns_registry_version');
  requireValue(Array.isArray(registry.clients) && registry.clients.length <= 254, 'peer_dns_registry_clients');
  const names = new Set(), ips = new Set(), forward = new Map(), reverse = new Map();
  for (const client of registry.clients) {
    requireValue(client && typeof client.name === 'string' && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(client.name), 'peer_dns_client_name');
    requireValue(typeof client.ipv4 === 'string' && /^10\.99\.0\.(?:[2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$/.test(client.ipv4), 'peer_dns_client_ipv4');
    requireValue(typeof client.revoked === 'boolean', 'peer_dns_client_revoked');
    requireValue(!names.has(client.name) && !ips.has(client.ipv4), 'peer_dns_duplicate_client');
    names.add(client.name); ips.add(client.ipv4);
    if (client.revoked) continue;
    const name = client.name + '.mpn';
    forward.set(asciiKey(name), client.ipv4);
    reverse.set(asciiKey(client.ipv4.split('.').reverse().join('.') + '.in-addr.arpa'), name);
  }
  return { revision: registry.revision, forward, reverse };
}

export function readPeerDnsRegistry(filename) {
  requireValue(typeof filename === 'string' && path.isAbsolute(filename) && path.normalize(filename) === filename, 'peer_dns_registry_path');
  // All writers must be trusted. O_NOFOLLOW also checks the final open rather
  // than trusting a prior lstat; bounded reads cannot allocate a growing file.
  for (let dir = path.dirname(filename); ; dir = path.dirname(dir)) {
    const st = fs.lstatSync(dir);
    requireValue(st.isDirectory() && !st.isSymbolicLink() && [0, process.getuid()].includes(st.uid)
      && (!(st.mode & 0o022) || (st.mode & 0o1000)), 'peer_dns_registry_parent');
    if (dir === '/') break;
  }
  const noPending = () => {
    try { fs.lstatSync(path.join(path.dirname(filename), 'transaction.json')); }
    catch (error) { if (error.code === 'ENOENT') return; throw error; }
    throw new Error('peer_dns_transaction_pending');
  };
  noPending();
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const st = fs.fstatSync(fd);
    requireValue(st.isFile() && st.nlink === 1 && [0, process.getuid()].includes(st.uid)
      && !(st.mode & 0o077) && st.size > 0 && st.size <= MAX_REGISTRY, 'peer_dns_registry_file');
    const bytes = Buffer.alloc(MAX_REGISTRY + 1); let used = 0;
    for (;;) {
      const count = fs.readSync(fd, bytes, used, bytes.length - used, null);
      if (!count) break;
      used += count; requireValue(used <= MAX_REGISTRY, 'peer_dns_registry_size');
    }
    const snapshot = peerDnsSnapshot(JSON.parse(bytes.subarray(0, used).toString('utf8')));
    // The second journal check alone has an ABA race: a reader can open the
    // tentative inode while a concurrent writer rolls it back and removes the
    // journal before this check. Only publish the inode still named AFTER the
    // final no-pending observation. A successful commit retains that inode;
    // rollback or another atomic replacement makes this answer SERVFAIL.
    noPending();
    const current = fs.lstatSync(filename);
    requireValue(current.isFile() && !current.isSymbolicLink() && current.nlink === 1
      && current.dev === st.dev && current.ino === st.ino && current.size === st.size
      && current.mtimeMs === st.mtimeMs && current.ctimeMs === st.ctimeMs, 'peer_dns_registry_replaced');
    return snapshot;
  } finally { fs.closeSync(fd); }
}

function nameWire(name) {
  return Buffer.concat([...name.split('.').map(label => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])), Buffer.from([0])]);
}
function record(owner, type, data, ttl = PEER_DNS_LIMITS.ttl) {
  const header = Buffer.alloc(10); header.writeUInt16BE(type); header.writeUInt16BE(1, 2);
  header.writeUInt32BE(ttl, 4); header.writeUInt16BE(data.length, 8);
  return Buffer.concat([nameWire(owner), header, data]);
}
function soa(zone, revision) {
  const numbers = Buffer.alloc(20);
  [revision % 0x100000000, 60, 30, 300, PEER_DNS_LIMITS.ttl].forEach((n, i) => numbers.writeUInt32BE(n, i * 4));
  return record(zone, 6, Buffer.concat([nameWire('mpn'), nameWire('hostmaster.mpn'), numbers]));
}

export function peerDnsAnswer(query, snapshot) {
  if (!Buffer.isBuffer(query) || query.length < 12 || query.length > MAX_QUERY || (query.readUInt16BE(2) & 0x8000)) return null;
  let q;
  try { q = parseDnsQuery(query); }
  catch {
    const reply = Buffer.alloc(12); query.copy(reply, 0, 0, 2);
    reply.writeUInt16BE(0x8001 | (query.readUInt16BE(2) & 0x0100), 2); return reply;
  }
  const failure = (code, authoritative = false) => {
    const r = dnsFailure(query, code); r.writeUInt16BE((r.readUInt16BE(2) & ~0x0080) | (authoritative ? 0x0400 : 0), 2); return r;
  };
  if (q.edns?.version) return failure(16); // BADVERS; preserve OPT envelope.
  const forward = inZone(q.nameKey, zoneKey), reverse = inZone(q.nameKey, reverseKey);
  if (!forward && !reverse) return failure(5); // No recursion or public DNS fallback.
  if (!snapshot) return failure(2); // Never serve stale entries after invalidation.
  const zone = forward ? 'mpn' : '0.99.10.in-addr.arpa', apex = q.nameKey === (forward ? zoneKey : reverseKey);
  const value = (forward ? snapshot.forward : snapshot.reverse).get(q.nameKey);
  const found = apex || value !== undefined, reply = failure(found ? 0 : 3, true);
  // Keep OPT last; answers use fully expanded names, so no pointer relocation.
  const parts = [reply.subarray(0, q.questionEnd)], answer = [];
  if (apex && q.type === 6) answer.push(soa(zone, snapshot.revision));
  else if (value && forward && q.type === 1) answer.push(record(q.name.toLowerCase(), 1, Buffer.from(value.split('.').map(Number))));
  else if (value && reverse && q.type === 12) answer.push(record(q.name.toLowerCase(), 12, nameWire(value)));
  reply.writeUInt16BE(answer.length, 6); parts.push(...answer);
  if (!answer.length) { reply.writeUInt16BE(1, 8); parts.push(soa(zone, snapshot.revision)); }
  parts.push(reply.subarray(q.questionEnd));
  return Buffer.concat(parts);
}

export async function startPeerDns({ registry, address = '127.0.0.1', port = 1055 } = {}) {
  requireValue(address === '127.0.0.1', 'peer_dns_loopback_only');
  requireValue(Number.isInteger(port) && port >= 0 && port <= 65535, 'peer_dns_port');
  readPeerDnsRegistry(registry); // Refuse startup with unreadable/untrusted state.
  let stopping = false, tokens = PEER_DNS_LIMITS.queryBurst, last = performance.now(), pending = 0;
  const clients = new Set(), counters = { answered: 0, refused: 0, failed: 0, dropped: 0 };
  const answer = query => {
    const now = performance.now(); tokens = Math.min(PEER_DNS_LIMITS.queryBurst, tokens + (now - last) * PEER_DNS_LIMITS.queriesPerSecond / 1000); last = now;
    if (stopping || tokens < 1) { counters.dropped++; return null; } tokens--;
    let snapshot;
    try { snapshot = readPeerDnsRegistry(registry); } catch { counters.failed++; }
    const response = peerDnsAnswer(query, snapshot);
    if (response) { counters.answered++; if ((response.readUInt16BE(2) & 15) === 5) counters.refused++; }
    return response;
  };
  const udp = dgram.createSocket('udp4');
  const tcp = net.createServer(socket => {
    if (stopping || clients.size >= PEER_DNS_LIMITS.tcpConnections) { socket.destroy(); return; }
    clients.add(socket); let buffered = Buffer.alloc(0), queries = 0;
    socket.setTimeout(PEER_DNS_LIMITS.idleMs, () => socket.destroy());
    socket.on('error', () => socket.destroy()); socket.on('close', () => clients.delete(socket));
    socket.on('data', chunk => {
      if (buffered.length + chunk.length > PEER_DNS_LIMITS.tcpBufferedBytes) { socket.destroy(); return; }
      buffered = Buffer.concat([buffered, chunk]);
      while (buffered.length >= 2) {
        const size = buffered.readUInt16BE(0);
        if (size < 12 || size > MAX_QUERY) { socket.destroy(); return; }
        if (buffered.length < size + 2) return;
        if (++queries > PEER_DNS_LIMITS.tcpQueries) { socket.destroy(); return; }
        const response = answer(buffered.subarray(2, size + 2)); buffered = buffered.subarray(size + 2);
        if (!response || socket.writableLength > PEER_DNS_LIMITS.tcpBufferedBytes) { socket.destroy(); return; }
        const length = Buffer.alloc(2); length.writeUInt16BE(response.length); socket.write(Buffer.concat([length, response]));
      }
    });
  });
  const close = async () => {
    if (stopping) return; stopping = true; for (const client of clients) client.destroy();
    await Promise.all([new Promise(resolve => { try { udp.close(resolve); } catch { resolve(); } }),
      new Promise(resolve => { try { tcp.close(resolve); } catch { resolve(); } })]);
  };
  udp.on('message', (query, peer) => {
    if (peer.address !== '127.0.0.1' || pending >= PEER_DNS_LIMITS.udpPending) return;
    const response = answer(query); if (!response) return;
    pending++; udp.send(response, peer.port, peer.address, () => { pending--; });
  });
  // Persistent errors are reported by readiness owner, never leave one protocol
  // silently alive. Caller can use failure to terminate its supervised service.
  let failureResolve; const failure = new Promise(resolve => { failureResolve = resolve; });
  const fail = error => { failureResolve(error.code ?? 'peer_dns_socket_error'); void close(); };
  udp.on('error', fail); tcp.on('error', fail);
  try {
    await new Promise((resolve, reject) => { udp.once('error', reject); udp.bind(port, address, () => { udp.removeListener('error', reject); resolve(); }); });
    const actualPort = udp.address().port;
    await new Promise((resolve, reject) => { tcp.once('error', reject); tcp.listen(actualPort, address, () => { tcp.removeListener('error', reject); resolve(); }); });
    return { address, port: actualPort, close, failure, counters };
  } catch (error) { await close(); throw error; }
}

export function peerDnsUnit({ node, script, registry, port = 1055 }) {
  for (const p of [node, script, registry]) requireValue(typeof p === 'string' && /^\/[A-Za-z0-9_./-]+$/.test(p) && path.normalize(p) === p, 'peer_dns_unit_path');
  requireValue(Number.isInteger(port) && port >= 1024 && port <= 65535, 'peer_dns_unit_port');
  return `[Unit]\nDescription=clean-vpn private mpn DNS zone\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=${node} ${script} run --registry=${registry} --port=${port}\nRestart=on-failure\nRestartSec=2\nTimeoutStopSec=10\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nRestrictSUIDSGID=yes\nRestrictRealtime=yes\nLockPersonality=yes\nCapabilityBoundingSet=\nRestrictAddressFamilies=AF_INET AF_UNIX\nTasksMax=32\nMemoryMax=128M\nLimitNOFILE=128\n\n[Install]\nWantedBy=multi-user.target\n`;
}
