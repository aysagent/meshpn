/** Read-only Linux socket evidence. No DNS probes or mutation authority. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { open, opendir, readlink } from 'node:fs/promises';
import { endianness } from 'node:os';

const protocols = ['tcp', 'udp', 'tcp6', 'udp6'];
export function assessDnsAdapterSockets({ port, uid, tables, before, after, endian = endianness() }) {
  assert.ok(Number.isInteger(port) && port >= 1024 && port <= 65535);
  assert.ok(Number.isSafeInteger(uid) && uid >= 0); assert.ok(['LE', 'BE'].includes(endian));
  const held = (values) => {
    assert.ok(Array.isArray(values) && values.length <= 256 && values.every((v) => /^[1-9][0-9]*$/.test(v)));
    return new Set(values);
  };
  const first = held(before), last = held(after), found = {};
  for (const protocol of protocols) {
    const text = tables[protocol]; assert.ok(typeof text === 'string' && Buffer.byteLength(text) <= 524288);
    const lines = text.trim().split('\n'); assert.match(lines.shift(), /local_address\s+rem(?:ote)?_address\s+st/);
    assert.ok(lines.length <= 4096);
    for (const line of lines) {
      const columns = line.trim().split(/\s+/); assert.ok(columns.length >= 10);
      const hex = protocol.endsWith('6') ? 32 : 8;
      const endpoint = new RegExp(`^[A-Fa-f0-9]{${hex}}:[A-Fa-f0-9]{4}$`);
      assert.match(columns[1], endpoint); assert.match(columns[2], endpoint); assert.match(columns[3], /^[A-Fa-f0-9]{2}$/);
      if (Number.parseInt(columns[1].split(':')[1], 16) !== port) continue;
      // Accepted TCP streams have the listener's local port too; only LISTEN
      // sockets participate. Every UDP binding on this port participates.
      if (protocol.startsWith('tcp') && columns[3].toUpperCase() !== '0A') continue;
      assert.ok(protocol === 'tcp' || protocol === 'udp', 'unexpected IPv6 adapter listener');
      assert.equal(found[protocol], undefined, 'multiple listeners on adapter port');
      assert.equal(columns[1].split(':')[0].toUpperCase(), endian === 'LE' ? '0100007F' : '7F000001', 'adapter must bind IPv4 loopback only');
      assert.equal(columns[2].toUpperCase(), '00000000:0000');
      assert.equal(columns[3].toUpperCase(), protocol === 'tcp' ? '0A' : '07');
      assert.match(columns[7], /^\d+$/); assert.equal(Number(columns[7]), uid, 'listener uid mismatch');
      const inode = columns[9]; assert.match(inode, /^[1-9][0-9]*$/);
      assert.ok(first.has(inode) && last.has(inode), 'listener not held by selected process');
      found[protocol] = inode;
    }
  }
  assert.deepEqual(Object.keys(found).sort(), ['tcp', 'udp'], 'both adapter listeners required');
  assert.notEqual(found.tcp, found.udp);
  return { udp: found.udp, tcp: found.tcp };
}

async function procText(path) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    assert.ok((await fd.stat()).isFile());
    const bytes = Buffer.alloc(524289); let used = 0;
    while (used < bytes.length) { const r = await fd.read(bytes, used, bytes.length - used, null); if (!r.bytesRead) break; used += r.bytesRead; }
    assert.ok(used > 0 && used <= 524288, 'socket table bound');
    return new TextDecoder('utf8', { fatal: true }).decode(bytes.subarray(0, used));
  } finally { await fd.close(); }
}
export async function inspectDnsAdapterSockets({ pid, uid, port, netns }) {
  assert.ok(Number.isSafeInteger(pid) && pid > 0 && pid <= 2147483647);
  assert.match(netns, /^net:\[\d+\]$/);
  const base = `/proc/${pid}`, scope = async () => assert.equal(await readlink(`${base}/ns/net`), netns);
  const held = async () => {
    const inodes = []; let count = 0;
    for await (const entry of await opendir(`${base}/fd`)) {
      assert.ok(++count <= 256, 'adapter FD bound'); assert.match(entry.name, /^\d+$/);
      let target;
      try { target = await readlink(`${base}/fd/${entry.name}`); }
      catch (e) { if (e.code === 'ENOENT') continue; throw e; }
      const match = /^socket:\[([1-9][0-9]*)\]$/.exec(target); if (match) inodes.push(match[1]);
    }
    return inodes;
  };
  await scope(); const before = await held(), tables = {};
  for (const protocol of protocols) tables[protocol] = await procText(`${base}/net/${protocol}`);
  const after = await held(); await scope();
  return assessDnsAdapterSockets({ uid, port, before, after, tables });
}
