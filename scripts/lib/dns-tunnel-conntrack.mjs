/** Reset only selected IPv4 DNS tuples at capture/release boundaries. Never
 * flush conntrack, change marks, reset non-DNS sessions, or invoke a shell. */
import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';
import { compileTunnelDnsPlan } from './dns-tunnel-plan.mjs';

const LIMIT = 128;
export function parseTunnelDnsConntrack(text, protocol) {
  assert.ok(['udp', 'tcp'].includes(protocol)); assert.equal(typeof text, 'string');
  assert.ok(Buffer.byteLength(text) <= 262144, 'DNS conntrack output limit');
  const lines = text.trim() ? text.trim().split('\n') : [];
  assert.ok(lines.length <= LIMIT, 'too many DNS conntrack entries; review required');
  return lines.map((line) => {
    assert.match(line, new RegExp(`^ipv4\\s+2\\s+${protocol}\\s+${protocol === 'udp' ? 17 : 6}\\s+`));
    const fields = {};
    for (const token of line.trim().split(/\s+/)) {
      const [key, value] = token.split('=');
      if (['src', 'dst', 'sport', 'dport', 'zone'].includes(key)) (fields[key] ??= []).push(value);
      assert.ok(!['zone-orig', 'zone-reply'].includes(key), 'directional conntrack zones unsupported');
    }
    for (const key of ['src', 'dst', 'sport', 'dport']) assert.equal(fields[key]?.length, 2, `bad DNS conntrack ${key}`);
    assert.ok(!fields.zone || fields.zone.length === 1 && fields.zone[0] === '0', 'nonzero DNS conntrack zone');
    for (const v of [...fields.src, ...fields.dst]) assert.ok(isIPv4(v), 'bad conntrack IPv4');
    for (const v of [...fields.sport, ...fields.dport]) assert.ok(/^\d{1,5}$/.test(v) && Number(v) > 0 && Number(v) <= 65535, 'bad conntrack port');
    assert.equal(fields.dport[0], '53', 'not ordinary DNS');
    return { protocol, src: fields.src[0], dst: fields.dst[0], sport: Number(fields.sport[0]), dport: 53,
      replySrc: fields.src[1], replyDst: fields.dst[1], replySport: Number(fields.sport[1]), replyDport: Number(fields.dport[1]) };
  });
}
const dumpArgs = (protocol) => ['-L', '-f', 'ipv4', '-p', protocol, '--dport', '53', '-o', 'extended'];
function deleteArgs(e) {
  return ['-D', '-f', 'ipv4', '-p', e.protocol, '-w', '0', '--orig-src', e.src, '--orig-dst', e.dst,
    '--orig-port-src', String(e.sport), '--orig-port-dst', '53', '--reply-src', e.replySrc,
    '--reply-dst', e.replyDst, '--reply-port-src', String(e.replySport), '--reply-port-dst', String(e.replyDport)];
}
function inSubnet(ip, cidr) {
  const n = (s) => s.split('.').reduce((a, b) => ((a << 8) | Number(b)) >>> 0, 0);
  const [base, bits] = cidr.split('/'), mask = (0xffffffff << (32 - Number(bits))) >>> 0;
  return (n(ip) & mask) === (n(base) & mask);
}

/** Called while the journal owns the network and release gate is closed.
 * Forwarded scope requires the source's return route to the selected ingress;
 * asymmetric ingress is not inferred from an IPv4 subnet alone. */
export function resetTunnelDnsConntrack(config, phase, run) {
  const p = compileTunnelDnsPlan(config); assert.ok(['enable', 'disable', 'preflight'].includes(phase));
  const deadline = performance.now() + 10000;
  const exec = (file, args) => { assert.ok(performance.now() < deadline, 'DNS conntrack cleanup deadline'); return run(file, args); };
  const read = (protocol) => parseTunnelDnsConntrack(exec('conntrack', dumpArgs(protocol)), protocol);
  const entries = ['udp', 'tcp'].flatMap(read);
  if (phase === 'preflight' || !entries.length) return { inspected: entries.length, deleted: 0 };
  const local = new Set(JSON.parse(exec('ip', ['-j', '-4', 'addr', 'show'])).flatMap((l) =>
    (l.addr_info ?? []).filter((a) => a.family === 'inet').map((a) => a.local)));
  const routes = new Map();
  const selected = entries.filter((e) => {
    if (e.src === p.listener.address || e.dst.startsWith('127.')) return false;
    const captured = e.replySrc === p.listener.address && e.replySport === p.listener.port;
    if (phase === 'enable' ? captured : !captured) return false;
    if (!p.fromTun && local.has(e.src)) return true;
    const iface = p.fromTun ?? p.lanInterface;
    if (!iface || local.has(e.src) || p.lanSubnet && !inSubnet(e.src, p.lanSubnet)) return false;
    if (!routes.has(e.src)) {
      const rs = JSON.parse(exec('ip', ['-j', '-4', 'route', 'get', e.src]));
      assert.ok(rs.length === 1, 'ambiguous DNS source return route');
      routes.set(e.src, !rs[0].type || rs[0].type === 'unicast' ? rs[0].dev : null);
    }
    return routes.get(e.src) === iface;
  });
  for (const e of selected) {
    try { exec('conntrack', deleteArgs(e)); }
    catch (error) {
      // Entries may expire naturally after the dump. Status alone is not proof
      // of absence: perform a fresh, checked read below even on status 1.
      if (error.status !== 1) throw error;
    }
  }
  const remaining = ['udp', 'tcp'].flatMap(read);
  const key = (e) => JSON.stringify(e);
  assert.ok(selected.every((e) => !remaining.some((r) => key(e) === key(r))), 'DNS conntrack tuple remains after cleanup');
  return { inspected: entries.length, deleted: selected.length };
}
