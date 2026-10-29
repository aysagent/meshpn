// Explicit systemd-resolved routing scope for .mpn. Owns one empty-use dummy
// interface and its /32; never edits an existing interface or global DNS.
import fs from 'node:fs';
import path from 'node:path';
import { isIPv4 } from 'node:net';
import { randomBytes } from 'node:crypto';
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { createDnsSystemBus } from './dns-system-bus.mjs';
import { resolvedMethod } from './dns-resolved-backend.mjs';

const exec = promisify(execFile), need = (x, code) => assert.ok(x, code);
export const peerDnsZones = Object.freeze(['mpn', '0.99.10.in-addr.arpa']);
export function peerDnsZoneConfig({ address = '169.254.255.53', port = 1055 } = {}) {
  need(isIPv4(address) && address.startsWith('169.254.') && !['0', '255'].includes(address.split('.').at(-1)), 'peer_dns_scope_address');
  need(Number.isInteger(port) && port >= 1024 && port <= 65535, 'peer_dns_scope_port'); return { address, port };
}
const expectedDns = config => ({ DNSEx: [[2, [127, 0, 0, 1], config.port, '']], Domains: peerDnsZones.map(n => [n, true]), DefaultRoute: false });
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
export function validatePeerDnsZoneRecord(r) {
  need(r?.version === 1 && r.kind === 'clean-vpn-peer-dns-zone' && /^[a-f0-9]{32}$/.test(r.id), 'peer_dns_zone_journal');
  assert.deepEqual(r.config, peerDnsZoneConfig(r.config));
  need(r.name === 'cvmpn' + r.id.slice(0, 8) && r.mac === '02:' + r.id.slice(8, 18).match(/../g).join(':'), 'peer_dns_zone_identity');
  need(['intent', 'active'].includes(r.phase) && (r.ifindex === null || Number.isSafeInteger(r.ifindex) && r.ifindex > 1), 'peer_dns_zone_phase');
  need(typeof r.boot === 'string' && /^[a-f0-9-]{36}$/.test(r.boot) && /^net:\[\d+\]$/.test(r.net), 'peer_dns_zone_scope');
  need(r.owner === null || /^:\d+\.\d+$/.test(r.owner), 'peer_dns_zone_bus'); need(r.phase !== 'active' || r.ifindex !== null && r.owner !== null, 'peer_dns_zone_active_identity'); return r;
}
function trustedDirectory(directory, create = false) {
  need(typeof directory === 'string' && path.isAbsolute(directory) && path.normalize(directory) === directory && directory !== '/', 'peer_dns_zone_directory');
  for (let p = path.dirname(directory); ; p = path.dirname(p)) {
    const s = fs.lstatSync(p); need(s.isDirectory() && !s.isSymbolicLink() && s.uid === 0 && (!(s.mode & 0o022) || (s.mode & 0o1000)), 'peer_dns_zone_parent'); if (p === '/') break;
  }
  if (create) try { fs.mkdirSync(directory, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  const st = fs.lstatSync(directory); need(st.isDirectory() && !st.isSymbolicLink() && st.uid === 0 && (st.mode & 0o777) === 0o700, 'peer_dns_zone_private_directory');
}
function load(filename) {
  let fd; try { fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
  catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  try { const s = fs.fstatSync(fd); need(s.isFile() && s.nlink === 1 && s.uid === 0 && (s.mode & 0o777) === 0o600 && s.size > 0 && s.size <= 16384, 'peer_dns_zone_private_journal'); const buffer = Buffer.alloc(16385), length = fs.readSync(fd, buffer, 0, buffer.length, 0); need(length <= 16384, 'peer_dns_zone_journal_limit'); return validatePeerDnsZoneRecord(JSON.parse(buffer.subarray(0, length).toString('utf8'))); }
  finally { fs.closeSync(fd); }
}
function syncDirectory(directory) { const fd = fs.openSync(directory, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function save(filename, value) {
  validatePeerDnsZoneRecord(value); const next = filename + '.' + randomBytes(8).toString('hex');
  const fd = fs.openSync(next, 'wx', 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  try { fs.renameSync(next, filename); syncDirectory(path.dirname(filename)); } finally { if (fs.existsSync(next)) fs.unlinkSync(next); }
}
export async function createPeerDnsZoneBackend({ run = (cmd, args) => exec(cmd, args, { timeout: 6000, maxBuffer: 262144, env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' } }) } = {}) {
  const bus = createDnsSystemBus(run), ip = async args => JSON.parse((await run('ip', args)).stdout);
  const context = async () => ({ boot: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(), net: fs.readlinkSync('/proc/self/ns/net'), owner: await bus.owner() });
  const link = async name => {
    const l = (await ip(['-d', '-j', 'link', 'show'])).find(x => x.ifname === name); if (!l) return null;
    const a = (await ip(['-j', 'address', 'show', 'dev', name]))[0];
    return { index: l.ifindex, name: l.ifname, mac: l.address, alias: l.ifalias ?? '', kind: l.linkinfo?.info_kind,
      mtu: l.mtu, master: l.master ?? null, up: l.flags.includes('UP'), addresses: a.addr_info.map(x => `${x.family}:${x.local}/${x.prefixlen}`).sort() };
  };
  const dns = async (owner, index) => {
    for (let i = 0; ; i++) { try { return await bus.linkSnapshot(owner, index); } catch (e) { if (i >= 10) throw e; await delay(50); } }
  };
  return { context, link, dns,
    async assertForeignDomains(owner, exclude) {
      const values = (await bus.managerSnapshot(owner)).Domains;
      for (const [index, domain] of values) if (index !== exclude) need(!peerDnsZones.some(z => domain.toLowerCase() === z || domain.toLowerCase().endsWith('.' + z)), 'peer_dns_foreign_zone_conflict');
    },
    async assertAddressAvailable(address, exclude) {
      const number = value => value.split('.').reduce((n, v) => n * 256 + Number(v), 0);
      const overlap = cidr => { const [base, rawBits] = cidr.split('/'), bits = rawBits === undefined ? 32 : Number(rawBits); if (!isIPv4(base) || bits === 0) return false; const block = 2 ** (32 - bits); return Math.floor(number(base) / block) === Math.floor(number(address) / block); };
      for (const item of await ip(['-j', '-4', 'address', 'show'])) if (item.ifname !== exclude)
        for (const a of item.addr_info) need(!overlap(`${a.local}/${a.prefixlen}`), 'peer_dns_scope_address_conflict');
      for (const route of await ip(['-j', '-4', 'route', 'show', 'table', 'all'])) if (route.dev !== exclude && route.dst && route.dst !== 'default') need(!overlap(route.dst), 'peer_dns_scope_route_conflict');
    },
    async create(r) { await run('ip', ['link', 'add', 'name', r.name, 'address', r.mac, 'mtu', '1500', 'type', 'dummy']); },
    async stamp(r) { await run('ip', ['link', 'set', 'dev', r.name, 'alias', 'clean-vpn-mpn:' + r.id]); },
    async address(r) { await run('ip', ['link', 'set', 'dev', r.name, 'addrgenmode', 'none']); await run('ip', ['address', 'add', r.config.address + '/32', 'dev', r.name]); },
    async up(r) { await run('ip', ['link', 'set', 'dev', r.name, 'up']); },
    async set(owner, index, property, value) { await bus.set(owner, resolvedMethod(property, value, index)); },
    async remove(r) { await run('ip', ['link', 'delete', 'dev', r.name]); },
  };
}
function owned(r, link, partial) {
  need(link && link.name === r.name && link.kind === 'dummy' && link.mac === r.mac && link.mtu === 1500 && link.master === null, 'peer_dns_zone_link_conflict');
  need(r.ifindex === null || link.index === r.ifindex, 'peer_dns_zone_link_reused');
  need(link.alias === 'clean-vpn-mpn:' + r.id || partial && link.alias === '', 'peer_dns_zone_alias_conflict');
  need(same(link.addresses, ['inet:' + r.config.address + '/32']) || partial && !link.addresses.length, 'peer_dns_zone_address_conflict');
  need(link.up || partial, 'peer_dns_zone_link_down');
}
function compatibleDns(current, expected, partial) {
  for (const key of ['DNSEx', 'Domains']) {
    const sorted = list => [...list].map(x => JSON.stringify(x)).sort();
    need(same(sorted(current[key]), sorted(expected[key])) || partial && current[key].every(x => expected[key].some(y => same(x, y))), 'peer_dns_zone_settings_conflict');
  }
  need(current.DefaultRoute === false || partial, 'peer_dns_zone_default_route_conflict');
}

export async function peerDnsZoneOperation({ directory, operation = 'apply', config = {}, backend, checkpoint = () => {} }) {
  need(process.platform === 'linux' && process.getuid() === 0, 'peer_dns_zone_linux_root');
  need(['apply', 'remove', 'status'].includes(operation), 'peer_dns_zone_operation'); config = peerDnsZoneConfig(config);
  trustedDirectory(directory, operation === 'apply');
  const lock = fs.openSync(directory + '/lock', fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600);
  try {
    const st = fs.fstatSync(lock); need(st.isFile() && st.uid === 0 && st.nlink === 1 && (st.mode & 0o777) === 0o600, 'peer_dns_zone_lock');
    execFileSync('flock', ['-n', '3'], { stdio: ['ignore', 'pipe', 'pipe', lock], timeout: 3000 });
    backend ??= await createPeerDnsZoneBackend(); const context = await backend.context(); const filename = directory + '/zone.json';
    let r = load(filename);
    if (r) assert.deepEqual(r.config, config, 'peer_dns_zone_config_changed');
    if (r && r.boot !== context.boot) {
      need(!(await backend.link(r.name)), 'peer_dns_zone_stale_link');
      if (operation === 'apply') r = null;
      else { if (operation === 'remove') { fs.unlinkSync(filename); syncDirectory(directory); } return { status: operation === 'remove' ? 'removed' : 'stale', previousBoot: true }; }
    }
    if (r) need(r.net === context.net, 'peer_dns_zone_namespace_changed');
    if (!r) {
      if (operation !== 'apply') return { status: 'absent' };
      await backend.assertForeignDomains(context.owner, null); await backend.assertAddressAvailable(config.address, null);
      const id = randomBytes(16).toString('hex');
      r = { version: 1, kind: 'clean-vpn-peer-dns-zone', id, name: 'cvmpn' + id.slice(0, 8), mac: '02:' + id.slice(8, 18).match(/../g).join(':'), config,
        phase: 'intent', ifindex: null, boot: context.boot, net: context.net, owner: null };
      need(!(await backend.link(r.name)), 'peer_dns_zone_name_occupied'); save(filename, r); await checkpoint('intent');
    }
    const expected = expectedDns(config); let view = await backend.link(r.name);
    if (operation === 'remove') {
      if (view) { owned(r, view, r.phase === 'intent'); const current = await backend.dns(context.owner, view.index); const reset = r.owner !== context.owner && !current.DNSEx.length && !current.Domains.length; compatibleDns(current, expected, r.phase === 'intent' || reset); await backend.remove(r); }
      need(!(await backend.link(r.name)), 'peer_dns_zone_remove_failed'); fs.unlinkSync(filename); syncDirectory(directory); return { status: 'removed', name: r.name };
    }
    if (operation === 'status') {
      owned(r, view, false); compatibleDns(await backend.dns(context.owner, view.index), expected, false); await backend.assertForeignDomains(context.owner, view.index);
      return { status: 'active', name: r.name, address: config.address, zones: peerDnsZones, port: config.port };
    }
    await backend.assertForeignDomains(context.owner, view?.index ?? null); await backend.assertAddressAvailable(config.address, r.name);
    if (!view) { need(r.phase === 'intent', 'peer_dns_zone_link_missing'); await backend.create(r); await checkpoint('created'); view = await backend.link(r.name); }
    owned(r, view, r.phase === 'intent');
    if (r.ifindex === null) { r.ifindex = view.index; save(filename, r); }
    if (!view.alias) { await backend.stamp(r); await checkpoint('stamped'); }
    if (!view.addresses.length) { await backend.address(r); await checkpoint('addressed'); }
    if (!view.up) { await backend.up(r); await checkpoint('up'); }
    const current = await backend.dns(context.owner, r.ifindex);
    const reset = r.owner !== context.owner && !current.DNSEx.length && !current.Domains.length;
    compatibleDns(current, expected, r.phase === 'intent' || reset);
    for (const key of ['DefaultRoute', 'DNSEx', 'Domains']) if (!same(current[key], expected[key])) {
      owned(r, await backend.link(r.name), false);
      await backend.assertForeignDomains(context.owner, r.ifindex);
      await backend.set(context.owner, r.ifindex, key, expected[key]); await checkpoint('set-' + key);
    }
    owned(r, await backend.link(r.name), false); compatibleDns(await backend.dns(context.owner, r.ifindex), expected, false);
    if (r.phase !== 'active' || r.owner !== context.owner) { r.phase = 'active'; r.owner = context.owner; save(filename, r); } await checkpoint('active');
    return { status: 'active', name: r.name, address: config.address, zones: peerDnsZones, port: config.port };
  } finally { fs.closeSync(lock); }
}
