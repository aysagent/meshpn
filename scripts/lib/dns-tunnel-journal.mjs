/** Same-boot network-only ownership for plain tunnel DNS. No DNS manager,
 * service, default-route or sysctl setters. Journal data is never executable. */
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { compileTunnelDnsPlan, compileTunnelDnsHold, TUNNEL_DNS_TABLE, TUNNEL_DNS_PRIORITIES } from './dns-tunnel-plan.mjs';

const C = fs.constants, LIMIT = 16384;
const keys = (v, names) => assert.deepEqual(Object.keys(v).sort(), [...names].sort(), 'unexpected tunnel DNS journal fields');
const scope = () => ({ boot: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(),
  net: fs.readlinkSync('/proc/self/ns/net'), user: fs.readlinkSync('/proc/self/ns/user') });
export const tunnelDnsStateDirectory = () => `/run/clean-vpn-tunnel-dns-${scope().net.match(/\d+/)[0]}`;
const configOf = (c) => {
  const p = compileTunnelDnsPlan(c);
  return { tun: p.tun, primary: p.servers[0], fromTun: p.fromTun, lanSubnet: p.lanSubnet, lanInterface: p.lanInterface };
};
const operations = (v) => compileTunnelDnsPlan({ ...v.config, tag: `clean-vpn-dns-tunnel-${v.id}` }).operations;
const holds = (v) => compileTunnelDnsHold(v.config, v.id);
const linkNames = (c) => [c.tun, c.fromTun, c.lanInterface].filter(Boolean);
export function validateTunnelDnsJournal(v) {
  keys(v, ['schema', 'id', 'scope', 'config', 'links', 'firewall', 'count', 'hold', 'stage']);
  assert.equal(v.schema, 1); assert.match(v.id, /^[a-f0-9]{24}$/);
  keys(v.scope, ['boot', 'net', 'user']); assert.match(v.scope.boot, /^[a-f0-9-]{36}$/);
  for (const k of ['net', 'user']) assert.match(v.scope[k], new RegExp(`^${k}:\\[\\d+\\]$`));
  keys(v.config, ['tun', 'primary', 'fromTun', 'lanSubnet', 'lanInterface']);
  assert.deepEqual(v.config, configOf(v.config));
  keys(v.links, linkNames(v.config));
  for (const l of Object.values(v.links)) {
    keys(l, ['ifindex', 'address', 'type']); assert.ok(Number.isSafeInteger(l.ifindex) && l.ifindex > 0);
    assert.ok(typeof l.address === 'string' && l.address.length <= 64 && typeof l.type === 'string' && l.type.length <= 32);
  }
  assert.ok(['nf_tables', 'legacy'].includes(v.firewall));
  assert.ok(Number.isInteger(v.count) && v.count >= 0 && v.count <= operations(v).length);
  assert.ok(Number.isInteger(v.hold) && v.hold >= 0 && v.hold <= holds(v).length);
  assert.ok(['installing', 'active', 'restoring', 'parked', 'released'].includes(v.stage));
  if (v.stage === 'active') { assert.equal(v.count, operations(v).length); assert.equal(v.hold, 0); }
  if (v.stage === 'released' || v.stage === 'parked') assert.equal(v.count, 0);
  if (v.stage === 'released') assert.equal(v.hold, 0);
  if (v.stage === 'parked') assert.equal(v.hold, holds(v).length);
  return v;
}

function trustedOwner(uid) {
  if (uid === 0 || uid === process.getuid()) return true;
  if (uid !== Number(fs.readFileSync('/proc/sys/kernel/overflowuid', 'utf8'))) return false;
  return !fs.readFileSync('/proc/self/uid_map', 'utf8').trim().split('\n').some((line) => {
    const [start, , size] = line.trim().split(/\s+/).map(Number); return uid >= start && uid < start + size;
  });
}
function privateFile(fd) {
  const s = fs.fstatSync(fd);
  assert.ok(s.isFile() && s.nlink === 1 && s.uid === process.getuid() && (s.mode & 0o777) === 0o600, 'unsafe journal/lock file');
  return s;
}

/** Alternate directories still coordinate on one netns lock. coordinate:false
 * and run/checkpoint injection are internal unit-test options, never CLI flags. */
export function openTunnelDnsJournal(directory = tunnelDnsStateDirectory(), options = {}) {
  assert.ok(isAbsolute(directory) && resolve(directory) === directory, 'absolute normalized DNS state directory required');
  const coordination = options.coordinate !== false && directory !== tunnelDnsStateDirectory()
    ? openTunnelDnsJournal(tunnelDnsStateDirectory(), { ...options, coordinate: false }) : null;
  try { return openLocal(directory, options, coordination); } catch (e) { coordination?.release(); throw e; }
}
function openLocal(directory, { run: customRun, checkpoint = () => {} }, coordination) {
  for (let p = dirname(directory); ; p = dirname(p)) {
    const s = fs.lstatSync(p);
    assert.ok(s.isDirectory() && !s.isSymbolicLink() && trustedOwner(s.uid), 'unsafe DNS state ancestor');
    assert.ok(!(s.mode & 0o022) || (s.mode & 0o1000), 'writable non-sticky DNS state ancestor');
    if (p === '/') break;
  }
  try { fs.mkdirSync(directory, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  const dirfd = fs.openSync(directory, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW), base = `/proc/self/fd/${dirfd}`;
  let lockfd, released = false, value = null;
  const release = () => {
    if (released) return; released = true;
    if (lockfd !== undefined) fs.closeSync(lockfd); fs.closeSync(dirfd); coordination?.release();
  };
  const run = customRun ?? ((file, args) => execFileSync(file, args, { encoding: 'utf8', timeout: 10000,
    stdio: ['ignore', 'pipe', 'pipe', lockfd, ...(coordination?.lockDescriptors ?? [])] }).trim());
  try {
    const s = fs.fstatSync(dirfd);
    assert.ok(s.uid === process.getuid() && (s.mode & 0o777) === 0o700, 'DNS state directory must be owned, mode 0700');
    lockfd = fs.openSync(join(base, 'lock'), C.O_RDWR | C.O_CREAT | C.O_NOFOLLOW | C.O_NONBLOCK, 0o600); privateFile(lockfd);
    try { execFileSync('flock', ['--exclusive', '--nonblock', '3'], { stdio: ['ignore', 'pipe', 'pipe', lockfd, ...(coordination?.lockDescriptors ?? [])] }); }
    catch { throw new Error('tunnel DNS journal locked by a live owner/recovery process'); }
    fs.fsyncSync(dirfd);
    let fd;
    try { fd = fs.openSync(join(base, 'journal.json'), C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK); }
    catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (fd !== undefined) try {
      const s = privateFile(fd); assert.ok(s.size > 0 && s.size <= LIMIT, 'DNS journal size limit');
      const b = Buffer.alloc(LIMIT + 1), n = fs.readSync(fd, b, 0, b.length, 0); assert.equal(n, s.size);
      value = validateTunnelDnsJournal(JSON.parse(b.subarray(0, n).toString('utf8')));
    } finally { fs.closeSync(fd); }
  } catch (e) { release(); throw e; }
  const save = () => {
    assert.ok(!released); validateTunnelDnsJournal(value);
    const body = JSON.stringify(value); assert.ok(Buffer.byteLength(body) <= LIMIT);
    const temporary = join(base, `journal-${randomBytes(12).toString('hex')}.tmp`);
    const fd = fs.openSync(temporary, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, body); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    checkpoint('file-synced', value); fs.renameSync(temporary, join(base, 'journal.json'));
    checkpoint('renamed', value); fs.fsyncSync(dirfd); checkpoint('dir-synced', value);
  };
  const observe = () => {
    assert.ok(!released && value, 'no tunnel DNS journal');
    assert.deepEqual(value.scope, scope(), 'different boot/network/user namespace; review required');
    const snapshot = readNetwork(run); assert.equal(snapshot.firewall, value.firewall, 'firewall backend changed');
    for (const [name, old] of Object.entries(value.links)) {
      // Parked state owns only gates, not the old TUN. A replacement TUN may
      // now legitimately reuse that name; selected ingress identity still matters.
      if (value.stage === 'parked' && name === value.config.tun) continue;
      if (snapshot.links[name]) assert.deepEqual(snapshot.links[name], old, `interface identity changed: ${name}`);
    }
    audit(snapshot, [...operations(value).slice(0, value.count), ...holds(value).slice(0, value.hold)]);
    return snapshot;
  };
  const present = (op, snapshot = observe()) => snapshot.items.includes(operationKey(op));
  const ensureHold = () => {
    observe(); value.stage = 'restoring'; save();
    for (const [index, op] of holds(value).entries()) {
      value.hold = Math.max(value.hold, index + 1); save();
      if (!present(op)) run(op.file, op.args);
      assert.ok(present(op), 'DNS hold read-back failed'); checkpoint('hold-applied', value);
    }
  };
  const removeHold = () => {
    while (value.hold > 0) {
      const op = holds(value)[value.hold - 1];
      if (present(op)) run(op.file, op.remove);
      assert.ok(!present(op), 'DNS hold undo failed'); checkpoint('hold-removed', value);
      value.hold--; save();
    }
  };
  const restore = ({ keepHold = false, apply = true } = {}) => {
    observe();
    if (!apply) return { stage: value.stage, operations: value.count, hold: value.hold, mode: 'dry-run' };
    if (value.stage === 'released' && !keepHold) return { mode: 'restored', operations: 0 };
    // Audited before installing anything; a foreign rule is never adopted/deleted.
    ensureHold(); const count = value.count;
    while (value.count > 0) {
      const op = operations(value)[value.count - 1];
      if (present(op)) run(op.file, op.remove);
      assert.ok(!present(op), 'DNS network undo failed'); checkpoint('removed', value);
      value.count--; save();
    }
    if (!keepHold) removeHold();
    value.stage = keepHold ? 'parked' : 'released'; save();
    return { mode: keepHold ? 'parked' : 'restored', operations: count };
  };
  return {
    release, restore,
    get lockDescriptors() { assert.ok(!released); return [lockfd, ...(coordination?.lockDescriptors ?? [])]; },
    get state() { return value ? structuredClone(value) : null; },
    prepareRestart({ fromTun = null, lanSubnet = null, lanInterface = null } = {}) {
      if (!value || value.stage === 'released') return;
      assert.deepEqual({ fromTun, lanSubnet, lanInterface },
        { fromTun: value.config.fromTun, lanSubnet: value.config.lanSubnet, lanInterface: value.config.lanInterface }, 'DNS restart scope changed; explicit recovery required');
      restore({ keepHold: true });
    },
    begin(input) {
      assert.ok(!released); const config = configOf(input);
      assert.ok(!value || ['released', 'parked'].includes(value.stage), 'unfinished tunnel DNS journal; recover first');
      if (value?.stage === 'parked') {
        observe();
        for (const key of ['fromTun', 'lanSubnet', 'lanInterface']) assert.equal(config[key], value.config[key], 'DNS parked scope changed');
      }
      const snapshot = readNetwork(run);
      audit(snapshot, value?.stage === 'parked' ? holds(value) : []);
      const links = {};
      for (const name of linkNames(config)) { assert.ok(snapshot.links[name], `missing interface ${name}`); links[name] = snapshot.links[name]; }
      const oldHold = value?.stage === 'parked' ? value.hold : 0, id = oldHold ? value.id : randomBytes(12).toString('hex');
      value = { schema: 1, id, scope: scope(), config, links, firewall: snapshot.firewall, count: 0, hold: oldHold, stage: 'installing' }; save();
      return this;
    },
    applyStage(stage) {
      assert.ok(['guard', 'route', 'activate'].includes(stage)); assert.equal(value?.stage, 'installing'); observe();
      const plan = operations(value); assert.equal(plan[value.count]?.stage, stage, 'DNS stages out of order');
      while (plan[value.count]?.stage === stage) {
        const op = plan[value.count]; assert.ok(!present(op), 'DNS operation exists before intent');
        value.count++; save(); run(op.file, op.args);
        assert.ok(present(op), 'DNS operation read-back failed'); checkpoint('applied', value);
      }
    },
    activate() {
      assert.equal(value?.stage, 'installing'); assert.equal(value.count, operations(value).length, 'incomplete DNS installation');
      const snapshot = observe(); assert.ok(operations(value).every((op) => present(op, snapshot)), 'missing DNS network state');
      removeHold(); value.stage = 'active'; save();
    },
  };
}

// Canonicalize only known iptables serialization differences. Unknown rules in
// our chains/tag space are a conflict, even when they look harmless.
function firewallKey(line) {
  const tokens = line.replace(/"/g, '').replace(/ -m (tcp|udp)(?= |$)/g, '')
    .replace(/ --reject-with (icmp-port-unreachable|icmp6-port-unreachable)(?= |$)/g, '')
    .replace(/\b(\d+\.\d+\.\d+\.\d+)\/32\b/g, '$1').split(/\s+/);
  const pairs = [];
  for (let i = 0; i < tokens.length; i += 2) {
    if (tokens[i] === '!') { pairs.push(`! ${tokens[i + 1]} ${tokens[i + 2]}`); i++; }
    else pairs.push(`${tokens[i]} ${tokens[i + 1] ?? ''}`);
  }
  return pairs.sort().join(' ');
}
const addr = (v) => v?.replace(/\/32$/, '');
function routeKey(r) {
  const allowed = ['type', 'dst', 'dev', 'metric', 'gateway', 'protocol', 'scope', 'prefsrc', 'flags', 'table'];
  assert.ok(Object.keys(r).every((k) => allowed.includes(k)), 'unknown DNS route attributes');
  return JSON.stringify({ type: r.type ?? 'unicast', dst: addr(r.dst), dev: r.dev ?? null,
    metric: r.metric ?? 0, gateway: r.gateway ?? null, protocol: r.protocol ?? 'boot', scope: r.scope ?? 'global',
    prefsrc: r.prefsrc ?? null, flags: (r.flags ?? []).filter((f) => f !== 'linkdown') });
}
function policyKey(r) {
  const { priority, src = 'all', dst = 'all', table, flags = [], ...extra } = r;
  assert.deepEqual(extra, {}, 'unknown DNS policy attributes'); assert.deepEqual(flags, []);
  return JSON.stringify({ priority, src: addr(src), dst: addr(dst), table: String(table) });
}
function operationKey(op) {
  const a = op.args, val = (key) => a.includes(key) ? a[a.indexOf(key) + 1] : undefined;
  if (op.file !== 'ip') {
    const r = op.remove, at = r.findIndex((s) => s === '-D' || s === '-X');
    return `${op.file}/${val('-t')}/${firewallKey([r[at] === '-D' ? '-A' : '-N', ...r.slice(at + 1)].join(' '))}`;
  }
  if (a[1] === 'rule') return `policy/${policyKey({ priority: Number(val('priority')), src: val('from'), dst: val('to'), table: val('lookup') })}`;
  const type = a[3] === 'unreachable' ? 'unreachable' : 'unicast';
  return `route/${routeKey({ type, dst: a[type === 'unicast' ? 3 : 4], dev: val('dev'), metric: Number(val('metric') ?? 0),
    prefsrc: val('src'), scope: type === 'unicast' ? 'link' : 'global' })}`;
}
function readNetwork(run) {
  const versions = ['iptables', 'ip6tables'].map((file) => run(file, ['--version']).match(/\((nf_tables|legacy)\)/)?.[1]);
  assert.ok(versions[0] && versions[0] === versions[1], 'unknown or mixed firewall backends');
  const items = [];
  for (const file of ['iptables', 'ip6tables']) for (const table of file === 'iptables' ? ['filter', 'nat'] : ['filter']) {
    for (const line of run(file, ['-w', '5', '-t', table, '-S']).split('\n')) {
      if (/CVPN-DNS-|clean-vpn-dns-(?:tunnel|hold)/.test(line)) items.push(`${file}/${table}/${firewallKey(line)}`);
    }
  }
  for (const r of JSON.parse(run('ip', ['-j', '-4', 'route', 'show', 'table', 'all'])))
    if (String(r.table) === String(TUNNEL_DNS_TABLE)) items.push(`route/${routeKey(r)}`);
  for (const r of JSON.parse(run('ip', ['-j', '-4', 'rule', 'show'])))
    if (TUNNEL_DNS_PRIORITIES.includes(r.priority) || String(r.table) === String(TUNNEL_DNS_TABLE)) items.push(`policy/${policyKey(r)}`);
  const links = Object.fromEntries(JSON.parse(run('ip', ['-j', 'link', 'show'])).map((l) => [l.ifname,
    { ifindex: l.ifindex, address: l.address ?? '', type: l.link_type }]));
  return { firewall: versions[0], items, links };
}
function audit(snapshot, allowed) {
  const expected = allowed.map(operationKey);
  assert.ok(snapshot.items.every((key) => expected.includes(key)), 'foreign tunnel DNS network state; review required');
  assert.equal(new Set(snapshot.items).size, snapshot.items.length, 'duplicate tunnel DNS network state');
}
