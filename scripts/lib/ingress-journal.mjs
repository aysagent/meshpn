/** Same-boot, scoped recovery. No shell commands or executable argv are read from disk. */
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { isAbsolute, join, resolve, dirname } from 'node:path';
import { isIPv4 } from 'node:net';
import { installIngressRouting, validateFromTun, INGRESS_TABLE, INGRESS_PRIORITY } from './ingress-routing.mjs';

const LIMIT = 65536;
const C = fs.constants;
const scope = () => ({ boot: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(),
  net: fs.readlinkSync('/proc/self/ns/net'), user: fs.readlinkSync('/proc/self/ns/user') });
function trustedAncestorOwner(uid) {
  if (uid === 0 || uid === process.getuid()) return true;
  // Container ancestors may belong to an unmapped outer administrator. Such a UID
  // cannot be assumed by a process in this user namespace (do not trust a mapped nobody).
  const overflow = Number(fs.readFileSync('/proc/sys/kernel/overflowuid', 'utf8'));
  if (uid !== overflow) return false;
  const ranges = fs.readFileSync('/proc/self/uid_map', 'utf8').trim().split('\n').map((l) => l.trim().split(/\s+/).map(Number));
  return !ranges.some(([start, , size]) => uid >= start && uid < start + size);
}
export const ingressStateDirectory = () => `/run/clean-vpn-ingress-${scope().net.match(/\d+/)[0]}`;
const keys = (v, names) => assert.deepEqual(Object.keys(v).sort(), names.sort(), 'unexpected journal fields');
const iface = (v) => validateFromTun({ fromTun: v, role: 'client' });
function identity(run, name) {
  const links = JSON.parse(run('ip', ['-j', 'link', 'show']));
  const link = links.find((l) => l.ifname === name);
  return link ? { ifindex: link.ifindex, address: link.address ?? '', type: link.link_type } : null;
}
function validate(v) {
  keys(v, ['schema', 'id', 'scope', 'config', 'original', 'links', 'port', 'count', 'stage']);
  assert.equal(v.schema, 1); assert.match(v.id, /^[a-f0-9]{24}$/);
  keys(v.scope, ['boot', 'net', 'user']);
  assert.match(v.scope.boot, /^[a-f0-9-]{36}$/);
  for (const key of ['net', 'user']) assert.match(v.scope[key], new RegExp(`^${key}:\\[\\d+\\]$`));
  keys(v.config, ['ingress', 'tun', 'address']); keys(v.config.ingress, ['name', 'bypass']);
  iface(v.config.ingress.name); iface(v.config.tun); assert.notEqual(v.config.ingress.name, v.config.tun);
  assert.equal(v.config.address, '10.99.0.2');
  assert.ok(Array.isArray(v.config.ingress.bypass) && v.config.ingress.bypass.length <= 256);
  for (const cidr of v.config.ingress.bypass) {
    assert.equal(typeof cidr, 'string'); const [ip, bits, extra] = cidr.split('/');
    assert.ok(isIPv4(ip) && extra === undefined && (bits === undefined || /^(?:[0-9]|[12][0-9]|3[0-2])$/.test(bits)));
  }
  const names = [v.config.ingress.name, v.config.tun]; keys(v.original, [...names]); keys(v.links, [...names]);
  for (const name of names) {
    assert.match(v.original[name], /^[012]$/); keys(v.links[name], ['ifindex', 'address', 'type']);
    assert.ok(Number.isSafeInteger(v.links[name].ifindex) && v.links[name].ifindex > 0);
    assert.equal(typeof v.links[name].address, 'string'); assert.equal(typeof v.links[name].type, 'string');
  }
  assert.ok(v.port === null || (Number.isInteger(v.port) && v.port > 0 && v.port <= 65535));
  assert.ok(['installing', 'restoring', 'released'].includes(v.stage));
  assert.ok(Number.isSafeInteger(v.count) && v.count >= 0 && v.count <= operations(v).length);
  assert.ok(v.stage !== 'released' || v.count === 0);
  return v;
}

// Use the very same installer to generate a deterministic, bounded allowlist of operations.
function operations(v) {
  const result = [], reads = new Set();
  const owner = installIngressRouting({ ...v.config, tag: `cvpn-${v.id}` }, {
    run(file, args) {
      assert.equal(file, 'sysctl'); assert.equal(args[0], '-n');
      const name = args[1].split('/')[3];
      if (reads.has(name)) return '2'; reads.add(name); return v.original[name];
    },
    transaction: { apply: (op) => result.push(op), close() {}, https() {} },
  });
  if (v.port !== null) owner.installHttpsRedirect(v.port);
  return result;
}

function privateFile(fd, mode) {
  const s = fs.fstatSync(fd);
  assert.ok(s.isFile() && s.nlink === 1 && s.uid === process.getuid() && (s.mode & 0o777) === mode, 'unsafe journal/lock file');
  return s;
}

/** Stable flock inode: the subprocess locks a dup of our open file description; our fd holds the lock. */
export function openIngressJournal(directory = ingressStateDirectory(), options = {}) {
  assert.ok(isAbsolute(directory) && resolve(directory) === directory, 'state directory must be an absolute normalized path');
  // Alternative storage must not permit a second owner in the same network namespace.
  // coordinate:false is exclusively for storage-only unit tests without /run permissions.
  const coordination = options.coordinate !== false && directory !== ingressStateDirectory()
    ? openIngressJournal(ingressStateDirectory(), { ...options, coordinate: false }) : null;
  try { return openLocalJournal(directory, options, coordination); }
  catch (error) { coordination?.release(); throw error; }
}
function openLocalJournal(directory, { run: customRun, checkpoint = () => {} }, coordination) {
  assert.ok(isAbsolute(directory) && resolve(directory) === directory, 'state directory must be an absolute normalized path');
  for (let p = dirname(directory); ; p = dirname(p)) {
    const s = fs.lstatSync(p); assert.ok(s.isDirectory() && !s.isSymbolicLink(), 'symlink in state directory path');
    assert.ok(p === '/' || trustedAncestorOwner(s.uid), 'foreign state directory ancestor');
    assert.ok(!(s.mode & 0o022) || (s.mode & 0o1000), 'writable non-sticky state directory ancestor');
    if (p === '/') break;
  }
  try { fs.mkdirSync(directory, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  const dirfd = fs.openSync(directory, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);
  let lockfd, released = false, value = null;
  const run = customRun ?? ((file, args) => execFileSync(file, args, {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe', lockfd, ...(coordination?.lockDescriptors ?? [])],
  }).trim());
  const base = `/proc/self/fd/${dirfd}`;
  const release = () => {
    if (released) return; released = true;
    if (lockfd !== undefined) fs.closeSync(lockfd); fs.closeSync(dirfd); coordination?.release();
  };
  try {
    const s = fs.fstatSync(dirfd);
    assert.ok(s.uid === process.getuid() && (s.mode & 0o777) === 0o700, 'state directory must be owned by caller, mode 0700');
    lockfd = fs.openSync(join(base, 'lock'), C.O_RDWR | C.O_CREAT | C.O_NOFOLLOW | C.O_NONBLOCK, 0o600);
    privateFile(lockfd, 0o600);
    try { execFileSync('flock', ['--exclusive', '--nonblock', '3'], { stdio: ['ignore', 'pipe', 'pipe', lockfd, ...(coordination?.lockDescriptors ?? [])] }); }
    catch { throw new Error('--from-tun: journal locked by a live owner/recovery process'); }
    fs.fsyncSync(dirfd);
    let fd;
    try { fd = fs.openSync(join(base, 'journal.json'), C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK); }
    catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (fd !== undefined) {
      try {
        const s = privateFile(fd, 0o600); assert.ok(s.size > 0 && s.size <= LIMIT, 'journal size limit');
        const b = Buffer.alloc(LIMIT + 1); const n = fs.readSync(fd, b, 0, b.length, 0);
        assert.equal(n, s.size); value = validate(JSON.parse(b.subarray(0, n).toString('utf8')));
      } finally { fs.closeSync(fd); }
    }
  } catch (e) { release(); throw e; }
  const save = () => {
    assert.ok(!released); validate(value);
    const body = JSON.stringify(value); assert.ok(Buffer.byteLength(body) <= LIMIT);
    const tmp = join(base, `journal-${randomBytes(12).toString('hex')}.tmp`);
    const fd = fs.openSync(tmp, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, body); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    checkpoint('file-synced', value);
    fs.renameSync(tmp, join(base, 'journal.json')); checkpoint('renamed', value);
    fs.fsyncSync(dirfd); checkpoint('dir-synced', value);
  };
  const assertScope = () => assert.deepEqual(value.scope, scope(), 'journal belongs to a different boot/network/user namespace; manual review required');
  const restore = ({ apply = true, name = value?.config.ingress.name } = {}) => {
    assert.ok(value, 'no saved ingress journal; legacy/manual state is not adopted'); assertScope();
    assert.equal(name, value.config.ingress.name, 'ingress name does not match journal');
    const plan = operations(value);
    const count = value.count;
    // Audit the whole owned scope BEFORE touching anything, including shared interface settings.
    audit(value, plan, run);
    if (!apply) return { mode: 'dry-run', stage: value.stage, operations: count, restoresPreviousForwarding: true };
    value.stage = 'restoring'; save();
    while (value.count > 0) {
      const op = plan[value.count - 1];
      if (present(value, op, run)) {
        run(op.file, op.remove);
        assert.ok(!present(value, op, run), 'undo did not restore expected state');
      }
      checkpoint('removed', value);
      value.count--; save();
    }
    value.stage = 'released'; save();
    return { mode: 'restored', operations: count, restoresPreviousForwarding: true };
  };
  return {
    release,
    // Mutating subprocesses inherit these descriptors: killing Node must not unlock
    // recovery while an already-running iptables/ip/sysctl can still change state.
    get lockDescriptors() { assert.ok(!released); return [lockfd, ...(coordination?.lockDescriptors ?? [])]; },
    assertAvailable() { assert.ok(!value || value.stage === 'released', '--from-tun: unfinished journal; run clean-vpn-recover.mjs first'); },
    begin(config) {
      this.assertAvailable();
      const original = {}, links = {};
      for (const name of [config.ingress.name, config.tun]) {
        links[name] = identity(run, name); assert.ok(links[name], `missing interface ${name}`);
        original[name] = run('sysctl', ['-n', `net/ipv4/conf/${name}/rp_filter`]);
      }
      value = { schema: 1, id: randomBytes(12).toString('hex'), scope: scope(),
        config: { ...config, address: config.address ?? '10.99.0.2' }, original, links, port: null, count: 0, stage: 'installing' };
      save();
      return {
        tag: `cvpn-${value.id}`,
        apply(op) {
          assert.equal(value.stage, 'installing');
          assert.deepEqual(op, operations(value)[value.count], 'unexpected ingress mutation');
          value.count++; save(); // durable intent BEFORE the mutation, including original sysctl values
          run(op.file, op.args); checkpoint('applied', value);
          if (op.file !== 'sysctl' || op.args[1].split('=').at(-1) !== value.original[op.args[1].split('/')[3]]) {
            assert.ok(present(value, op, run), 'ingress mutation read-back failed');
          }
        },
        https(port) { assert.equal(value.port, null); value.port = port; save(); },
        close() { restore(); release(); },
      };
    },
    restore,
  };
}

// Compare canonical rule tokens; iptables -S adds implicit protocol modules and /32 suffixes.
function canonical(tokens) {
  const words = tokens.join(' ').replace(/"/g, '').replace(/ -m (tcp|udp)(?= |$)/g, '')
    .replace(/\b(\d+\.\d+\.\d+\.\d+)\/32\b/g, '$1')
    .replace(/ESTABLISHED,RELATED/g, 'RELATED,ESTABLISHED').split(/\s+/);
  const pairs = [];
  for (let i = 0; i < words.length; i += 2) {
    if (words[i] === '!') { pairs.push(`! ${words[i + 1]} ${words[i + 2]}`); i++; }
    else pairs.push(`${words[i]} ${words[i + 1] ?? ''}`);
  }
  return pairs.sort().join(' ');
}
function firewallLines(run, op) {
  const table = op.args.includes('-t') ? op.args[op.args.indexOf('-t') + 1] : 'filter';
  return run(op.file, ['-w', '5', '-t', table, '-S']).split('\n').filter(Boolean).map((l) => canonical([l]));
}
function firewallExpected(op) {
  const r = op.remove; const at = r.findIndex((x) => x === '-D' || x === '-X');
  return canonical([r[at] === '-D' ? '-A' : '-N', ...r.slice(at + 1)]);
}
function routeKey(r) {
  const known = new Set(['type', 'dst', 'dev', 'metric', 'gateway', 'protocol', 'scope', 'prefsrc', 'flags', 'table']);
  assert.ok(Object.keys(r).every((key) => known.has(key)), 'unexpected routing attributes; review required');
  return JSON.stringify({ type: r.type ?? 'unicast', dst: r.dst, dev: r.dev ?? null, metric: r.metric ?? 0,
    gateway: r.gateway ?? null, protocol: r.protocol ?? 'boot', scope: r.scope ?? 'global',
    prefsrc: r.prefsrc ?? null, flags: (r.flags ?? []).filter((f) => f !== 'linkdown') });
}
function expectedRoute(op) {
  const a = op.args; const val = (k) => a.includes(k) ? a[a.indexOf(k) + 1] : undefined;
  const type = ['throw', 'unreachable'].includes(a[3]) ? a[3] : 'unicast';
  return routeKey({ type, dst: a[type === 'unicast' ? 3 : 4], dev: val('dev'), metric: Number(val('metric') ?? 0),
    scope: type === 'unicast' ? 'link' : 'global' });
}
function routes(run) { return JSON.parse(run('ip', ['-j', '-4', 'route', 'show', 'table', 'all'])).filter((r) => String(r.table) === String(INGRESS_TABLE)); }
function policies(run) { return JSON.parse(run('ip', ['-j', '-4', 'rule', 'show'])).filter((r) => Number(r.priority) === INGRESS_PRIORITY || String(r.table) === String(INGRESS_TABLE)); }
function isPolicy(v, r) {
  const { priority, src = 'all', table, iif, flags = [], ...extra } = r;
  return priority === INGRESS_PRIORITY && src === 'all' && String(table) === String(INGRESS_TABLE)
    && iif === v.config.ingress.name && flags.length === 0 && Object.keys(extra).length === 0;
}
function present(v, op, run) {
  if (op.file === 'iptables' || op.file === 'ip6tables') {
    const n = firewallLines(run, op).filter((l) => l === firewallExpected(op)).length;
    assert.ok(n <= 1, 'duplicate owned firewall rule'); return n === 1;
  }
  if (op.file === 'sysctl') {
    const name = op.args[1].split('/')[3], link = identity(run, name);
    if (!link) return false;
    assert.deepEqual(link, v.links[name], `interface identity changed: ${name}`);
    const current = run('sysctl', ['-n', `net/ipv4/conf/${name}/rp_filter`]);
    assert.ok(current === v.original[name] || current === '2', `rp_filter conflict: ${name}`);
    return current !== v.original[name];
  }
  if (op.args[1] === 'route') {
    const n = routes(run).filter((r) => routeKey(r) === expectedRoute(op)).length;
    assert.ok(n <= 1, 'duplicate owned route'); return n === 1;
  }
  const rs = policies(run); assert.ok(rs.length <= 1 && rs.every((r) => isPolicy(v, r)), 'policy routing conflict'); return rs.length === 1;
}
function audit(v, plan, run) {
  for (const name of Object.keys(v.links)) {
    const link = identity(run, name);
    if (link) assert.deepEqual(link, v.links[name], `interface identity changed: ${name}`);
  }
  const active = plan.slice(0, v.count);
  for (const file of ['iptables', 'ip6tables']) for (const table of file === 'iptables' ? ['filter', 'nat'] : ['filter']) {
    const relevant = active.filter((op) => op.file === file && (op.args.includes('-t') ? op.args[op.args.indexOf('-t') + 1] : 'filter') === table);
    const allowed = relevant.map(firewallExpected);
    const lines = firewallLines(run, { file, args: ['-t', table] }).filter((l) => /CVPN-INGRESS|cvpn-[a-f0-9]{24}/.test(l));
    assert.ok(lines.every((l) => allowed.includes(l)) && new Set(lines).size === lines.length, `foreign/duplicate firewall state: ${file}/${table}`);
  }
  const allowed = active.filter((op) => op.file === 'ip' && op.args[1] === 'route').map(expectedRoute);
  const actual = routes(run).map(routeKey);
  assert.ok(actual.every((r) => allowed.includes(r)) && new Set(actual).size === actual.length, 'foreign routing table state');
  const rs = policies(run);
  assert.ok(rs.length <= 1 && rs.every((r) => isPolicy(v, r)) && (!rs.length || active.some((op) => op.file === 'ip' && op.args[1] === 'rule')), 'foreign routing policy');
  for (const op of active.filter((op) => op.file === 'sysctl')) present(v, op, run);
}
