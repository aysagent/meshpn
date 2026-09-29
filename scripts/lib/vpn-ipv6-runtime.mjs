/** Same-boot IPv6 ownership. Fixed plans, private flock journal, fail-closed client guard. */
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { runTunnelDnsCommand } from './dns-tunnel-command.mjs';
import { CLIENT6, EXIT6, IPV6_TABLE, IPV6_PRIORITY, ipv6Plan, ipv6TunnelRoute, validV6Interface, isVpnIpv6Rule, overlapsVpnIpv6 } from './vpn-ipv6.mjs';

const C = fs.constants;
const scope = () => ({ boot: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(), net: fs.readlinkSync('/proc/self/ns/net'), user: fs.readlinkSync('/proc/self/ns/user') });
export const ipv6StateDirectory = () => `/run/clean-vpn-ipv6-${scope().net.match(/\d+/)[0]}`;
const keys = (v, k) => assert.deepEqual(Object.keys(v).sort(), [...k].sort());
export function validateIpv6State(v) {
  keys(v, ['schema', 'scope', 'config', 'links', 'backend', 'count', 'dynamic', 'stage']); assert.equal(v.schema, 1);
  keys(v.scope, ['boot', 'net', 'user']); assert.match(v.scope.boot, /^[a-f0-9-]{36}$/);
  assert.match(v.scope.net, /^net:\[\d+\]$/); assert.match(v.scope.user, /^user:\[\d+\]$/);
  keys(v.config, ['role', 'tun', 'ext', 'id', 'forward', 'tunForward']); assert.match(v.config.tunForward, /^[01]$/);
  const ops = ipv6Plan(v.config);
  assert.ok(Number.isInteger(v.count) && v.count >= 0 && v.count <= ops.length);
  assert.equal(typeof v.dynamic, 'boolean'); assert.ok(!v.dynamic || v.config.role === 'client');
  assert.ok(['installing', 'active', 'restoring', 'released'].includes(v.stage));
  assert.ok(['legacy', 'nf_tables'].includes(v.backend));
  keys(v.links, [v.config.tun, ...(v.config.ext ? [v.config.ext] : [])]);
  for (const link of Object.values(v.links)) {
    keys(link, ['ifindex', 'address', 'type']); assert.ok(Number.isInteger(link.ifindex) && link.ifindex > 0);
    assert.ok(typeof link.address === 'string' && typeof link.type === 'string');
  }
  if (v.stage === 'released') assert.ok(v.count === 0 && !v.dynamic);
  if (v.stage === 'active') assert.equal(v.count, ops.length);
  return v;
}

function privateFile(fd) {
  const s = fs.fstatSync(fd); assert.ok(s.isFile() && s.uid === process.getuid() && s.nlink === 1 && (s.mode & 0o777) === 0o600);
  return s;
}
export function openIpv6Runtime({ run: injectedRun, checkpoint = () => {} } = {}) {
  const directory = ipv6StateDirectory();
  const parent = fs.lstatSync('/run'); assert.ok(parent.isDirectory() && !parent.isSymbolicLink() && parent.uid === 0 && !(parent.mode & 0o022));
  try { fs.mkdirSync(directory, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  const dfd = fs.openSync(directory, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW), base = `/proc/self/fd/${dfd}`;
  let lock, state = null, released = false, deadline = performance.now() + 120000;
  const resetBudget = () => { deadline = performance.now() + 120000; };
  const run = (file, args) => {
    const remaining = deadline - performance.now(); assert.ok(remaining > 0, 'IPv6 operation budget exceeded; recovery journal retained');
    return injectedRun ? injectedRun(file, args) : runTunnelDnsCommand(file, args, { lockDescriptors: lock === undefined ? [] : [lock], timeoutMs: Math.min(8000, remaining) });
  };
  const release = () => { if (released) return; released = true; if (lock !== undefined) fs.closeSync(lock); fs.closeSync(dfd); };
  try {
    const d = fs.fstatSync(dfd); assert.ok(d.uid === process.getuid() && (d.mode & 0o777) === 0o700, 'unsafe IPv6 state directory');
    lock = fs.openSync(`${base}/lock`, C.O_RDWR | C.O_CREAT | C.O_NOFOLLOW | C.O_NONBLOCK, 0o600); privateFile(lock);
    runTunnelDnsCommand('flock', ['--exclusive', '--nonblock', '3'], { lockDescriptors: [lock] });
    let fd;
    try { fd = fs.openSync(`${base}/journal.json`, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (fd !== undefined) try {
      const s = privateFile(fd); assert.ok(s.size > 0 && s.size < 16384);
      const b = Buffer.alloc(s.size); assert.equal(fs.readSync(fd, b, 0, b.length, 0), s.size);
      state = validateIpv6State(JSON.parse(b.toString()));
    } finally { fs.closeSync(fd); }
  } catch (e) { release(); throw e; }
  const save = () => {
    assert.ok(!released); validateIpv6State(state);
    const temp = `${base}/state-${randomBytes(12).toString('hex')}.tmp`;
    const fd = fs.openSync(temp, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, JSON.stringify(state)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(temp, `${base}/journal.json`); fs.fsyncSync(dfd); checkpoint('saved', state);
  };
  const read = args => JSON.parse(run('ip', ['-j', ...args]));
  const backend = () => { const v = run('ip6tables', ['--version']); assert.match(v, /\((nf_tables|legacy)\)/); return /\((nf_tables|legacy)\)/.exec(v)[1]; };
  const identities = () => Object.fromEntries(read(['link', 'show']).map(l => [l.ifname, { ifindex: l.ifindex, address: l.address ?? '', type: l.link_type }]));
  const routeRows = () => read(['-6', 'route', 'show', 'table', 'all']).filter(r => String(r.table) === IPV6_TABLE);
  function audit() {
    assert.ok(state && !released); assert.deepEqual(state.scope, scope(), 'IPv6 journal from another boot/namespace');
    assert.equal(backend(), state.backend, 'IPv6 firewall backend changed');
    const current = identities();
    for (const [name, link] of Object.entries(state.links)) {
      if (current[name]) assert.deepEqual(current[name], link, `IPv6 interface replaced: ${name}`);
      else assert.equal(name, state.config.tun, 'exit interface missing');
    }
    if (state.config.role === 'client') {
      const rules = read(['-6', 'rule', 'show']);
      for (const rule of rules.filter(r => String(r.priority) === IPV6_PRIORITY || String(r.table) === IPV6_TABLE))
        assert.ok(isVpnIpv6Rule(rule), 'foreign IPv6 policy rule');
      assert.ok(rules.filter(r => String(r.priority) === IPV6_PRIORITY).length <= 1, 'duplicate IPv6 rules');
      for (const r of routeRows()) assert.ok((r.type === 'unreachable' && r.dst === 'default' && r.metric === 32767) ||
        (r.dst === '2000::/3' && r.dev === state.config.tun && r.prefsrc === CLIENT6), 'foreign IPv6 table entry');
    }
    return current;
  }
  function present(op) {
    if (op.kind === 'fw' || op.kind === 'chain') {
      try { run(op.file, op.check); return true; } catch (e) { if (e.status === 1) return false; throw e; }
    }
    if (op.kind === 'sysctl') return identities()[state.config.tun] && run('sysctl', ['-n', op.key]) === '1';
    if (op.kind === 'addr') return read(['-6', 'addr', 'show']).some(l => l.ifname === op.name && l.addr_info.some(a => a.local === op.address && a.prefixlen === 126));
    if (op.kind === 'rule') return read(['-6', 'rule', 'show']).some(isVpnIpv6Rule);
    return routeRows().some(r => op.route === 'unreachable' ? r.type === 'unreachable' && r.dst === 'default' : r.dst === '2000::/3' && r.dev === state.config.tun);
  }
  const remove = op => { if (present(op)) run(op.file, op.remove); assert.ok(!present(op) || op.kind === 'sysctl' && state.config.tunForward === '1', 'IPv6 restore read-back failed'); };
  return {
    get state() { return state; }, release, audit() { resetBudget(); return audit(); },
    begin(role, tun, ext = null) {
      resetBudget();
      assert.ok(!state || state.stage === 'released', 'IPv6 recovery required: node scripts/clean-vpn-ipv6-recover.mjs --apply');
      assert.ok(validV6Interface(tun)); assert.ok(ext === null || validV6Interface(ext));
      const links = identities(); assert.ok(links[tun]); if (ext) assert.ok(links[ext]);
      assert.equal(run('sysctl', ['-n', `net/ipv6/conf/${tun}/disable_ipv6`]), '0', 'IPv6 disabled on TUN');
      const addrs = read(['-6', 'addr', 'show']);
      assert.ok(!addrs.some(l => l.addr_info.some(a => overlapsVpnIpv6(`${a.local}/${a.prefixlen}`))), 'internal VPN IPv6 address collision');
      assert.ok(!read(['-6', 'route', 'show', 'table', 'all']).some(r => overlapsVpnIpv6(r.dst)), 'internal VPN IPv6 route collision');
      if (role === 'client') {
        assert.equal(routeRows().length, 0, 'IPv6 table already used');
        assert.ok(!read(['-6', 'rule', 'show']).some(r => String(r.priority) === IPV6_PRIORITY || String(r.table) === IPV6_TABLE), 'IPv6 policy already used');
      }
      let forward = false;
      if (role === 'exit' && ext) {
        let route = [];
        try { route = read(['-6', 'route', 'get', '2606:4700:4700::1111']); } catch (e) { if (e.status !== 2) throw e; }
        const global = addrs.find(l => l.ifname === ext)?.addr_info.some(a => a.scope === 'global' && /^[23]/.test(a.local) && !a.tentative && !a.dadfailed);
        forward = !!global && route.length === 1 && route[0].dev === ext && (!route[0].type || route[0].type === 'unicast') &&
          run('sysctl', ['-n', 'net/ipv6/conf/all/forwarding']) === '1' && run('sysctl', ['-n', `net/ipv6/conf/${ext}/forwarding`]) === '1';
      }
      const config = { role, tun, ext, id: randomBytes(12).toString('hex'), forward, tunForward: run('sysctl', ['-n', `net/ipv6/conf/${tun}/forwarding`]) };
      state = { schema: 1, scope: scope(), config, links: Object.fromEntries([tun, ...(ext ? [ext] : [])].map(n => [n, links[n]])),
        backend: backend(), count: 0, dynamic: false, stage: 'installing' }; save();
      for (const [i, op] of ipv6Plan(config).entries()) {
        if (op.kind !== 'sysctl') assert.ok(!present(op), 'IPv6 operation already exists');
        state.count = i + 1; save(); run(op.file, op.args); assert.ok(present(op), `IPv6 install read-back failed: ${op.kind} #${i + 1}`); checkpoint('applied', state);
      }
      state.stage = 'active'; save();
      return role === 'exit' && forward ? 'tunnel' : 'blocked';
    },
    capability(value) {
      resetBudget();
      assert.equal(state.config.role, 'client'); assert.equal(state.stage, 'active'); audit();
      for (const op of ipv6Plan(state.config)) assert.ok(present(op), 'IPv6 owned protection was changed; refusing capability');
      const op = ipv6TunnelRoute(state.config);
      if (value === 'tunnel') { state.dynamic = true; save(); if (!present(op)) run(op.file, op.args); assert.ok(present(op)); }
      else { remove(op); state.dynamic = false; save(); }
      return value === 'tunnel' ? 'tunnel' : 'blocked';
    },
    restore() {
      resetBudget();
      if (!state || state.stage === 'released') return;
      audit(); state.stage = 'restoring'; save();
      if (state.config.role === 'client') { remove(ipv6TunnelRoute(state.config)); state.dynamic = false; save(); }
      const ops = ipv6Plan(state.config);
      while (state.count > 0) { audit(); remove(ops[state.count - 1]); state.count--; save(); checkpoint('removed', state); }
      state.stage = 'released'; save();
    },
  };
}
