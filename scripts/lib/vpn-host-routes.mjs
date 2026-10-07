/** Same-boot host route ownership. Add-only: never replace an existing route.
 * Recovery is explicit, never an automatic release of an egress guard. */
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { isIPv4 } from 'node:net';
import { runTunnelDnsCommand } from './dns-tunnel-command.mjs';
const C = fs.constants, PROTO = 186, METRIC = 42760, LIMIT = 32768;
const scope = () => ({ boot: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(),
  net: fs.readlinkSync('/proc/self/ns/net'), user: fs.readlinkSync('/proc/self/ns/user') });
export const hostRouteStateDirectory = () => `/run/clean-vpn-host-routes-${scope().net.match(/\d+/)[0]}`;
const keys = (v, k) => assert.deepEqual(Object.keys(v).sort(), [...k].sort());
const iface = v => assert.ok(typeof v === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$/.test(v) && v !== 'lo');
const dst = v => { assert.ok(typeof v === 'string' && (['0.0.0.0/1', '128.0.0.0/1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].includes(v)
  || v.endsWith('/32') && isIPv4(v.slice(0, -3)))); return v; };
const normalizeDst = v => isIPv4(v) ? `${v}/32` : v;
export function validateHostRouteState(s) {
  keys(s, ['schema', 'scope', 'tun', 'links', 'routes', 'rp', 'stage', ...(Object.hasOwn(s, 'transition') ? ['transition'] : [])]); assert.equal(s.schema, 1);
  keys(s.scope, ['boot', 'net', 'user']); assert.match(s.scope.boot, /^[a-f0-9-]{36}$/);
  for (const k of ['net', 'user']) assert.match(s.scope[k], new RegExp(`^${k}:\\[\\d+\\]$`));
  iface(s.tun); assert.ok(['active', 'restoring', 'released'].includes(s.stage));
  assert.ok(Array.isArray(s.routes) && s.routes.length <= 64);
  assert.equal(new Set(s.routes.map(r => r.dst)).size, s.routes.length);
  for (const r of s.routes) { keys(r, ['dst', 'dev', 'gateway']); dst(r.dst); iface(r.dev);
    assert.ok(r.gateway === null || isIPv4(r.gateway)); assert.ok(Object.hasOwn(s.links, r.dev)); }
  for (const [name, l] of Object.entries(s.links)) { iface(name); keys(l, ['ifindex', 'address', 'type']);
    assert.ok(Number.isSafeInteger(l.ifindex) && l.ifindex > 0);
    assert.ok(typeof l.address === 'string' && l.address.length <= 64 && typeof l.type === 'string' && l.type.length <= 32); }
  assert.ok(Object.hasOwn(s.links, s.tun)); assert.ok(Object.keys(s.links).length <= 16);
  if (s.transition) {
    keys(s.transition, ['dev', 'from', 'to']); iface(s.transition.dev);
    assert.notEqual(s.transition.dev, s.tun); assert.ok(Object.hasOwn(s.links, s.transition.dev));
    for (const g of [s.transition.from, s.transition.to]) assert.ok(g === null || isIPv4(g));
    assert.notEqual(s.transition.from, s.transition.to); assert.notEqual(s.stage, 'released');
    assert.ok(s.routes.filter(r => r.dev === s.transition.dev).every(r => r.gateway === s.transition.from));
  } else assert.ok(!Object.hasOwn(s, 'transition'));
  assert.ok(s.rp === null || Number.isInteger(s.rp) && s.rp >= 0 && s.rp <= 2);
  if (s.stage === 'released') assert.ok(s.routes.length === 0 && s.rp === null);
  return s;
}
const identity = l => ({ ifindex: l.ifindex, address: l.address ?? '', type: l.link_type });
const strictlyOwned = (row, r) => normalizeDst(row.dst) === r.dst && row.dev === r.dev && (row.gateway ?? null) === r.gateway
  && Number(row.protocol) === PROTO && row.metric === METRIC
  && Object.keys(row).every(k => ['dst', 'dev', 'gateway', 'protocol', 'metric', 'scope', 'flags', 'type', 'table'].includes(k))
  && (!row.type || row.type === 'unicast') && (!row.table || ['main', '254'].includes(String(row.table)))
  && (!row.flags || row.flags.length === 0) && (!row.scope || (r.gateway ? ['global', '0'] : ['link', '253']).includes(String(row.scope)));
const routeArgs = r => [r.dst, ...(r.gateway ? ['via', r.gateway] : []), 'dev', r.dev, 'proto', String(PROTO), 'metric', String(METRIC)];

export function openHostRoutes({ directory = hostRouteStateDirectory(), run: injected, checkpoint = () => {}, allowTunLinkDown = false } = {}) {
  assert.equal(typeof allowTunLinkDown, 'boolean');
  // Alternate directory and executor are internal test hooks, not CLI flags.
  if (!injected) { const p = fs.lstatSync('/run'); assert.ok(p.isDirectory() && !p.isSymbolicLink() && p.uid === 0 && !(p.mode & 0o022)); }
  try { fs.mkdirSync(directory, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  const dfd = fs.openSync(directory, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW), base = `/proc/self/fd/${dfd}`;
  let lock, state = null, closed = false, deadline = Infinity;
  const release = () => { if (closed) return; closed = true; if (lock !== undefined) fs.closeSync(lock); fs.closeSync(dfd); };
  const privateFile = fd => { const s = fs.fstatSync(fd); assert.ok(s.isFile() && s.uid === process.getuid() && s.nlink === 1 && (s.mode & 0o777) === 0o600); return s; };
  const run = (f, a) => { assert.ok(!closed && performance.now() < deadline, 'host route budget exceeded; journal retained');
    return injected ? injected(f, a) : runTunnelDnsCommand(f, a, { lockDescriptors: [lock], timeoutMs: Math.min(8000, deadline - performance.now()) }); };
  try {
    const d = fs.fstatSync(dfd); assert.ok(d.uid === process.getuid() && (d.mode & 0o777) === 0o700);
    lock = fs.openSync(`${base}/lock`, C.O_RDWR | C.O_CREAT | C.O_NOFOLLOW | C.O_NONBLOCK, 0o600); privateFile(lock);
    runTunnelDnsCommand('flock', ['--exclusive', '--nonblock', '3'], { lockDescriptors: [lock] });
    let fd;
    try { fd = fs.openSync(`${base}/journal.json`, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (fd !== undefined) try { const s = privateFile(fd); assert.ok(s.size > 0 && s.size <= LIMIT);
      const b = Buffer.alloc(LIMIT + 1), n = fs.readSync(fd, b); assert.equal(n, s.size);
      state = validateHostRouteState(JSON.parse(b.subarray(0, n).toString()));
    } finally { fs.closeSync(fd); }
  } catch (e) { release(); throw e; }
  const save = () => {
    validateHostRouteState(state); const body = JSON.stringify(state); assert.ok(Buffer.byteLength(body) <= LIMIT);
    const path = `${base}/state-${randomBytes(12).toString('hex')}.tmp`;
    const fd = fs.openSync(path, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, body); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(path, `${base}/journal.json`); fs.fsyncSync(dfd); checkpoint('saved', structuredClone(state));
  };
  const links = () => Object.fromEntries(JSON.parse(run('ip', ['-j', 'link', 'show'])).map(l => [l.ifname, identity(l)]));
  const rows = () => JSON.parse(run('ip', ['-N', '-j', '-4', 'route', 'show', 'table', 'main']));
  const rp = () => { const v = Number(run('sysctl', ['-n', 'net.ipv4.conf.all.rp_filter'])); assert.ok([0, 1, 2].includes(v)); return v; };
  const variants = r => state.transition?.dev === r.dev ? [r, { ...r, gateway: state.transition.to }] : [r];
  // Persistent TUN has no carrier while its direct native service is quiesced.
  // Only this kernel flag on the same journalled TUN identity is accepted;
  // legacy callers and uplink routes retain the original strict audit.
  const owned = (row, r) => strictlyOwned(allowTunLinkDown && r.dev === state?.tun &&
    Array.isArray(row.flags) && row.flags.length === 1 && row.flags[0] === 'linkdown' ? { ...row, flags: [] } : row, r);
  function audit({ requireTun = false } = {}) {
    assert.ok(state && !closed); assert.deepEqual(state.scope, scope(), 'different boot/namespace');
    const now = links(), table = rows();
    if (requireTun) assert.ok(now[state.tun], 'TUN disappeared; recovery required');
    for (const [name, old] of Object.entries(state.links)) {
      if (!now[name]) assert.equal(name, state.tun, 'uplink disappeared; review required');
      else assert.deepEqual(now[name], old, `interface replaced: ${name}`);
    }
    for (const r of state.routes) {
      const matches = table.filter(v => normalizeDst(v.dst) === r.dst);
      assert.ok(matches.length <= 1 && matches.every(v => variants(r).some(candidate => owned(v, candidate))), `foreign route at ${r.dst}; no changes`);
    }
    if (state.rp !== null) assert.ok([state.rp, 2].includes(rp()), 'rp_filter changed by another owner');
    return table;
  }
  return {
    get lockDescriptors() { assert.ok(!closed); return [lock]; },
    get state() { return state; }, release,
    assertAvailable() { assert.ok(!state || state.stage === 'released', 'Host IPv4 recovery required: node scripts/clean-vpn-host-recover.mjs --apply'); },
    audit() { deadline = performance.now() + 120000; return audit(); },
    begin(tun) { this.assertAvailable(); deadline = performance.now() + 120000; iface(tun);
      const current = links(); assert.ok(current[tun]);
      state = { schema: 1, scope: scope(), tun, links: { [tun]: current[tun] }, routes: [], rp: null, stage: 'active' }; save(); },
    add(destination, dev, gateway = null) {
      deadline = performance.now() + 120000; assert.equal(state.stage, 'active'); dst(destination); iface(dev);
      assert.ok(!state.transition, 'unfinished uplink transition');
      assert.ok(gateway === null || isIPv4(gateway));
      const table = audit(), r = { dst: destination, dev, gateway };
      const previous = state.routes.find(v => v.dst === destination);
      if (previous) { assert.deepEqual(previous, r); assert.ok(table.some(v => owned(v, r)), 'owned route disappeared'); return; }
      const existing = table.filter(v => normalizeDst(v.dst) === destination);
      if (existing.length) {
        // Do not erase pre-existing metrics, MTU, protocol or policy. An existing
        // compatible unicast route needs no mutation and is never ours to remove.
        assert.ok(existing.length === 1 && Number(existing[0].protocol) !== PROTO && existing[0].dev === dev && (existing[0].gateway ?? null) === gateway
          && (!existing[0].type || existing[0].type === 'unicast') && !existing[0].nexthops,
        `existing incompatible route at ${destination}; not replacing it`); return;
      }
      const current = links(); assert.ok(current[dev]); state.links[dev] = current[dev];
      state.routes.push(r); save(); run('ip', ['-4', 'route', 'add', ...routeArgs(r)]);
      checkpoint('applied', structuredClone(state)); assert.ok(audit().some(v => owned(v, r)), 'route add read-back failed');
    },
    repairUplink(dev, gateway, serverIp) {
      // DHCP/networkd may remove our uplink routes on carrier loss while TUN
      // split defaults survive. Reconnect must not route the exit into TUN.
      // Only re-add durable, same-boot ownership on the SAME interface/gateway.
      // Never replace/adopt foreign routes or choose a new network silently.
      deadline = performance.now() + 15000;
      assert.ok(!state?.transition, 'unfinished uplink transition');
      assert.equal(state?.stage, 'active'); iface(dev); assert.notEqual(dev, state.tun);
      assert.ok(gateway === null || isIPv4(gateway)); assert.ok(isIPv4(serverIp));
      const target = `${serverIp}/32`, intent = state.routes.find(r => r.dst === target);
      if (intent) assert.ok(intent.dev === dev && intent.gateway === gateway, 'exit route ownership mismatch');
      const auditUplink = () => {
        const table = audit({ requireTun: true });
        const defaults = table.filter(r => ['default', '0.0.0.0/0'].includes(r.dst));
        assert.ok(defaults.length === 1 && defaults[0].dev === dev && (defaults[0].gateway ?? null) === gateway
          && (!defaults[0].type || defaults[0].type === 'unicast') && !defaults[0].nexthops,
        'uplink default absent or changed; reconnect postponed');
        if (!intent) {
          const borrowed = table.filter(r => normalizeDst(r.dst) === target);
          assert.ok(borrowed.length === 1 && borrowed[0].dev === dev && (borrowed[0].gateway ?? null) === gateway
            && Number(borrowed[0].protocol) !== PROTO && (!borrowed[0].type || borrowed[0].type === 'unicast')
            && !borrowed[0].nexthops, 'unowned exit bypass disappeared or changed; manual review required');
        }
        return table;
      };
      let table = auditUplink();
      let repaired = 0;
      for (const r of state.routes.filter(r => r.dev === dev)) {
        assert.equal(r.gateway, gateway, 'uplink route gateway mismatch');
        if (table.some(row => owned(row, r))) continue;
        // The initial snapshot, then the previous write's full read-back, is
        // the pre-add audit. No I/O or callback occurs between that snapshot
        // and the next add; do not fork an identical second audit. Still use
        // add (never replace), and audit after EVERY write/checkpoint.
        run('ip', ['-4', 'route', 'add', ...routeArgs(r)]);
        checkpoint('repaired', structuredClone(state));
        table = auditUplink();
        assert.ok(table.some(row => owned(row, r)), 'route repair read-back failed'); repaired++;
      }
      return repaired;
    },
    repairTunRoutes() {
      deadline = performance.now() + 15000; assert.equal(state?.stage, 'active');
      assert.ok(!state.transition, 'unfinished uplink transition');
      let table = audit({ requireTun: true }), changed = 0;
      for (const r of state.routes.filter(r => r.dev === state.tun)) {
        assert.equal(r.gateway, null);
        if (table.some(v => owned(v, r))) continue;
        run('ip', ['-4', 'route', 'add', ...routeArgs(r)]); changed++;
        checkpoint('tun-repaired', structuredClone(state)); table = audit({ requireTun: true });
        assert.ok(table.some(v => owned(v, r)), 'TUN route repair read-back failed');
      }
      return changed;
    },
    rebindUplink(dev, gateway, serverIp) {
      // Caller must quiesce the engine and retain its independent guard FIRST.
      // Durable old/new intent permits replay after any delete/add/save boundary.
      deadline = performance.now() + 30000;
      assert.equal(state?.stage, 'active'); iface(dev); assert.notEqual(dev, state.tun);
      assert.ok(gateway === null || isIPv4(gateway)); assert.ok(isIPv4(serverIp));
      const intent = state.routes.find(r => r.dst === `${serverIp}/32`);
      assert.ok(intent && intent.dev === dev, 'owned exit bypass required for rebind');
      const from = intent.gateway;
      assert.ok(state.routes.filter(r => r.dev === dev).every(r => r.gateway === from), 'mixed uplink gateways');
      if (state.transition) assert.deepEqual(state.transition, { dev, from, to: gateway }, 'unfinished different uplink transition');
      const read = () => {
        const table = audit({ requireTun: true });
        const defaults = table.filter(r => ['default', '0.0.0.0/0'].includes(r.dst));
        assert.ok(defaults.length === 1 && defaults[0].dev === dev && (defaults[0].gateway ?? null) === gateway &&
          (!defaults[0].type || defaults[0].type === 'unicast') && !defaults[0].nexthops,
        'uplink default absent or changed; rebind postponed');
        return table;
      };
      read();
      if (from === gateway) return this.repairUplink(dev, gateway, serverIp);
      if (!state.transition) { state.transition = { dev, from, to: gateway }; save(); }
      let changed = 0;
      for (const r of state.routes.filter(r => r.dev === dev)) {
        let table = read(); const next = { ...r, gateway };
        if (table.some(v => owned(v, r))) {
          run('ip', ['-4', 'route', 'del', ...routeArgs(r)]); changed++;
          checkpoint('rebind-removed', structuredClone(state)); table = read();
          assert.ok(!table.some(v => owned(v, r)), 'old uplink route still present');
        }
        if (!table.some(v => owned(v, next))) {
          run('ip', ['-4', 'route', 'add', ...routeArgs(next)]); changed++;
          checkpoint('rebind-added', structuredClone(state)); table = read();
        }
        assert.ok(table.some(v => owned(v, next)), 'new uplink route read-back failed');
      }
      read();
      for (const r of state.routes) if (r.dev === dev) r.gateway = gateway;
      delete state.transition; save();
      return changed;
    },
    relaxRpFilter() {
      deadline = performance.now() + 120000; assert.equal(state.stage, 'active'); audit();
      assert.equal(state.rp, null); const before = rp(); if (before === 2) return;
      state.rp = before; save(); run('sysctl', ['-w', 'net.ipv4.conf.all.rp_filter=2']);
      checkpoint('rp-applied', structuredClone(state)); assert.equal(rp(), 2);
    },
    restore() {
      deadline = performance.now() + 120000; if (!state || state.stage === 'released') return;
      audit(); state.stage = 'restoring'; save();
      while (state.routes.length) {
        const table = audit(), r = state.routes.at(-1);
        const actual = variants(r).find(candidate => table.some(v => owned(v, candidate)));
        if (actual) run('ip', ['-4', 'route', 'del', ...routeArgs(actual)]);
        checkpoint('removed', structuredClone(state)); assert.ok(!audit().some(v => variants(r).some(candidate => owned(v, candidate))), 'route removal read-back failed');
        state.routes.pop(); save();
      }
      audit(); if (state.rp !== null && rp() !== state.rp) run('sysctl', ['-w', `net.ipv4.conf.all.rp_filter=${state.rp}`]);
      if (state.rp !== null) assert.equal(rp(), state.rp);
      state.rp = null; delete state.transition; state.stage = 'released'; save();
    },
  };
}
