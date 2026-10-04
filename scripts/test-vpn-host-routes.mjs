import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, chmodSync, renameSync, symlinkSync, linkSync, existsSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { tmpdir } from 'node:os';
import { openHostRoutes, validateHostRouteState } from './lib/vpn-host-routes.mjs';
import { recoverHost } from './clean-vpn-host-recover.mjs';

// Execute the real CLI route setup with fake kernel IO and a real durable journal.
const clientSource = readFileSync(new URL('./clean-vpn.js', import.meta.url), 'utf8');
const setupStart = clientSource.indexOf('async function setupClientRoutesAsync(');
const setupEnd = clientSource.indexOf('\n/** IPv4 default через TUN', setupStart);
assert.ok(setupStart > 0 && setupEnd > setupStart);
function routeSetup(f, defaultRoute) {
  return runInNewContext(`${clientSource.slice(setupStart, setupEnd)}\nsetupClientRoutesAsync`, {
    getDefaultRouteLinux: defaultRoute, resolveHostToIpv4: async () => '198.51.100.2',
    captureServerRoutes: () => [], getSysctlNum: () => f.rp,
    console: { log() {} },
  });
}
function fixture(t) {
  const directory = mkdtempSync(`${tmpdir()}/host-routes-test-`);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const f = { directory, routes: [], rp: 0, changes: 0, calls: [],
    links: [{ ifname: 'tun0', ifindex: 8, link_type: 'none' }, { ifname: 'eth0', ifindex: 2, address: '00:01', link_type: 'ether' }] };
  f.run = (file, args) => {
    f.calls.push([file, ...args]);
    if (file === 'sysctl') {
      if (args[0] === '-n') return String(f.rp);
      f.changes++; f.rp = Number(args[1].split('=')[1]); return '';
    }
    if (args.includes('link')) return JSON.stringify(f.links);
    if (args.includes('show')) return JSON.stringify(f.routes);
    const [, , action, dst, ...opts] = args;
    const get = k => opts.includes(k) ? opts[opts.indexOf(k) + 1] : undefined;
    f.changes++;
    if (action === 'add') f.routes.push({ dst: dst.replace('/32', ''), dev: get('dev'), ...(get('via') ? { gateway: get('via') } : {}),
      protocol: get('proto'), metric: Number(get('metric')), scope: get('via') ? '0' : '253', flags: [] });
    else { assert.equal(action, 'del'); f.routes = f.routes.filter(r => r.dst !== dst.replace('/32', '')); }
    return '';
  };
  f.open = checkpoint => openHostRoutes({ directory, run: f.run, checkpoint });
  return f;
}
for (const previous of ['absent', 'released']) test(`missing default route preserves ${previous} journal and permits retry`, async t => {
  const f = fixture(t);
  if (previous === 'released') { const r = f.open(); r.begin('tun0'); r.restore(); r.release(); }
  const path = `${f.directory}/journal.json`, contents = () => existsSync(path) ? readFileSync(path, 'utf8') : null;
  const before = contents();
  let available = false;
  const setup = routeSetup(f, () => available ? { gw: '192.0.2.1', dev: 'eth0' } : null);
  for (let attempt = 0; attempt < 3; attempt++) {
    const r = f.open();
    try { r.assertAvailable(); await assert.rejects(setup('tun0', '198.51.100.2', false, { hostRoutes: r }), /Не найден default route/); }
    finally { r.release(); }
    assert.equal(contents(), before); assert.equal(f.changes, 0);
  }
  available = true;
  const r = f.open();
  try {
    r.assertAvailable(); await setup('tun0', '198.51.100.2', false, { hostRoutes: r });
    assert.equal(r.state.stage, 'active'); assert.equal(f.routes.length, 1); assert.equal(f.rp, 2);
    r.restore(); assert.equal(r.state.stage, 'released'); assert.equal(f.routes.length, 0); assert.equal(f.rp, 0);
  } finally { r.release(); }
});
test('route lookup error publishes no journal; ingress does not need a host default', async t => {
  const f = fixture(t), r = f.open();
  try {
    const setup = routeSetup(f, () => { throw Error('route lookup failed'); });
    await assert.rejects(setup('tun0', '198.51.100.2', false, { hostRoutes: r }), /route lookup failed/);
    assert.equal(r.state, null); assert.equal(f.changes, 0);
    await setup('tun0', '198.51.100.2', false, { fromTun: 'ingress0' });
  } finally { r.release(); }
});
test('CLI does not begin ownership before route setup; stale journal gate remains before TUN startup', () => {
  const impl = clientSource.slice(clientSource.indexOf('async function runClientImpl('));
  assert.doesNotMatch(impl, /hostRoutes\?\.begin\(ifname\)/);
  const entry = clientSource.slice(clientSource.indexOf('async function runClient(options)'), clientSource.indexOf('async function runClientImpl('));
  assert.ok(entry.indexOf('hostRoutes?.assertAvailable()') < entry.indexOf('await runClientImpl('));
});
test('durable add-only routes and rp_filter restore exactly; repeated recovery is harmless', t => {
  const f = fixture(t), r = f.open(); r.begin('tun0');
  r.add('198.51.100.2/32', 'eth0', '192.0.2.1'); r.add('0.0.0.0/1', 'tun0'); r.relaxRpFilter();
  assert.equal(f.rp, 2); assert.equal(f.routes.length, 2); r.release();
  assert.equal(recoverHost([], f.open).stage, 'active');
  const reopened = f.open(); assert.throws(() => reopened.assertAvailable(), /recovery required/); reopened.release();
  assert.equal(recoverHost(['--apply'], f.open).stage, 'released');
  assert.deepEqual(f.routes, []); assert.equal(f.rp, 0);
  const changes = f.changes; recoverHost(['--apply'], f.open); assert.equal(f.changes, changes);
});
for (const cut of ['saved', 'applied', 'removed', 'rp-applied']) test(`recover durable cut at ${cut}`, t => {
  const f = fixture(t); let armed = false;
  const r = f.open(label => { if (armed && label === cut) throw Error('cut'); }); r.begin('tun0');
  if (cut === 'removed') { r.add('198.51.100.2/32', 'eth0'); armed = true; assert.throws(() => r.restore(), /cut/); }
  else if (cut === 'rp-applied') { armed = true; assert.throws(() => r.relaxRpFilter(), /cut/); }
  else { armed = true; assert.throws(() => r.add('198.51.100.2/32', 'eth0'), /cut/); }
  r.release(); recoverHost(['--apply'], f.open); assert.deepEqual(f.routes, []); assert.equal(f.rp, 0);
});
test('pre-existing compatible routes are preserved, incompatible routes refused', t => {
  const f = fixture(t); f.routes = [{ dst: '10.0.0.0/8', dev: 'eth0', gateway: '192.0.2.1', protocol: 'static', metric: 77, metrics: [{ mtu: 1400 }] }];
  const before = structuredClone(f.routes), r = f.open(); r.begin('tun0');
  r.add('10.0.0.0/8', 'eth0', '192.0.2.1');
  assert.throws(() => r.add('10.0.0.0/8', 'tun0'), /incompatible/);
  r.restore(); r.release(); assert.deepEqual(f.routes, before); assert.equal(f.changes, 0);
});
for (const corrupt of ['route', 'link', 'rp', 'boot']) test(`foreign ${corrupt} refuses recovery before mutation`, t => {
  const f = fixture(t), r = f.open(); r.begin('tun0'); r.add('198.51.100.2/32', 'eth0'); r.relaxRpFilter(); r.release();
  if (corrupt === 'route') f.routes[0].metric++;
  if (corrupt === 'link') f.links[1].ifindex++;
  if (corrupt === 'rp') f.rp = 1;
  if (corrupt === 'boot') { const path = `${f.directory}/journal.json`, s = JSON.parse(readFileSync(path));
    s.scope.boot = '00000000-0000-0000-0000-000000000000'; writeFileSync(path, JSON.stringify(s)); }
  const changes = f.changes; assert.throws(() => recoverHost(['--apply'], f.open)); assert.equal(f.changes, changes);
});
test('dead TUN routes may disappear but a replacement TUN is not adopted', t => {
  const f = fixture(t), r = f.open(); r.begin('tun0'); r.add('0.0.0.0/1', 'tun0'); r.relaxRpFilter(); r.release();
  f.routes = []; f.links[0].ifindex++;
  assert.throws(() => recoverHost(['--apply'], f.open), /interface replaced/);
  f.links.shift(); recoverHost(['--apply'], f.open); assert.equal(f.rp, 0);
});
test('strict data schema, bounded prefixes and real lifetime lock', t => {
  const f = fixture(t), r = f.open(); r.begin('tun0');
  assert.throws(() => f.open()); assert.throws(() => r.add('default', 'eth0'));
  const s = structuredClone(r.state); s.command = ['rm']; assert.throws(() => validateHostRouteState(s));
  r.restore(); r.release(); assert.throws(() => recoverHost(['--anything'], f.open));
});
for (const unsafe of ['symlink', 'hardlink', 'permissions', 'oversized', 'malformed'])
  test(`unsafe ${unsafe} journal is refused without network changes`, t => {
    const f = fixture(t), r = f.open(); r.begin('tun0'); r.release();
    const path = `${f.directory}/journal.json`;
    if (unsafe === 'symlink') { renameSync(path, `${path}.original`); symlinkSync(`${path}.original`, path); }
    if (unsafe === 'hardlink') linkSync(path, `${path}.linked`);
    if (unsafe === 'permissions') chmodSync(path, 0o644);
    if (unsafe === 'oversized') writeFileSync(path, 'x'.repeat(32769));
    if (unsafe === 'malformed') writeFileSync(path, '{}');
    assert.throws(() => recoverHost(['--apply'], f.open)); assert.equal(f.changes, 0);
  });
test('unrecorded protocol-186 route is not adopted or removed', t => {
  const f = fixture(t); f.routes = [{ dst: '198.51.100.2', dev: 'eth0', protocol: '186', metric: 42760 }];
  const r = f.open(); r.begin('tun0');
  assert.throws(() => r.add('198.51.100.2/32', 'eth0'), /incompatible/);
  r.restore(); r.release(); assert.equal(f.routes.length, 1); assert.equal(f.changes, 0);
});

test('DHCP route loss is repaired before reconnect without replacing routes or changing the journal', t => {
  const f = fixture(t), r = f.open(); r.begin('tun0');
  r.add('198.51.100.2/32', 'eth0', '192.0.2.1'); r.add('192.168.0.0/16', 'eth0', '192.0.2.1');
  r.add('0.0.0.0/1', 'tun0');
  const defaults = { dst: 'default', dev: 'eth0', gateway: '192.0.2.1', protocol: 'dhcp', prefsrc: '192.0.2.7' };
  f.routes.push(defaults);
  const saved = readFileSync(`${f.directory}/journal.json`, 'utf8');
  f.routes = f.routes.filter(row => row.dev !== 'eth0' || row.dst === 'default');
  assert.equal(r.repairUplink('eth0', '192.0.2.1', '198.51.100.2'), 2);
  assert.equal(r.repairUplink('eth0', '192.0.2.1', '198.51.100.2'), 0);
  assert.equal(readFileSync(`${f.directory}/journal.json`, 'utf8'), saved);
  r.restore(); r.release(); assert.deepEqual(f.routes, [defaults]);
});
test('four-route repair uses one initial audit and one full read-back per add', t => {
  const f = fixture(t), r = f.open(); r.begin('tun0');
  for (const dst of ['198.51.100.2/32', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']) r.add(dst, 'eth0', '192.0.2.1');
  r.relaxRpFilter();
  f.routes = [{ dst: 'default', dev: 'eth0', gateway: '192.0.2.1' }]; f.calls.length = 0;
  try {
    assert.equal(r.repairUplink('eth0', '192.0.2.1', '198.51.100.2'), 4);
    assert.equal(f.calls.length, 19); // 5 * (links, routes, rp_filter) + 4 add.
    assert.equal(f.calls.filter(c => c.includes('replace')).length, 0);
  } finally { r.release(); }
});
for (const change of ['foreign-route', 'default', 'tun', 'rp-filter'])
test('repair stops before a second write after checkpoint changes ' + change, t => {
  const f = fixture(t);
  const r = f.open(stage => {
    if (stage !== 'repaired') return;
    if (change === 'foreign-route') f.routes.push({ dst: '192.168.0.0/16', dev: 'eth0', gateway: '192.0.2.254', protocol: 'static' });
    if (change === 'default') f.routes[0].gateway = '192.0.2.254';
    if (change === 'tun') f.links.shift();
    if (change === 'rp-filter') f.rp = 1;
  });
  r.begin('tun0'); r.add('198.51.100.2/32', 'eth0', '192.0.2.1'); r.add('192.168.0.0/16', 'eth0', '192.0.2.1'); r.relaxRpFilter();
  f.routes = [{ dst: 'default', dev: 'eth0', gateway: '192.0.2.1' }]; const before = f.changes;
  try { assert.throws(() => r.repairUplink('eth0', '192.0.2.1', '198.51.100.2')); assert.equal(f.changes, before + 1); }
  finally { r.release(); }
});
for (const fault of ['no-default', 'new-gateway', 'new-interface', 'foreign-exit', 'foreign-private', 'missing-tun', 'multiple-defaults'])
  test(`uplink repair refuses ${fault} before writes`, t => {
    const f = fixture(t), r = f.open(); r.begin('tun0');
    r.add('198.51.100.2/32', 'eth0', '192.0.2.1'); r.add('192.168.0.0/16', 'eth0', '192.0.2.1');
    f.routes = [{ dst: 'default', dev: 'eth0', gateway: '192.0.2.1' }];
    if (fault === 'no-default') f.routes = [];
    if (fault === 'new-gateway') f.routes[0].gateway = '192.0.2.254';
    if (fault === 'new-interface') f.links[1].ifindex++;
    if (fault === 'foreign-exit') f.routes.push({ dst: '198.51.100.2', dev: 'tun0', protocol: 'static' });
    if (fault === 'foreign-private') f.routes.push({ dst: '192.168.0.0/16', dev: 'eth0', gateway: '192.0.2.1', protocol: 'static' });
    if (fault === 'missing-tun') f.links.shift();
    if (fault === 'multiple-defaults') f.routes.push({ ...f.routes[0], metric: 10 });
    const changes = f.changes;
    try { assert.throws(() => r.repairUplink('eth0', '192.0.2.1', '198.51.100.2')); assert.equal(f.changes, changes); }
    finally { r.release(); }
  });
test('borrowed exit bypass is not recreated after loss', t => {
  const f = fixture(t), r = f.open();
  f.routes.push({ dst: '198.51.100.2', dev: 'eth0', gateway: '192.0.2.1', protocol: 'static' });
  r.begin('tun0'); r.add('198.51.100.2/32', 'eth0', '192.0.2.1');
  f.routes.push({ dst: 'default', dev: 'eth0', gateway: '192.0.2.1' });
  assert.equal(r.repairUplink('eth0', '192.0.2.1', '198.51.100.2'), 0);
  f.routes.shift();
  try { assert.throws(() => r.repairUplink('eth0', '192.0.2.1', '198.51.100.2'), /unowned exit bypass/); assert.equal(f.changes, 0); }
  finally { r.release(); }
});
test('native TLS connector repairs bypass before opening the replacement socket', () => {
  const start = clientSource.indexOf('const repaired = routeCtx.hostRoutes.repairUplink(');
  assert.ok(start > 0);
  assert.match(clientSource.slice(start, start + 700), /repairUplink[\s\S]*await connectTlsVpn\(\{ \.\.\.tlsConnectOpts/);
});
test('every TLS reconnect audits routes; failed audit never opens a TLS socket', async () => {
  const marker = clientSource.indexOf('const repaired = routeCtx.hostRoutes.repairUplink(');
  const start = clientSource.lastIndexOf('async () => {', marker);
  const end = clientSource.indexOf('\n      },', marker) + '\n      }'.length;
  assert.ok(start > 0 && end > start);
  const events = [], routeCtx = { stopping: false, serverIp: '198.51.100.2', dev: 'eth0', gw: '192.0.2.1',
    hostRoutes: { repairUplink(...args) { events.push(['repair', ...args]); if (fail) throw Error('no uplink'); return 1; } } };
  let fail = false;
  const watch = { available: true, generation: 0 };
  const connect = runInNewContext(`let tlsVpnSocket, tlsAttempt; (${clientSource.slice(start, end)})`, {
    AbortController,
    routeCtx, uplinkWatch: watch, splitDefault: true, ipv6Runtime: null, tlsConnectOpts: {}, console: { log() {} },
    connectTlsVpn: async () => { events.push(['connect']); return {}; },
  });
  await connect(); await connect();
  assert.deepEqual(events.map(e => e[0]), ['repair', 'connect', 'repair', 'connect']);
  watch.available = false;
  await assert.rejects(connect(), /uplink not ready/); assert.equal(events.length, 4);
  watch.available = true; watch.generation++;
  await connect(); assert.deepEqual(events.slice(-2).map(e => e[0]), ['repair', 'connect']);
  fail = true;
  await assert.rejects(connect(), /no uplink/);
  assert.equal(events.at(-1)[0], 'repair');
  const n = events.length; routeCtx.stopping = true;
  await assert.rejects(connect(), /client stopping/); assert.equal(events.length, n);
});
test('TLS result from an obsolete uplink generation is destroyed before adoption', async () => {
  const marker = clientSource.indexOf('const repaired = routeCtx.hostRoutes.repairUplink(');
  const start = clientSource.lastIndexOf('async () => {', marker);
  const end = clientSource.indexOf('\n      },', marker) + '\n      }'.length;
  const watch = { generation: 0 }; let destroyed = false;
  const connect = runInNewContext(`let tlsVpnSocket, tlsAttempt; (${clientSource.slice(start, end)})`, {
    AbortController,
    routeCtx: { stopping: false }, uplinkWatch: watch, splitDefault: true, ipv6Runtime: null,
    tlsConnectOpts: {}, console: { log() {} }, connectTlsVpn: async () => {
      watch.generation++; return { destroy() { destroyed = true; } };
    },
  });
  await assert.rejects(connect(), /uplink changed/); assert.equal(destroyed, true);
});
test('uplink cancellation reaches the pending connector and the next attempt gets a fresh signal', async () => {
  const marker = clientSource.indexOf('const repaired = routeCtx.hostRoutes.repairUplink(');
  const start = clientSource.lastIndexOf('async () => {', marker);
  const end = clientSource.indexOf('\n      },', marker) + '\n      }'.length;
  const signals = [], context = {
    AbortController, routeCtx: { stopping: false, hostRoutes: { repairUplink() { return 0; } } },
    uplinkWatch: { generation: 0 }, splitDefault: true, ipv6Runtime: null, tlsConnectOpts: {}, console: { log() {} },
    connectTlsVpn: opts => {
      assert.equal(opts.fastRecovery, true); signals.push(opts.signal);
      if (signals.length > 1) return Promise.resolve({});
      return new Promise((resolve, reject) => opts.signal.addEventListener('abort', () => reject(Error('cancelled')), { once: true }));
    },
  };
  const api = runInNewContext(`let tlsVpnSocket, tlsAttempt;
    ({connect: (${clientSource.slice(start, end)}), abort: () => tlsAttempt.abort(), pending: () => tlsAttempt})`, context);
  const failed = assert.rejects(api.connect(), /cancelled/);
  api.abort(); await failed; assert.equal(api.pending(), null);
  await api.connect(); assert.equal(signals[0].aborted, true); assert.equal(signals[1].aborted, false);
  assert.notEqual(signals[0], signals[1]); assert.equal(api.pending(), null);
});
