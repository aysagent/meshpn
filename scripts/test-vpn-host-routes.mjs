import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, chmodSync, renameSync, symlinkSync, linkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { openHostRoutes, validateHostRouteState } from './lib/vpn-host-routes.mjs';
import { recoverHost } from './clean-vpn-host-recover.mjs';
function fixture(t) {
  const directory = mkdtempSync(`${tmpdir()}/host-routes-test-`);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const f = { directory, routes: [], rp: 0, changes: 0,
    links: [{ ifname: 'tun0', ifindex: 8, link_type: 'none' }, { ifname: 'eth0', ifindex: 2, address: '00:01', link_type: 'ether' }] };
  f.run = (file, args) => {
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
