import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { openHostRoutes } from './lib/vpn-host-routes.mjs';
import { nativeRouteCoordinator, validateNativeRouteConfig } from './lib/native-route-service.mjs';
import { nativeRouteServiceUnit } from './lib/native-route-unit.mjs';
const config = { version: 1, tun: 'tun0', uplink: 'wlan0', exit_ip: '198.51.100.2',
  engine_unit: 'native-client.service', guard_unit: 'guard.service', route_unit: 'native-routes.service' };
function fixture(t) {
  const directory = fs.mkdtempSync('/tmp/native-routes-'); t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const f = { table: [{ dst: 'default', dev: 'wlan0', gateway: '192.0.2.1' }], events: [], active: false, guard: true, lower: true,
    address: '192.0.2.2', index: 2, rules: [255, 254, 253].map((table, i) => ({ priority: [0, 32766, 32767][i], src: 'all', table: String(table) })) };
  f.run = (file, args) => {
    if (file === 'systemctl') {
      if (args.includes('stop')) { f.events.push('stop'); if (!f.stuck) f.active = false; f.onStop?.(); return ''; }
      if (args.includes('start')) { f.events.push('start'); f.active = true; return ''; }
      const key = args[args.indexOf('-p') + 1];
      if (key === 'BindsTo') return f.noBinds ? '' : 'guard.service native-routes.service';
      if (key === 'MainPID') return f.active ? '100' : '0';
      if (args.includes(config.route_unit)) return f.stopping ? 'deactivating' : 'active';
      return args.includes('guard.service') ? f.guard ? 'active' : 'failed' : f.active ? 'active' : 'inactive';
    }
    if (args.includes('rule')) return JSON.stringify(f.rules);
    if (args.includes('addr')) return JSON.stringify([{ ifindex: f.index, flags: f.lower ? ['UP', 'LOWER_UP'] : [],
      addr_info: [{ family: 'inet', scope: 'global', local: f.address, prefixlen: 24 }] }]);
    if (args.includes('link')) return JSON.stringify([{ ifname: 'tun0', ifindex: 8, link_type: 'none' },
      { ifname: 'wlan0', ifindex: f.index, link_type: 'ether', address: '00:01' }]);
    if (args.includes('show')) return JSON.stringify(f.table);
    const [, , action, dst, ...opts] = args;
    f.events.push(action); assert.equal(f.active, false, 'route mutation before quiescence');
    const get = k => opts.includes(k) ? opts[opts.indexOf(k) + 1] : undefined;
    if (action === 'add') f.table.push({ dst, dev: get('dev'), gateway: get('via'), protocol: '186', metric: 42760 });
    else { assert.equal(action, 'del'); f.table = f.table.filter(r => r.dst !== dst); }
    f.onWrite?.();
    return '';
  };
  f.routes = openHostRoutes({ directory, run: f.run }); t.after(() => f.routes.release());
  f.coordinator = nativeRouteCoordinator(config, f.routes, f.run);
  return f;
}
test('native service routes: quiesce before initial install, address/gateway change and missing route repair', t => {
  const f = fixture(t); assert.equal(f.coordinator.tick().state, 'ready');
  assert.deepEqual(f.events, ['stop', 'add', 'add', 'add', 'start']); f.events.length = 0;
  assert.equal(f.coordinator.tick().changed, false); assert.deepEqual(f.events, []);
  f.table[0].gateway = '192.0.2.254'; f.address = '192.0.2.99';
  assert.equal(f.coordinator.tick().state, 'ready'); assert.deepEqual(f.events, ['stop', 'del', 'add', 'start']);
  f.events.length = 0; f.table = f.table.filter(r => r.dst !== '0.0.0.0/1');
  assert.equal(f.coordinator.tick().state, 'ready'); assert.deepEqual(f.events, ['stop', 'add', 'start']);
  f.events.length = 0; f.address = '192.0.2.100';
  assert.equal(f.coordinator.tick().state, 'ready'); assert.deepEqual(f.events, ['stop', 'start']);
  const saved = structuredClone(f.table); f.coordinator.close(); assert.deepEqual(f.table, saved); assert.equal(f.active, false);
});
for (const fault of ['default', 'multiple', 'policy', 'identity', 'foreign', 'guard', 'carrier', 'bindings', 'coordinator-stopping'])
test('native route coordinator stays quiesced on ' + fault, t => {
  const f = fixture(t); assert.equal(f.coordinator.tick().state, 'ready'); f.events.length = 0;
  if (fault === 'default') f.table.shift();
  if (fault === 'multiple') f.table.push({ ...f.table[0], metric: 99 });
  if (fault === 'policy') f.rules.push({ priority: 20, src: 'all', table: '10' });
  if (fault === 'identity') f.index++;
  if (fault === 'foreign') f.table[1].protocol = 'static';
  if (fault === 'guard') f.guard = false;
  if (fault === 'carrier') f.lower = false;
  if (fault === 'bindings') f.noBinds = true;
  if (fault === 'coordinator-stopping') f.stopping = true;
  assert.equal(f.coordinator.tick().state, 'waiting'); assert.deepEqual(f.events, ['stop']); assert.equal(f.active, false);
});
test('native route coordinator never mutates if engine cannot be quiesced', t => {
  const f = fixture(t); f.active = true; f.stuck = true;
  assert.throws(() => f.coordinator.tick(), /not_quiesced/); assert.deepEqual(f.events, ['stop', 'stop']);
  assert.equal(f.routes.state, null);
});
test('native route coordinator refuses a changing lease before route mutation', t => {
  const f = fixture(t); f.onStop = () => { f.address = '192.0.2.33'; };
  assert.equal(f.coordinator.tick().state, 'waiting'); assert.equal(f.routes.state, null);
  assert.deepEqual(f.events, ['stop', 'stop']);
});
test('native route coordinator never starts on stale post-mutation lease evidence', t => {
  const f = fixture(t); f.onWrite = () => { f.address = '192.0.2.33'; };
  assert.equal(f.coordinator.tick().state, 'waiting'); assert.equal(f.active, false);
  assert.equal(f.events.includes('start'), false); assert.equal(f.routes.state.stage, 'active');
  f.onWrite = undefined; assert.equal(f.coordinator.tick().state, 'ready');
});
test('native route coordinator refuses to adopt a compatible foreign exit bypass', t => {
  const f = fixture(t); const foreign = { dst: config.exit_ip + '/32', dev: config.uplink, gateway: '192.0.2.1', protocol: 'static', metric: 77 };
  f.table.push(foreign);
  assert.equal(f.coordinator.tick().state, 'waiting'); assert.deepEqual(f.events, ['stop', 'stop']);
  assert.ok(f.table.includes(foreign)); assert.equal(f.active, false);
});
test('route fault fixture refuses the development host and signals owned DHCP processes directly', () => {
  assert.throws(() => execFileSync('/bin/sh', ['scripts/lib/native-route-vm.sh'], { stdio: 'pipe', timeout: 5000 }));
  const source = fs.readFileSync('scripts/lib/native-route-vm.sh', 'utf8');
  assert.doesNotMatch(source, /^\s*ip netns exec .*&$/m);
  assert.match(source, /\/usr\/bin\/ip netns exec nc2 .*udhcpc/);
});
test('native route config and unit reject executable input; independent route lifetime', () => {
  for (const patch of [{ uplink: 'lo' }, { command: 'bad' }, { engine_unit: 'x;stop.service' }, { route_unit: config.engine_unit }])
    assert.throws(() => validateNativeRouteConfig({ ...config, ...patch }));
  const unit = nativeRouteServiceUnit({ config: '/run/profile.json', script: '/opt/routes.mjs', profile: config, provisionUnit: 'provision.service' });
  assert.match(unit, /Type=simple/); assert.match(unit, /BindsTo=provision.service guard.service/);
  assert.doesNotMatch(unit, /ExecStop=|Restart=always/); assert.match(unit, /RestrictAddressFamilies=AF_UNIX AF_NETLINK/);
  assert.throws(() => nativeRouteServiceUnit({ config: '/bad %n', script: '/opt/routes.mjs', profile: config, provisionUnit: 'provision.service' }));
});
