// Metadata/control only. No packet sockets, payload streams or legacy engine.
import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';
export function validateNativeRouteConfig(c) {
  assert.deepEqual(Object.keys(c).sort(), ['version', 'tun', 'uplink', 'exit_ip', 'engine_unit', 'guard_unit', 'route_unit'].sort());
  assert.equal(c.version, 1); assert.ok(isIPv4(c.exit_ip));
  for (const k of ['tun', 'uplink']) assert.match(c[k], /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,14}$/);
  assert.notEqual(c.tun, c.uplink); assert.ok(![c.tun, c.uplink].includes('lo'));
  for (const k of ['engine_unit', 'guard_unit', 'route_unit']) assert.match(c[k], /^[a-z][a-z0-9-]{0,63}\.service$/);
  assert.equal(new Set([c.engine_unit, c.guard_unit, c.route_unit]).size, 3);
  return c;
}
export function nativeRouteCoordinator(config, routes, run) {
  const c = validateNativeRouteConfig(config);
  const plan = [{ dst: c.exit_ip + '/32', dev: c.uplink },
    { dst: '0.0.0.0/1', dev: c.tun }, { dst: '128.0.0.0/1', dev: c.tun }];
  const command = (file, args) => run(file, args).trim();
  const ctl = (...args) => command('systemctl', ['--no-pager', ...args]);
  const prop = (unit, key) => ctl('show', unit, '-p', key, '--value');
  let previous = null, closed = false;
  const stop = () => {
    ctl('stop', c.engine_unit);
    assert.equal(prop(c.engine_unit, 'MainPID'), '0', 'native_engine_not_quiesced');
    assert.ok(['inactive', 'failed'].includes(prop(c.engine_unit, 'ActiveState')), 'native_engine_not_quiesced');
    previous = null;
  };
  const protection = () => {
    assert.equal(prop(c.route_unit, 'ActiveState'), 'active', 'native_route_service_not_active');
    assert.equal(prop(c.guard_unit, 'ActiveState'), 'active', 'native_guard_not_active');
    const binds = prop(c.engine_unit, 'BindsTo').split(/\s+/);
    assert.ok(binds.includes(c.route_unit) && binds.includes(c.guard_unit), 'native_missing_lifecycle_dependency');
  };
  const snapshot = () => {
    const rules = JSON.parse(command('ip', ['-N', '-j', '-4', 'rule', 'show']));
    assert.deepEqual(rules, [{ priority: 0, src: 'all', table: '255' },
      { priority: 32766, src: 'all', table: '254' }, { priority: 32767, src: 'all', table: '253' }], 'native_custom_policy_requires_review');
    const addresses = JSON.parse(command('ip', ['-j', '-4', 'addr', 'show', 'dev', c.uplink]));
    assert.equal(addresses.length, 1); const link = addresses[0];
    assert.ok(link.flags.includes('UP') && link.flags.includes('LOWER_UP'), 'native_uplink_down');
    const ips = link.addr_info.filter(a => a.family === 'inet' && a.scope === 'global');
    assert.equal(ips.length, 1, 'native_single_uplink_address_required');
    assert.ok(isIPv4(ips[0].local));
    const table = JSON.parse(command('ip', ['-N', '-j', '-4', 'route', 'show', 'table', 'main']));
    const defaults = table.filter(r => ['default', '0.0.0.0/0'].includes(r.dst));
    assert.equal(defaults.length, 1, 'native_single_default_required'); const d = defaults[0];
    assert.equal(d.dev, c.uplink); assert.ok(!d.nexthops && (!d.type || d.type === 'unicast'));
    assert.ok(d.gateway === undefined || isIPv4(d.gateway));
    return { stamp: JSON.stringify([link.ifindex, ips[0].local, ips[0].prefixlen, d.gateway ?? null, d.metric ?? null]), gateway: d.gateway ?? null, table };
  };
  const journal = () => {
    const s = routes.state; if (!s || s.stage === 'released') return;
    assert.equal(s.stage, 'active'); assert.equal(s.tun, c.tun); assert.equal(s.rp, null);
    assert.ok(Object.keys(s.links).every(dev => [c.tun, c.uplink].includes(dev)));
    assert.ok(s.routes.every(r => plan.some(p => p.dst === r.dst && p.dev === r.dev) && (r.dev !== c.tun || r.gateway === null)), 'native_route_profile_mismatch');
    routes.audit();
  };
  const complete = snap => routes.state?.stage === 'active' && !routes.state.transition && routes.state.routes.length === plan.length &&
    routes.state.routes.every(r => snap.table.some(row => (row.dst === r.dst || row.dst + '/32' === r.dst) && row.dev === r.dev &&
      (row.gateway ?? null) === r.gateway && Number(row.protocol) === 186 && row.metric === 42760));
  return {
    tick() {
      assert.ok(!closed);
      let stage = 'protection';
      try {
        protection(); stage = 'ownership'; journal(); stage = 'uplink'; let snap = snapshot();
        if (previous === snap.stamp && complete(snap)) return { state: 'ready', changed: false };
        stage = 'quiesce'; stop(); protection(); const afterStop = snapshot();
        assert.equal(afterStop.stamp, snap.stamp, 'native_uplink_changed_during_stop'); snap = afterStop;
        stage = 'rebind';
        if (!routes.state || routes.state.stage === 'released') routes.begin(c.tun);
        if (routes.state.routes.some(r => r.dst === c.exit_ip + '/32')) routes.rebindUplink(c.uplink, snap.gateway, c.exit_ip);
        else routes.add(c.exit_ip + '/32', c.uplink, snap.gateway);
        // Never borrow the endpoint bypass: switching its gateway would be unsafe.
        assert.ok(routes.state.routes.some(r => r.dst === c.exit_ip + '/32'), 'native_owned_exit_route_required');
        routes.repairTunRoutes();
        for (const p of plan.slice(1)) routes.add(p.dst, p.dev);
        stage = 'readback'; protection(); journal(); const final = snapshot();
        assert.equal(final.stamp, snap.stamp, 'native_uplink_changed_during_rebind');
        assert.ok(complete(final), 'native_route_readback_incomplete');
        // Never synchronously wait for engine startup from its network dependency.
        // Do not replace a concurrently queued stop transaction (including ours).
        stage = 'activate'; ctl('start', '--job-mode=fail', '--no-block', c.engine_unit); previous = final.stamp;
        return { state: 'ready', changed: true };
      } catch (error) {
        stop(); // If quiescence fails, escalate to service failure/BindsTo.
        return { state: 'waiting', changed: false, stage, reason: 'network_or_ownership_not_ready' };
      }
    },
    close() { if (closed) return; closed = true; stop(); },
  };
}
