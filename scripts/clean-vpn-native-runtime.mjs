#!/usr/bin/env node
// Explicit isolated namespace only. No host routes, resolv.conf or services.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { runtimePlan, restoreTable, auditRuntimeTables } from './lib/native-runtime-plan.mjs';

const run = (cmd, args, input) => execFileSync(cmd, args, { encoding: 'utf8', input, timeout: 15000, maxBuffer: 1024 * 1024 });
const read = p => fs.readFileSync(p, 'utf8');
function privateFile(p, limit = 16384) {
  const s = fs.lstatSync(p);
  assert.ok(s.isFile() && s.uid === 0 && !(s.mode & 0o022) && s.size <= limit, 'unsafe_config_file');
  return read(p);
}
function main() {
  assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0, 'rootful_runtime_required');
  assert.equal(process.argv.length, 3, 'usage_runtime_ENGINE_JSON');
  const parent = process.env.CVPN_PARENT_NETNS;
  assert.match(parent ?? '', /^net:\[\d+\]$/, 'parent_namespace_anchor_required');
  const namespace = fs.readlinkSync('/proc/self/ns/net');
  assert.notEqual(namespace, parent, 'host_network_refused');
  const source = process.argv[2]; assert.ok(source.startsWith('/'));
  const configText = privateFile(source), c = JSON.parse(configText);
  let lan = process.env.CVPN_LAN_INTERFACE || process.env.CVPN_LAN_SUBNET
    ? { interface: process.env.CVPN_LAN_INTERFACE, subnet: process.env.CVPN_LAN_SUBNET } : null;
  let uplink = process.env.CVPN_UPLINK ?? 'eth0';
  const mtu = Number(process.env.CVPN_MTU ?? 1400);
  if (uplink === 'auto' || lan?.interface === 'auto') {
    // Validate values before using them in discovery. Names below are only
    // placeholders for pure validation, never passed to a network command.
    runtimePlan(c, { uplink: 'cvpnuplink', mtu, lan: lan ? { ...lan, interface: 'cvpnlan' } : null });
    const addresses = JSON.parse(run('ip', ['-j', '-4', 'addr', 'show']));
    if (lan?.interface === 'auto') {
      const [network, prefix] = lan.subnet.split('/'), bits = Number(prefix);
      const numeric = ip => ip.split('.').reduce((v, b) => v * 256 + Number(b), 0);
      const candidates = addresses.filter(l => !['lo', c.tun].includes(l.ifname) && l.addr_info.some(a =>
        a.prefixlen === bits && Math.floor(numeric(a.local) / 2 ** (32 - bits)) === numeric(network) / 2 ** (32 - bits)));
      assert.equal(candidates.length, 1, 'unique_lan_interface_required'); lan = { ...lan, interface: candidates[0].ifname };
    }
    if (uplink === 'auto') {
      if (c.role === 'client') uplink = JSON.parse(run('ip', ['-j', '-4', 'route', 'get', c.address]))[0]?.dev;
      else {
        const candidates = addresses.filter(l => l.addr_info.some(a => a.local === c.address));
        assert.equal(candidates.length, 1, 'unique_exit_interface_required'); uplink = candidates[0].ifname;
      }
    }
  }
  const plan = runtimePlan(c, { uplink, mtu, lan });
  const backend = process.env.CVPN_IPTABLES_BACKEND ?? 'nft';
  assert.ok(['nft', 'legacy'].includes(backend), 'explicit_firewall_backend_required');
  plan.firewallBackend = backend;
  const firewall = (family, op) => `${family === 6 ? 'ip6tables' : 'iptables'}-${backend}-${op}`;
  const engine = process.env.CVPN_ENGINE ?? '/usr/local/bin/clean-vpn-engine';
  assert.ok(engine.startsWith('/'));
  // Validate credentials/profile and required grants before any OS write.
  run(engine, ['--check-config', source]);
  const caps = BigInt('0x' + read('/proc/self/status').match(/^CapEff:\s*([0-9a-f]+)$/m)[1]);
  for (const bit of [12, 13]) assert.ok((caps & (1n << BigInt(bit))) !== 0n, 'NET_ADMIN_and_NET_RAW_required');
  assert.ok(fs.statSync('/dev/net/tun').isCharacterDevice(), 'tun_device_required');
  const links = JSON.parse(run('ip', ['-j', 'link', 'show']));
  assert.ok(links.some(l => l.ifname === plan.uplink), 'uplink_missing');
  assert.ok(!links.some(l => !['lo', plan.uplink, plan.tun, plan.lan?.interface].includes(l.ifname)), 'unexpected_link_refused');
  if (plan.forwarding) assert.equal(read('/proc/sys/net/ipv4/ip_forward').trim(), '1', 'forwarding_requires_namespaced_ip_forward_1');
  if (plan.lan) {
    const network = plan.lan.subnet.split('/'), bits = Number(network[1]);
    const numeric = ip => ip.split('.').reduce((v, b) => v * 256 + Number(b), 0);
    const lanAddresses = JSON.parse(run('ip', ['-j', '-4', 'addr', 'show', 'dev', plan.lan.interface]))[0]?.addr_info ?? [];
    assert.ok(lanAddresses.some(a => a.prefixlen === bits && Math.floor(numeric(a.local) / 2 ** (32 - bits)) === numeric(network[0]) / 2 ** (32 - bits)), 'lan_address_mismatch');
    assert.ok(!JSON.parse(run('ip', ['-j', '-4', 'addr', 'show', 'dev', plan.uplink]))[0].addr_info.some(a => Math.floor(numeric(a.local) / 2 ** (32 - bits)) === numeric(network[0]) / 2 ** (32 - bits)), 'lan_uplink_overlap');
  }
  const state = process.env.CVPN_STATE_DIRECTORY ?? '/run/clean-vpn';
  assert.match(state, /^\/run\/clean-vpn(?:-[a-zA-Z0-9_-]{1,48})?$/, 'private_runtime_state_path_required');
  fs.mkdirSync(state, { mode: 0o700, recursive: true });
  const st = fs.lstatSync(state); assert.ok(st.isDirectory() && st.uid === 0 && !(st.mode & 0o077), 'private_state_required');
  const journal = state + '/network.json';
  const fingerprint = createHash('sha256').update(JSON.stringify(plan)).digest('hex');
  const saved = () => Object.fromEntries(plan.tables.map(t => [`${t.family}/${t.name}`, run(firewall(t.family, 'save'), ['-t', t.name])]));
  const persist = record => {
    const fd = fs.openSync(journal + '.tmp', 'wx', 0o600);
    try { fs.writeFileSync(fd, JSON.stringify(record) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(journal + '.tmp', journal);
  };
  if (fs.existsSync(journal)) {
    const previous = JSON.parse(privateFile(journal));
    assert.equal(previous.namespace, namespace, 'recreate_requires_fresh_run_tmpfs');
    assert.equal(previous.fingerprint, fingerprint, 'network_config_changed_recreate_required');
    assert.equal(previous.phase, 'ready', 'interrupted_setup_recreate_required');
    auditRuntimeTables(plan, saved());
    const a = JSON.parse(run('ip', ['-j', 'addr', 'show', 'dev', plan.tun]))[0];
    assert.equal(a.mtu, plan.mtu); assert.ok(a.flags.includes('UP'));
    assert.deepEqual(a.addr_info.filter(v => v.family === 'inet').map(v => `${v.local}/${v.prefixlen}`), [plan.tunAddress]);
    if (plan.role === 'client') {
      const routes = JSON.parse(run('ip', ['-j', '-4', 'route', 'show']));
      for (const dst of ['0.0.0.0/1', '128.0.0.0/1']) {
        const matches = routes.filter(r => r.dst === dst); assert.equal(matches.length, 1);
        assert.equal(matches[0].dev, plan.tun); assert.equal(matches[0].prefsrc, plan.address);
      }
      assert.ok(routes.some(r => r.dst === plan.endpoint && r.dev === plan.uplink), 'endpoint_route_missing');
    }
  } else {
    assert.ok(!links.some(l => l.ifname === plan.tun), 'foreign_tun_refused');
    assert.ok(Object.values(saved()).every(v => !v.includes('CVPN_R_')), 'foreign_runtime_chains_refused');
    const routes = JSON.parse(run('ip', ['-j', '-4', 'route', 'show', 'default']));
    assert.ok(routes.length <= 1, 'ambiguous_default_routes');
    if (routes.length) { assert.equal(routes[0].dev, plan.uplink); assert.ok(routes[0].gateway, 'default_gateway_required'); }
    const endpointRoute = JSON.parse(run('ip', ['-j', '-4', 'route', 'get', plan.endpoint]))[0];
    if (plan.role === 'client') assert.equal(endpointRoute.dev, plan.uplink, 'endpoint_not_on_uplink');
    assert.ok(JSON.parse(run('ip', ['-j', '-4', 'route', 'show'])).every(r => !['0.0.0.0/1', '128.0.0.0/1', plan.endpoint].includes(r.dst)), 'route_collision');
    persist({ version: 1, namespace, fingerprint, phase: 'preparing', plan });
    for (const t of plan.tables) run(firewall(t.family, 'restore'), ['--wait', '5', '--noflush'], restoreTable(t));
    run('ip', ['tuntap', 'add', 'dev', plan.tun, 'mode', 'tun']);
    run('ip', ['addr', 'add', plan.tunAddress, 'dev', plan.tun]);
    run('ip', ['link', 'set', plan.tun, 'mtu', String(plan.mtu), 'up']);
    if (plan.role === 'client') {
      run('ip', ['route', 'add', `${plan.endpoint}/32`, ...(endpointRoute.gateway ? ['via', endpointRoute.gateway] : []), 'dev', plan.uplink]);
      for (const dst of ['0.0.0.0/1', '128.0.0.0/1']) run('ip', ['route', 'add', dst, 'dev', plan.tun, 'src', plan.address]);
    } else assert.equal(read('/proc/sys/net/ipv4/ip_forward').trim(), '1', 'exit_requires_namespaced_ip_forward_1');
    auditRuntimeTables(plan, saved());
    persist({ version: 1, namespace, fingerprint, phase: 'ready', plan });
  }
  // Private snapshot: engine receives exactly the configuration just validated.
  fs.writeFileSync(state + '/engine.json', configText, { mode: 0o600 });
  console.log(JSON.stringify({ kind: 'native-runtime-network', phase: 'guarded', role: plan.role, namespace, fingerprint }));
}
try { main(); } catch (error) {
  // No automatic guard teardown on failure. Destroy the owned namespace.
  console.error('NATIVE_RUNTIME_REFUSED: ' + (error.code ? error.code + ': ' : '') + error.message.split('\n')[0]);
  process.exitCode = 1;
}
