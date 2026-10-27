#!/usr/bin/env node
// Bounded gateway controller for an explicitly isolated Linux network namespace.
// Physical host activation deliberately remains outside this contract.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { gatewayPlan, validateGatewayConfig, canonicalGatewayRule as canonical } from './lib/native-runtime-gateway-plan.mjs';
import { dnsProbe } from './clean-vpn-native-runtime-health.mjs';
const C = fs.constants;
const privateFile = fd => {
  const s = fs.fstatSync(fd); assert.ok(s.isFile() && s.uid === 0 && s.nlink === 1 && (s.mode & 0o777) === 0o600 && s.size <= 32768, 'private_gateway_file_required'); return s;
};
const readPrivate = file => {
  const fd = fs.openSync(file, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK);
  try { privateFile(fd); return JSON.parse(fs.readFileSync(fd, 'utf8')); } finally { fs.closeSync(fd); }
};
const scope = () => ({ boot: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(), net: fs.readlinkSync('/proc/self/ns/net'), user: fs.readlinkSync('/proc/self/ns/user') });
const matches = (row, wanted) => Object.entries(wanted).every(([k, v]) => String(k === 'iif' ? row.iif ?? row.iifname : row[k]) === String(v));

export async function gatewayMain(args, { checkpoint = () => {}, ready = () => {} } = {}) {
  const { values: v, positionals } = parseArgs({ args, allowPositionals: true, options: { config: { type: 'string' }, seconds: { type: 'string' } } });
  const [action] = positionals; assert.ok(positionals.length === 1 && ['plan', 'preflight', 'apply', 'recover', 'status'].includes(action));
  const flags = args.filter(a => a.startsWith('--')).map(a => a.split('=')[0]); assert.equal(new Set(flags).size, flags.length);
  assert.ok(v.seconds === undefined || action === 'apply');
  const seconds = Number(v.seconds ?? 300); assert.ok(Number.isInteger(seconds) && seconds >= 10 && seconds <= 900);
  assert.equal(Boolean(v.config), ['plan', 'preflight', 'apply'].includes(action), 'config_only_for_plan_preflight_apply');
  if (action === 'plan') {
    const config = validateGatewayConfig(JSON.parse(fs.readFileSync(v.config, 'utf8')));
    console.log(JSON.stringify({ ...gatewayPlan(config, '000000000000000000000000'), mode: 'plan', networkChanged: false }, null, 2)); return;
  }
  assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0);
  const here = scope(), parent = process.env.CVPN_PARENT_NETNS;
  assert.match(parent ?? '', /^net:\[\d+\]$/, 'parent_namespace_anchor_required'); assert.notEqual(here.net, parent, 'host_namespace_refused');
  let lock, dirfd;
  const run = (bin, argv) => execFileSync(bin, argv, { encoding: 'utf8', timeout: 10000, killSignal: 'SIGKILL',
    stdio: ['ignore', 'pipe', 'pipe', ...(lock === undefined ? [] : [lock])] }).trim();
  const json = argv => JSON.parse(run('ip', argv));
  const links = () => json(['-j', 'link', 'show']);
  const identity = (name, list = links()) => { const link = list.find(l => l.ifname === name); return link ? { index: link.ifindex, address: link.address ?? '', type: link.link_type } : null; };
  const rows = kind => json(kind === 'policy' ? ['-j', '-4', 'rule', 'show'] : ['-j', '-4', 'route', 'show', 'table', 'all']);
  const lines = (family, table) => run(family === 6 ? 'ip6tables-nft' : 'iptables-nft', ['-w', '5', '-t', table, '-S']).split('\n').filter(Boolean);
  const present = op => {
    const found = op.kind === 'firewall' ? lines(op.family, op.table).filter(l => canonical(l) === canonical(op.expected)) : rows(op.kind).filter(r => matches(r, op.match));
    assert.ok(found.length <= 1, 'duplicate_gateway_state'); return found.length === 1;
  };
  const config = v.config ? validateGatewayConfig(readPrivate(v.config)) : null;
  const preflight = c => {
    assert.equal(run('sysctl', ['-n', 'net.ipv4.ip_forward']), '1', 'configured_gateway_required');
    const list = links();
    for (const dev of [c.ingress.interface, c.bridge.interface]) {
      assert.ok(list.find(l => l.ifname === dev)?.flags.includes('UP'), 'gateway_interface_down');
      assert.equal(run('sysctl', ['-n', `net.ipv4.conf.${dev}.rp_filter`]), '2', 'loose_rp_filter_required');
    }
    const addr = json(['-j', '-4', 'addr', 'show', 'dev', c.bridge.interface]);
    assert.ok(addr[0].addr_info.some(a => a.local === c.bridge.host && a.prefixlen === Number(c.bridge.subnet.split('/')[1])), 'bridge_address_mismatch');
    const target = json(['-j', '-4', 'route', 'get', c.bridge.client])[0]; assert.equal(target.dev, c.bridge.interface); assert.equal(target.gateway, undefined, 'onlink_backend_required');
    assert.equal(rows('route').filter(r => String(r.table) === String(c.table)).length, 0, 'gateway_table_busy');
    assert.ok(rows('policy').every(r => (r.priority === 0 || r.priority > c.priority) && String(r.table) !== String(c.table)), 'earlier_or_conflicting_policy');
    for (const [family, table] of [[4, 'filter'], [6, 'filter'], [4, 'nat']]) assert.ok(lines(family, table).every(l => !/CVPN_G[WD]|cvpn-gw-/.test(l)), 'unowned_gateway_state');
    return { ingress: identity(c.ingress.interface, list), bridge: identity(c.bridge.interface, list) };
  };
  if (action === 'preflight') { console.log(JSON.stringify({ status: 'preflight-ok', scope: here, links: preflight(config), networkChanged: false, readinessProbed: false })); return; }
  const directory = '/run/clean-vpn-gateway-' + here.net.match(/\d+/)[0];
  // Fixed per-netns location prevents alternate journals becoming concurrent owners.
  const root = fs.lstatSync('/run'); assert.ok(root.isDirectory() && !root.isSymbolicLink() && root.uid === 0 && !(root.mode & 0o022));
  const noJournal = () => {
    for (const [family, table] of [[4, 'filter'], [6, 'filter'], [4, 'nat']]) assert.ok(lines(family, table).every(l => !/CVPN_G[WD]|cvpn-gw-/.test(l)), 'gateway_rules_without_journal');
    console.log('NATIVE_GATEWAY=no-active-journal');
  };
  if (action !== 'apply' && !fs.existsSync(directory)) { noJournal(); return; }
  if (action === 'apply') try { fs.mkdirSync(directory, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  dirfd = fs.openSync(directory, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);
  let timer, signal, state;
  try {
    const d = fs.fstatSync(dirfd); assert.ok(d.uid === 0 && (d.mode & 0o777) === 0o700);
    const base = '/proc/self/fd/' + dirfd, file = base + '/journal.json';
    lock = fs.openSync(base + '/lock', C.O_RDWR | C.O_CREAT | C.O_NOFOLLOW | C.O_NONBLOCK, 0o600); privateFile(lock);
    try { execFileSync('flock', ['--exclusive', '--nonblock', '3'], { timeout: 10000, stdio: ['ignore', 'pipe', 'pipe', lock] }); }
    catch {
      if(action==='status'){console.log(JSON.stringify({stage:'live-owner',readinessProbed:false}));return;}
      throw Error('live_owner_refused');
    }
    try { state = readPrivate(file); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (action !== 'apply' && !state) { noJournal(); return; }
    const validate = s => {
      assert.deepEqual(Object.keys(s).sort(), ['config', 'id', 'links', 'next', 'schema', 'scope'].sort()); assert.equal(s.schema, 1); assert.deepEqual(s.scope, here, 'gateway_scope_mismatch');
      const ops = gatewayPlan(s.config, s.id).operations; assert.ok(Number.isInteger(s.next) && s.next >= 0 && s.next <= ops.length);
      assert.deepEqual(Object.keys(s.links).sort(), ['bridge', 'ingress']);
      return ops;
    };
    const save = () => {
      validate(state); const tmp = base + '/tmp-' + randomBytes(12).toString('hex'), fd = fs.openSync(tmp, 'wx', 0o600);
      try { fs.writeFileSync(fd, JSON.stringify(state)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      checkpoint('before-rename', state.next); fs.renameSync(tmp, file); fs.fsyncSync(dirfd);
    };
    const audit = ops => {
      let tagged = false;
      for (const key of ['ingress', 'bridge']) {
        const current = identity(state.config[key].interface);
        // Removed bridge is a tested recovery case; a replacement is not ours.
        if (current) assert.deepEqual(current, state.links[key], 'gateway_interface_replaced');
      }
      for (const [family, table] of [[4, 'filter'], [6, 'filter'], [4, 'nat']]) {
        const expected = ops.filter(o => o.kind === 'firewall' && o.family === family && o.table === table).map(o => canonical(o.expected));
        const owned = lines(family, table).filter(l => /CVPN_G[WD]|cvpn-gw-/.test(l)).map(canonical);
        assert.ok(owned.every(l => expected.includes(l)) && new Set(owned).size === owned.length, 'gateway_foreign_firewall_drift');
        tagged ||= owned.some(l=>l.includes('cvpn-gw-'+state.id));
      }
      for (const kind of ['route', 'policy']) {
        const owned = rows(kind).filter(r => String(r.table) === String(state.config.table) || kind === 'policy' && r.priority === state.config.priority);
        const allowed = ops.filter(o => o.kind === kind); assert.ok(owned.every(r => allowed.some(o => matches(r, o.match))), 'gateway_foreign_route_drift');
        // Route rows cannot carry the full random ownership tag. If all of
        // our tagged firewall state vanished (including namespace recreation),
        // matching numeric table/ifindex values alone do not authorize deletion.
        assert.ok(owned.length===0||tagged,'gateway_routes_without_ownership_tag');
      }
    };
    const recover = () => {
      assert.ok(state, 'no_gateway_journal'); const ops = validate(state); audit(ops.slice(0, state.next));
      while (state.next) { const op = ops[state.next - 1]; if (present(op)) run(...op.del); assert.equal(present(op), false); state.next--; save(); }
      fs.unlinkSync(file); fs.fsyncSync(dirfd); console.log('NATIVE_GATEWAY=restored');
    };
    if (action === 'apply') {
      assert.equal(state, undefined, 'recover_previous_gateway_first');
      const linkIds = preflight(config);
      await Promise.all([false, true].map(tcp => dnsProbe(config.bridge.client, 53, tcp)));
      state = { schema: 1, scope: here, config, links: linkIds, next: 0, id: randomBytes(12).toString('hex') }; save();
      const ops = validate(state);
      for (const [i, op] of ops.entries()) { state.next = i + 1; save(); checkpoint('before-mutation', state.next); run(...op.add); checkpoint('after-mutation', state.next); assert.ok(present(op)); }
      audit(ops); console.log('NATIVE_GATEWAY=ready'); ready();
      await new Promise(resolve => { timer = setTimeout(resolve, seconds * 1000); signal = () => resolve(); process.once('SIGTERM', signal); process.once('SIGINT', signal); });
      recover();
    } else if (action === 'recover') recover();
    else { const ops = validate(state); audit(ops.slice(0, state.next)); console.log(JSON.stringify({ stage: state.next === ops.length && ops.every(present) ? 'applied' : 'incomplete', operations: state.next, readinessProbed: false })); }
  } finally {
    clearTimeout(timer); if (signal) { process.off('SIGTERM', signal); process.off('SIGINT', signal); }
    if (lock !== undefined) fs.closeSync(lock); fs.closeSync(dirfd);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv[2] === '--help') console.log('Usage: clean-vpn-native-gateway.mjs plan|preflight|apply --config=FILE [--seconds=10..900]; recover|status\nApply/recover: root in a dedicated Linux netns, CVPN_PARENT_NETNS must identify its parent. Same-boot journal; SIGKILL retains guard until independent recovery. Never edits host defaults, resolver, dnsmasq files or sysctls.');
  else gatewayMain(process.argv.slice(2)).catch(e => { console.error('NATIVE_GATEWAY=failed: ' + e.message); process.exitCode = 1; });
}
