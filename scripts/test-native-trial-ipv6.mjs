import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { ipv6Plan, CLIENT6 } from './lib/vpn-ipv6.mjs';
import { validateBlockedTrialIpv6, inspectBlockedTrialIpv6, validateReleasedTrialIpv6 } from './lib/native-trial-ipv6.mjs';
import { deriveTrialConfig } from './lib/native-radxa-trial.mjs';

function blocked() {
  const config = { role: 'client', tun: 'tun0', ext: null, id: 'a'.repeat(24), forward: false, tunForward: '0' };
  const scope = { boot: 'a'.repeat(36), net: 'net:[1]', user: 'user:[2]' };
  return { scope, backend: 'nf_tables', state: { schema: 1, scope: { ...scope }, config,
    links: { tun0: { ifindex: 7, address: '', type: 'none' } }, backend: 'nf_tables',
    stage: 'active', count: ipv6Plan(config).length, dynamic: false },
  links: [{ ifname: 'tun0', ifindex: 7, link_type: 'none', addr_info: [{ family: 'inet6', local: CLIENT6, prefixlen: 126 }] }],
  rules: [{ priority: 0, src: 'all', table: 'local' },
    { priority: 10995, src: 'all', dst: '2000::', dstlen: 3, table: '19997' },
    { priority: 32766, src: 'all', table: 'main' }],
  routes: [{ type: 'unreachable', dst: 'default', table: '19997', metric: 32767 },
    { dst: 'default', dev: 'wlan0', gateway: 'fe80::1' },
    { dst: 'fd42:6376:706e::/126', dev: 'tun0' }, { dst: 'fe80::/64', dev: 'tun0' }] };
}
test('blocked auto accepts ULA on TUN and main-table WLAN default without enabling native IPv6', () => {
  const ipv6Evidence = blocked(); validateBlockedTrialIpv6(ipv6Evidence);
  const root = '/root/dev/meshpn';
  const config = deriveTrialConfig(['node', root + '/scripts/clean-vpn.js', '--role=client', '--type=tls',
    '--server=154.62.226.216:443', '--split-default', '--dns-usb=1', '--ipv6=auto'],
  { cwd: root, root, exists: () => true, ipv6Evidence });
  assert.equal(config.dns, true); assert.equal(config.tun, 'tun0');
  assert.ok(!('ipv6' in config)); assert.ok(!('ipv6Evidence' in config));
});
const bad = {
  'active tunnel': e => { e.state.dynamic = true; },
  'installing': e => { e.state.stage = 'installing'; },
  'released': e => { e.state.stage = 'released'; e.state.count = 0; },
  'foreign namespace': e => { e.scope.net = 'net:[3]'; },
  'foreign boot': e => { e.scope.boot = 'b'.repeat(36); },
  'different backend': e => { e.backend = 'legacy'; },
  'new TUN': e => { e.links[0].ifindex++; },
  'missing ULA': e => { e.links[0].addr_info = []; },
  'missing policy': e => { e.rules.splice(1, 1); },
  'duplicate policy': e => { e.rules.push(e.rules[1]); },
  'earlier bypass': e => { e.rules.push({ priority: 1, src: 'all', table: 'main' }); },
  'foreign selector': e => { e.rules[1].fwmark = 1; },
  'missing block route': e => { e.routes.shift(); },
  'extra tunnel route': e => { e.routes.push({ table: '19997', dev: 'tun0', dst: '2000::/3' }); },
  'main tunnel default': e => { e.routes.push({ dev: 'tun0', dst: 'default' }); },
};
for (const [name, mutate] of Object.entries(bad)) test(`blocked-auto refuses ${name}`, () => {
  const e = blocked(); mutate(e); assert.throws(() => validateBlockedTrialIpv6(e));
});
test('no evidence cannot silently downgrade auto to off', () => assert.throws(() => validateBlockedTrialIpv6(), /requires_blocked_evidence/));

function collector(e = blocked()) {
  const commands = [];
  const io = { readState: () => structuredClone(e.state), scope: () => e.scope, async run(file, args) {
    commands.push([file, args]);
    if (file === 'ip6tables') return args[0] === '--version' ? 'ip6tables v1.8 (nf_tables)' : '';
    if (args.includes('address')) return JSON.stringify(e.links);
    return JSON.stringify(args.includes('rule') ? e.rules : e.routes);
  } };
  return { io, commands };
}
test('live snapshot checks all fixed firewall operations without acquiring lock or modifying network', async () => {
  const { io, commands } = collector(); await inspectBlockedTrialIpv6(io);
  assert.equal(commands.filter(([f, a]) => f === 'ip6tables' && a.includes('-C')).length, 7);
  assert.ok(commands.every(([f, a]) => f === 'ip' ? a.includes('show') : a.includes('-C') || a.includes('-S') || a.includes('--version')));
});
test('journal transition during snapshot refuses trial', async () => {
  const { io } = collector(); let count = 0;
  io.readState = () => { const s = blocked().state; if (++count > 1) s.dynamic = true; return s; };
  await assert.rejects(inspectBlockedTrialIpv6(io), /ipv6_changed_during_trial_preflight/);
});
test('missing firewall operation refuses trial', async () => {
  const { io } = collector(), run = io.run;
  io.run = (f, a) => { if (a.includes('-C')) throw Error('missing_rule'); return run(f, a); };
  await assert.rejects(inspectBlockedTrialIpv6(io), /missing_rule/);
});
test('journal reader uses bounded private regular files; refuses links, public files, FIFO and unsafe directory', t => {
  if (process.platform !== 'linux' || spawnSync('unshare', ['-Ur', 'true']).status !== 0) return t.skip('userns unavailable');
  const r = spawnSync('unshare', ['-Ur', process.execPath, '--input-type=module', '-e', `
    import fs from 'node:fs';
    import assert from 'node:assert/strict';
    import {execFileSync} from 'node:child_process';
    import {readTrialIpv6State} from './scripts/lib/native-trial-ipv6.mjs';
    const dir = fs.mkdtempSync('/tmp/cv-trial-ipv6-reader-'), file = dir + '/journal.json';
    const state = ${JSON.stringify(blocked().state)};
    try {
      fs.writeFileSync(file, JSON.stringify(state), {mode:0o600});
      assert.deepEqual(readTrialIpv6State(dir), state);
      fs.chmodSync(file, 0o644); assert.throws(() => readTrialIpv6State(dir));
      fs.chmodSync(file, 0o600);
      fs.linkSync(file, dir + '/hardlink'); assert.throws(() => readTrialIpv6State(dir));
      fs.unlinkSync(dir + '/hardlink');
      fs.renameSync(file, dir + '/original'); fs.symlinkSync(dir + '/original', file);
      assert.throws(() => readTrialIpv6State(dir)); fs.unlinkSync(file);
      execFileSync('mkfifo', [file]); assert.throws(() => readTrialIpv6State(dir)); fs.unlinkSync(file);
      fs.writeFileSync(file, ' '.repeat(16384), {mode:0o600}); assert.throws(() => readTrialIpv6State(dir));
      fs.writeFileSync(file, JSON.stringify(state));
      fs.chmodSync(dir, 0o755); assert.throws(() => readTrialIpv6State(dir));
      fs.chmodSync(dir, 0o700); fs.symlinkSync(dir, dir + '/symlink');
      assert.throws(() => readTrialIpv6State(dir + '/symlink'));
    } finally { fs.rmSync(dir, {recursive:true,force:true}); }
  `], { encoding: 'utf8', timeout: 10000 });
  assert.equal(r.status, 0, r.stderr);
});

const released = () => ({ report: { mode: 'dry-run', stage: 'released', operations: 0, tunnelRoute: false },
  rules: [], routes: [], links: [], filter: '-P OUTPUT ACCEPT\n-N CLEANVPN_KS_OUT', nat: '-P POSTROUTING ACCEPT' });
test('cleanup requires released journal for auto; absent journal is allowed only for off', () => {
  validateReleasedTrialIpv6(released(), true);
  const e = released(); e.report = { mode: 'no-journal', operations: 0 };
  validateReleasedTrialIpv6(e, false); assert.throws(() => validateReleasedTrialIpv6(e, true));
});
for (const [name, mutate] of Object.entries({
  'unreleased journal': e => { e.report.stage = 'active'; },
  'native TUN still exists': e => { e.links = [{ ifname: 'tun0', addr_info: [] }]; },
  'orphan rule': e => { e.rules = blocked().rules; },
  'orphan route': e => { e.routes = blocked().routes; },
  'orphan address': e => { e.links = [{ ifname: 'other', addr_info: blocked().links[0].addr_info }]; },
  'orphan filter chain': e => { e.filter += '\n-N CV6_aaaaaaaaaaaaaaaa'; },
  'orphan nat tag': e => { e.nat += '\n-A POSTROUTING -m comment --comment clean-vpn-ipv6-aaa'; },
})) test(`cleanup refuses ${name}`, () => { const e = released(); mutate(e); assert.throws(() => validateReleasedTrialIpv6(e, true)); });

test('real kernel blocked policy is accepted; adding tunnel route is rejected', t => {
  if (process.platform !== 'linux' || spawnSync('unshare', ['-Urn', 'true']).status !== 0) return t.skip('netns unavailable');
  const source = `
    import { execFileSync as run } from 'node:child_process';
    import { validateBlockedTrialIpv6 } from './scripts/lib/native-trial-ipv6.mjs';
    const e = ${JSON.stringify(blocked())};
    const ip = (...a) => run('ip', a, {encoding:'utf8'});
    ip('link','add','tun0','type','dummy'); ip('link','set','tun0','up');
    ip('-6','addr','add','${CLIENT6}/126','dev','tun0','nodad');
    ip('-6','route','add','unreachable','default','table','19997','metric','32767');
    ip('-6','rule','add','pref','10995','to','2000::/3','lookup','19997');
    e.links = JSON.parse(ip('-j','address','show'));
    const tun = e.links.find(l => l.ifname === 'tun0');
    e.state.links.tun0 = {ifindex:tun.ifindex,address:tun.address??'',type:tun.link_type};
    e.rules = JSON.parse(ip('-j','-6','rule','show'));
    e.routes = JSON.parse(ip('-j','-6','route','show','table','all'));
    validateBlockedTrialIpv6(e);
    ip('-6','route','add','2000::/3','dev','tun0','table','19997');
    e.routes = JSON.parse(ip('-j','-6','route','show','table','all'));
    let refused = false; try { validateBlockedTrialIpv6(e); } catch { refused = true; }
    if (!refused) process.exit(1);
  `;
  const r = spawnSync('unshare', ['-Urn', process.execPath, '--input-type=module', '-e', source], { encoding: 'utf8', timeout: 10000 });
  assert.equal(r.status, 0, r.stderr);
});
