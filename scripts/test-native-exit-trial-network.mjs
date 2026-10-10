import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { openNativeExitTrialNetwork } from './lib/native-exit-trial-network.mjs';
import { recoverNativeExit } from './clean-vpn-native-exit-recover.mjs';

const config = { endpoint: '154.62.226.216', uplink: 'eth0', port: 443 };
const scope = { boot: '11111111-2222-3333-4444-555555555555', net: 'net:[42]', user: 'user:[7]' };
const opts = extra => ({ stateScope: () => scope, trustedAncestor: () => true, ...extra });
function temp(t) { const dir = fs.mkdtempSync('/tmp/cvpn-exit-owner-'); t.after(() => fs.rmSync(dir, { recursive: true, force: true })); return dir; }
function machine() {
  const tables = { filter: [], nat: [] }, links = [], calls = []; let forwarding = '0';
  const run = (file, args) => {
    calls.push([file, [...args]]);
    if (file === 'sysctl') {
      if (args[0] === '-n') return forwarding;
      forwarding = args[1].endsWith('=1') ? '1' : '0'; return `net.ipv4.ip_forward = ${forwarding}`;
    }
    if (file === 'ip') {
      if (args[0] === '-j' && args.includes('link')) return JSON.stringify(links.map(link => ({ ifname: link.name, ifindex: link.index,
        mtu: link.mtu, flags: link.up ? ['UP'] : [], linkinfo: { info_kind: 'tun' } })));
      if (args[0] === '-j' && args.includes('address')) { const link = links.find(item => item.name === args.at(-1));
        return JSON.stringify(link ? [{ ifname: link.name, addr_info: link.address ? [{ family: 'inet', local: '10.99.0.1', prefixlen: 24 }] : [] }] : []); }
      if (args[0] === 'tuntap' && args[1] === 'add') { links.push({ name: args[3], index: 90, mtu: 1500, up: false, address: false }); return ''; }
      if (args[0] === 'tuntap' && args[1] === 'del') { const at = links.findIndex(item => item.name === args[3]); assert.notEqual(at, -1); links.splice(at, 1); return ''; }
      const link = links.find(item => item.name === args.at(-1) || item.name === args[args.indexOf('dev') + 1]); assert.ok(link);
      if (args[0] === 'address') link.address = args[1] === 'add';
      else if (args[0] === 'link') { link.up = args.includes('up'); if (args.includes('mtu')) link.mtu = Number(args[args.indexOf('mtu') + 1]); }
      return '';
    }
    assert.equal(file, 'iptables'); if (args[0] === '--version') return 'iptables v1.8.9 (nf_tables)';
    const table = args[args.indexOf('-t') + 1];
    const action = args.find(value => ['-S', '-I', '-D'].includes(value));
    if (action === '-S') return tables[table].join('\n');
    const at = args.indexOf(action), chain = args[at + 1], spec = args.slice(at + (action === '-I' ? 3 : 2));
    const line = `-A ${chain} ${spec.join(' ')}`;
    if (action === '-I') { assert.ok(!tables[table].includes(line)); tables[table].unshift(line); }
    else { const index = tables[table].indexOf(line); assert.notEqual(index, -1); tables[table].splice(index, 1); }
    return '';
  };
  return { run, tables, links, calls, get forwarding() { return forwarding; } };
}

test('scoped exit owner uses random TUN, preserves unrelated rules and original forwarding', t => {
  const m = machine(); m.tables.filter.push('-A INPUT -m comment --comment unrelated -j ACCEPT');
  const owner = openNativeExitTrialNetwork(temp(t), opts({ run: m.run }));
  try {
    owner.assertAvailable(); const prepared = owner.prepare(config); assert.match(prepared.tun, /^cvne[a-f0-9]{10}$/);
    const active = owner.install(); assert.equal(active.tun, prepared.tun); assert.equal(owner.audit().stage, 'active');
    assert.equal(m.forwarding, '1'); assert.equal(m.links.length, 1);
    assert.equal(owner.restore().mode, 'restored'); assert.equal(m.forwarding, '0'); assert.deepEqual(m.links, []);
    assert.deepEqual(m.tables, { filter: ['-A INPUT -m comment --comment unrelated -j ACCEPT'], nat: [] }); owner.assertAvailable();
  } finally { owner.release(); }
});

test('pre-existing forwarding is never disabled', t => {
  const m = machine(); m.run('sysctl', ['-w', 'net.ipv4.ip_forward=1']);
  const owner = openNativeExitTrialNetwork(temp(t), opts({ run: m.run }));
  try { owner.prepare(config); owner.install(); owner.restore(); assert.equal(m.forwarding, '1'); }
  finally { owner.release(); }
});

test('firewall backend drift refuses cleanup', t => {
  const m = machine(), dir = temp(t), owner = openNativeExitTrialNetwork(dir, opts({ run: m.run }));
  owner.prepare(config); owner.install(); owner.release();
  const drift = (file, args) => file === 'iptables' && args[0] === '--version' ? 'iptables v1.8.9 (legacy)' : m.run(file, args);
  const recovery = openNativeExitTrialNetwork(dir, opts({ run: drift }));
  try { assert.throws(() => recovery.restore(), /firewall backend changed/); } finally { recovery.release(); }
});

for (const boundary of ['renamed', 'dir-synced', 'applied']) test(`exit recovery handles install interruption at ${boundary}`, t => {
  const m = machine(), dir = temp(t); let armed = false, cut = false;
  const owner = openNativeExitTrialNetwork(dir, opts({ run: m.run, checkpoint(name) {
    if (armed && !cut && name === boundary) { cut = true; throw Error('cut'); }
  } }));
  owner.prepare(config); armed = true; assert.throws(() => owner.install(), /cut/); owner.release();
  const recovery = openNativeExitTrialNetwork(dir, opts({ run: m.run }));
  try { assert.equal(recovery.restore().mode, 'restored'); assert.equal(m.forwarding, '0'); assert.deepEqual(m.links, []); }
  finally { recovery.release(); }
});

test('recovery CLI defaults to audit only', () => {
  const calls = [], open = () => ({ state: { stage: 'active' }, restore: options => { calls.push(options); return { mode: options.apply ? 'restored' : 'dry-run' }; }, release: () => calls.push('release') });
  assert.equal(recoverNativeExit([], open).mode, 'dry-run'); assert.deepEqual(calls, [{ apply: false }, 'release']);
  assert.throws(() => recoverNativeExit(['--force'], open));
});

test('real netns applies and removes only scoped exit state', { timeout: 20000 }, t => {
  if (process.platform !== 'linux' || spawnSync('unshare', ['-Urn', 'ip', 'link', 'set', 'lo', 'up']).status !== 0)
    return t.skip('unprivileged user/network namespaces unavailable');
  const module = new URL('./lib/native-exit-trial-network.mjs', import.meta.url).href;
  const result = spawnSync('unshare', ['-Urn', process.execPath, '--input-type=module', '-e', `
    import assert from 'node:assert/strict'; import fs from 'node:fs'; import {execFileSync} from 'node:child_process';
    import {openNativeExitTrialNetwork} from ${JSON.stringify(module)};
    const run=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:5000}).trim();
    run('ip',['link','add','eth0','type','dummy']); run('ip',['link','set','eth0','up']);
    run('iptables',['-A','INPUT','-m','comment','--comment','independent-exit-rule','-j','ACCEPT']);
    const dir='/tmp/cvpn-exit-real-'+process.pid, o=openNativeExitTrialNetwork(dir,{run});
    const p=o.prepare(${JSON.stringify(config)}); assert.match(p.tun,/^cvne/); o.install(); assert.equal(o.audit().stage,'active');
    o.restore(); o.assertAvailable(); o.release();
    assert.match(run('iptables',['-S','INPUT']),/independent-exit-rule/); assert.doesNotMatch(run('iptables',['-S']),/clean-vpn-native-exit-/);
    assert.doesNotMatch(run('iptables',['-t','nat','-S']),/clean-vpn-native-exit-/); assert.equal(run('sysctl',['-n','net.ipv4.ip_forward']),'0');
    fs.rmSync(dir,{recursive:true}); console.log('real-exit-owner-pass');
  `], { encoding: 'utf8', timeout: 18000 });
  assert.equal(result.status, 0, result.stderr + result.stdout); assert.match(result.stdout, /real-exit-owner-pass/);
});
