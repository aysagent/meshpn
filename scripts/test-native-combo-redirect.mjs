import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { nativeComboRedirectPlan } from './lib/native-combo-redirect-plan.mjs';
import { openNativeComboRedirectJournal } from './lib/native-combo-redirect-journal.mjs';
import { recoverNativeComboRedirect } from './clean-vpn-native-combo-redirect-recover.mjs';

const config = { interface: 'usb0', subnet: '192.168.7.0/24', endpoint: '154.62.226.216',
  listen_port: 33002, deny_ipv4: ['8.8.8.0/24'] };
const scope = { boot: '11111111-2222-3333-4444-555555555555', net: 'net:[42]', user: 'user:[7]' };
const testOptions = extra => ({ stateScope: () => scope, trustedAncestor: () => true, ...extra });
function firewall() {
  const tables = { filter: [], nat: [] }, calls = [];
  const run = (file, args) => {
    calls.push([file, [...args]]);
    if (file === 'ip') return JSON.stringify([{ ifname: 'usb0', ifindex: 4, address: '02:00:00:00:00:02', link_type: 'ether' }]);
    assert.equal(file, 'iptables');
    if (args[0] === '--version') return 'iptables v1.8.9 (nf_tables)';
    const table = args[args.indexOf('-t') + 1], action = args.find(value => ['-S', '-N', '-A', '-I', '-D', '-X'].includes(value));
    if (action === '-S') return tables[table].join('\n');
    const at = args.indexOf(action), chain = args[at + 1];
    if (action === '-N') { assert.ok(!tables[table].includes(`-N ${chain}`)); tables[table].push(`-N ${chain}`); return ''; }
    if (action === '-X') { assert.deepEqual(tables[table].filter(line => line.startsWith(`-A ${chain} `)), []);
      const index = tables[table].indexOf(`-N ${chain}`); assert.notEqual(index, -1); tables[table].splice(index, 1); return ''; }
    const skip = action === '-I' ? 3 : 2, spec = args.slice(at + skip), line = `-A ${chain} ${spec.join(' ')}`;
    if (action === '-A' || action === '-I') { assert.ok(!tables[table].includes(line)); tables[table].push(line); return ''; }
    const index = tables[table].indexOf(line); assert.notEqual(index, -1, line); tables[table].splice(index, 1); return '';
  };
  return { run, calls, tables };
}
function directory(t) {
  // The test sandbox exposes /var/tmp through a symlink; production deliberately
  // rejects symlinked ancestors, so use the real sticky /tmp directory here.
  const value = fs.mkdtempSync(path.join('/tmp', 'cvpn-combo-redirect-'));
  t.after(() => fs.rmSync(value, { recursive: true, force: true })); return value;
}

test('plan activates last, closes listener first and blocks HTTPS fallback after cvks4', () => {
  const plan = nativeComboRedirectPlan(config, 'ab'.repeat(12)), text = plan.operations.map(op => op.args.join(' '));
  assert.match(text[0], /-t filter -I INPUT 1 .*--dport 33002.*-j DROP/);
  assert.match(text.at(-1), /-t nat -I PREROUTING 1 -i usb0 -s 192\.168\.7\.0\/24 .*--dport 443.*-j CVPN-CT-/);
  assert.ok(text.some(line => /-t filter -A FORWARD .*--dport 443.*-j DROP/.test(line)));
  assert.ok(text.some(line => /-t filter -I INPUT 1 .*--ctstate DNAT.*--ctorigdstport 443.*-j ACCEPT/.test(line)));
  assert.ok(text.indexOf(text.find(line => line.includes('-A FORWARD'))) < text.length - 1);
  for (const destination of ['10.0.0.0/8', '8.8.8.0/24', '154.62.226.216/32'])
    assert.ok(text.some(line => line.includes(`-d ${destination} -j RETURN`)));
});
for (const patch of [{ interface: 'lo' }, { subnet: '192.168.7.1/24' }, { endpoint: '127.0.0.1' },
  { listen_port: 1053 }, { deny_ipv4: ['8.8.8.1/24'] }, { extra: true }])
  test(`plan rejects ${JSON.stringify(patch)}`, () => assert.throws(() => nativeComboRedirectPlan({ ...config, ...patch }, 'ab'.repeat(12))));

test('journal writes intent, installs exact overlay, audits and restores only its rules', t => {
  const f = firewall(), journal = openNativeComboRedirectJournal(directory(t), testOptions({ run: f.run }));
  try {
    journal.assertAvailable(); const installed = journal.install(config);
    assert.ok(installed.operations > 20); assert.equal(journal.audit().stage, 'active');
    assert.ok(f.tables.filter.some(line => line.includes('clean-vpn-native-combo-')));
    assert.ok(f.tables.nat.some(line => line.startsWith('-N CVPN-CT-')));
    assert.equal(journal.restore().operations, installed.operations);
    assert.deepEqual(f.tables, { filter: [], nat: [] }); journal.assertAvailable();
  } finally { journal.release(); }
});

for (const boundary of ['renamed', 'dir-synced', 'applied']) test(`recovery handles interruption at ${boundary}`, t => {
  const f = firewall(), dir = directory(t); let cut = true;
  const first = openNativeComboRedirectJournal(dir, testOptions({ run: f.run,
    checkpoint(name) { if (cut && name === boundary) { cut = false; throw Error('cut'); } } }));
  assert.throws(() => first.install(config), /cut/); first.release();
  const recovery = openNativeComboRedirectJournal(dir, testOptions({ run: f.run }));
  try { assert.equal(recovery.restore().mode, 'restored'); assert.deepEqual(f.tables, { filter: [], nat: [] }); }
  finally { recovery.release(); }
});

test('foreign owned-prefix state and interface replacement refuse cleanup', t => {
  const f = firewall(), dir = directory(t), journal = openNativeComboRedirectJournal(dir, testOptions({ run: f.run }));
  journal.install(config); f.tables.nat.push('-N CVPN-CT-ffffffffffffffff');
  assert.throws(() => journal.restore(), /foreign redirect state/); journal.release();
  f.tables.nat.pop();
  const replaced = (file, args) => file === 'ip'
    ? JSON.stringify([{ ifname: 'usb0', ifindex: 99, address: '02:00:00:00:00:02', link_type: 'ether' }]) : f.run(file, args);
  const second = openNativeComboRedirectJournal(dir, testOptions({ run: replaced }));
  try { assert.throws(() => second.restore(), /interface replaced/); } finally { second.release(); }
});

test('recovery CLI is read-only by default and requires exact apply token', () => {
  const calls = [], state = { stage: 'active' };
  const open = () => ({ state, restore: options => { calls.push(options); return { mode: options.apply ? 'restored' : 'dry-run' }; },
    release: () => calls.push('release'), assertAvailable: () => calls.push('available') });
  assert.equal(recoverNativeComboRedirect([], open).mode, 'dry-run');
  assert.deepEqual(calls, [{ apply: false }, 'release']); calls.length = 0;
  assert.equal(recoverNativeComboRedirect(['--apply'], open).mode, 'restored');
  assert.deepEqual(calls, [{ apply: true }, 'release']);
  for (const args of [['--force'], ['--apply', '--apply']]) assert.throws(() => recoverNativeComboRedirect(args, open));
});

test('real netns installs, audits and removes only the owned overlay', { timeout: 20000 }, t => {
  if (process.platform !== 'linux' || spawnSync('unshare', ['-Urn', 'ip', 'link', 'add', 'cvpntest', 'type', 'dummy']).status !== 0)
    return t.skip('unprivileged user/network namespaces unavailable');
  const module = new URL('./lib/native-combo-redirect-journal.mjs', import.meta.url).href;
  const result = spawnSync('unshare', ['-Urn', process.execPath, '--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import fs from 'node:fs';
    import {execFileSync} from 'node:child_process';
    import {openNativeComboRedirectJournal} from ${JSON.stringify(module)};
    const run=(file,args)=>execFileSync(file,args,{encoding:'utf8',timeout:5000}).trim();
    run('ip',['link','add','usb0','type','dummy']); run('ip',['link','set','usb0','up']);
    run('ip',['address','add','192.168.7.1/24','dev','usb0']);
    run('iptables',['-w','5','-t','filter','-A','INPUT','-m','comment','--comment','independent-rule','-j','ACCEPT']);
    const dir='/tmp/cvpn-combo-real-'+process.pid;
    const j=openNativeComboRedirectJournal(dir,{run});
    j.assertAvailable(); const installed=j.install(${JSON.stringify(config)}); assert.ok(installed.operations>20);
    assert.equal(j.audit().stage,'active'); assert.equal(j.restore().mode,'restored'); j.assertAvailable(); j.release();
    assert.match(run('iptables',['-w','5','-t','filter','-S','INPUT']),/independent-rule/);
    assert.doesNotMatch(run('iptables',['-w','5','-t','filter','-S']),/clean-vpn-native-combo-|CVPN-CT-/);
    assert.doesNotMatch(run('iptables',['-w','5','-t','nat','-S']),/clean-vpn-native-combo-|CVPN-CT-/);
    fs.rmSync(dir,{recursive:true}); console.log('real-overlay-pass');
  `], { encoding: 'utf8', timeout: 18000 });
  assert.equal(result.status, 0, result.stderr + result.stdout);
  assert.match(result.stdout, /real-overlay-pass/);
});
