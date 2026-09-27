import assert from 'node:assert/strict';
import test from 'node:test';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { openTunnelDnsJournal, validateTunnelDnsJournal } from './lib/dns-tunnel-journal.mjs';

const config = { tun: 'tun0', fromTun: 'wg0' };
function fixture(t) {
  const dir = fs.mkdtempSync(join(fs.realpathSync(tmpdir()), 'meshpn-tunnel-dns-journal-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const tables = new Map(), routes = [], policies = [], mutations = [];
  const links = [{ ifname: 'tun0', ifindex: 11, address: '', link_type: 'none' },
    { ifname: 'wg0', ifindex: 10, address: '', link_type: 'none' }];
  const run = (file, args) => {
    const val = (key) => args[args.indexOf(key) + 1];
    if (file === 'iptables' || file === 'ip6tables') {
      if (args[0] === '--version') return `${file} v1.8.10 (nf_tables)`;
      const key = `${file}/${val('-t')}`; if (!tables.has(key)) tables.set(key, []);
      const lines = tables.get(key); if (args.includes('-S')) return lines.join('\n');
      mutations.push([file, args]);
      const at = args.findIndex((v) => ['-N', '-X', '-I', '-A', '-D'].includes(v)), command = args[at];
      const spec = [args[at + 1], ...args.slice(at + (command === '-I' ? 3 : 2))];
      const line = [command === '-N' || command === '-X' ? '-N' : '-A', ...spec].join(' ');
      if (command === '-X' || command === '-D') { const index = lines.indexOf(line); assert.ok(index >= 0); lines.splice(index, 1); }
      else { assert.ok(!lines.includes(line)); lines.push(line); }
      return '';
    }
    assert.equal(file, 'ip');
    if (args.includes('link')) return JSON.stringify(links);
    const collection = args.includes('route') ? routes : policies;
    if (args.includes('show')) return JSON.stringify(collection);
    mutations.push([file, args]);
    const item = args.includes('route') ? args.includes('unreachable')
      ? { type: 'unreachable', dst: 'default', metric: 32767, table: 19998 }
      : { dst: args[3], dev: val('dev'), prefsrc: val('src'), scope: 'link', table: 19998 }
      : { priority: Number(val('priority')), src: val('from'), dst: val('to'), table: Number(val('lookup')) };
    if (args.includes('add')) collection.push(item);
    else { const index = collection.findIndex((v) => JSON.stringify(v) === JSON.stringify(item)); assert.ok(index >= 0); collection.splice(index, 1); }
    return '';
  };
  const open = (options = {}) => openTunnelDnsJournal(dir, { coordinate: false, run, ...options });
  return { dir, path: join(dir, 'journal.json'), open, run, tables, routes, policies, links, mutations };
}
const install = (j) => { for (const stage of ['guard', 'route', 'activate']) j.applyStage(stage); j.activate(); };

test('network journal writes bounded data, stages exact own operations and restores only those', (t) => {
  const f = fixture(t), j = f.open(); t.after(() => j.release());
  j.begin(config); assert.equal(f.mutations.length, 0); assert.equal(j.state.count, 0);
  assert.equal(fs.statSync(f.path).mode & 0o777, 0o600);
  assert.ok(!fs.readFileSync(f.path, 'utf8').includes('iptables'));
  assert.throws(() => j.applyStage('route'), /out of order/);
  install(j); assert.equal(j.state.stage, 'active');
  const n = f.mutations.length; j.restore({ apply: false }); assert.equal(f.mutations.length, n);
  j.restore(); assert.equal(j.state.stage, 'released'); assert.equal(j.state.count, 0);
  assert.deepEqual(f.routes, []); assert.deepEqual(f.policies, []);
  assert.ok([...f.tables.values()].every((lines) => !lines.length));
  const end = f.mutations.length; j.restore(); assert.equal(f.mutations.length, end);
});

test('restart preserves a closed gate across cleanup, replacement TUN and new install', (t) => {
  const f = fixture(t); let j = f.open(); t.after(() => j.release()); j.begin(config); install(j); j.release();
  j = f.open(); assert.throws(() => j.prepareRestart({ fromTun: 'wg9' }), /scope changed/);
  j.prepareRestart({ fromTun: 'wg0' }); assert.equal(j.state.stage, 'parked'); assert.ok(j.state.hold > 0);
  f.links[0].ifindex = 99; // old network mutations have gone; replacing the TUN is now legitimate
  j.begin({ ...config, primary: '9.9.9.9' }); assert.ok(j.state.hold > 0);
  for (const stage of ['guard', 'route', 'activate']) { j.applyStage(stage); assert.ok(j.state.hold > 0); }
  j.activate(); assert.equal(j.state.hold, 0); assert.equal(j.state.stage, 'active'); j.restore();
});

test('interruption after a durable mutation intent is recoverable without applying unknown commands', (t) => {
  for (const point of ['dir-synced', 'applied', 'removed', 'hold-applied', 'hold-removed']) {
    const f = fixture(t); let armed = false;
    let j = f.open({ checkpoint: (name, v) => {
      if (armed && name === point && (v.count > 0 || v.hold > 0)) { armed = false; throw new Error('simulated interruption'); }
    } });
    j.begin(config);
    if (['removed', 'hold-applied', 'hold-removed'].includes(point)) install(j);
    armed = true;
    assert.throws(() => point === 'applied' || point === 'dir-synced' ? j.applyStage('guard') : j.restore(), /interruption/);
    j.release(); j = f.open(); try { j.restore(); assert.equal(j.state.stage, 'released'); } finally { j.release(); }
  }
});

for (const conflict of ['rule', 'duplicate', 'route', 'policy', 'interface']) test(`foreign ${conflict} stops recovery before any mutation`, (t) => {
  const f = fixture(t), j = f.open(); t.after(() => j.release()); j.begin(config); install(j);
  if (conflict === 'rule') f.tables.get('iptables/filter').push('-A CVPN-DNS-IN -j ACCEPT');
  if (conflict === 'duplicate') f.tables.get('iptables/filter').push(f.tables.get('iptables/filter')[1]);
  if (conflict === 'route') f.routes.push({ dst: '203.0.113.0/24', dev: 'eth0', scope: 'link', table: 19998 });
  if (conflict === 'policy') f.policies.push({ priority: 10996, src: 'all', table: 123 });
  if (conflict === 'interface') f.links[1].ifindex++;
  const before = f.mutations.length; assert.throws(() => j.restore()); assert.equal(f.mutations.length, before);
});

for (const [name, change] of [
  ['command', (v) => { v.command = ['iptables', '-F']; }],
  ['schema', (v) => { v.schema = 2; }],
  ['cursor', (v) => { v.count = 9999; }],
  ['hold', (v) => { v.hold = -1; }],
  ['scope', (v) => { v.config.tun = '../../eth0'; }],
  ['server', (v) => { v.config.primary = 'dns.invalid'; }],
  ['stage', (v) => { v.stage = 'execute'; }],
]) test(`malformed ${name} journal rejected before network inspection`, (t) => {
  const f = fixture(t), j = f.open(); j.begin(config); const v = j.state; j.release(); change(v);
  assert.throws(() => validateTunnelDnsJournal(v));
  fs.writeFileSync(f.path, JSON.stringify(v)); let reads = 0;
  assert.throws(() => f.open({ run: () => { reads++; throw new Error('unexpected network access'); } })); assert.equal(reads, 0);
});

test('old boot journal refuses recovery before any network access', (t) => {
  const f = fixture(t), j = f.open(); j.begin(config); const v = j.state; j.release();
  v.scope.boot = '0'.repeat(8) + '-0000-0000-0000-000000000000'; fs.writeFileSync(f.path, JSON.stringify(v));
  let reads = 0; const old = f.open({ run: () => { reads++; } }); t.after(() => old.release());
  assert.throws(() => old.restore(), /different boot/); assert.equal(reads, 0);
});

test('symlink, hardlink, large file and permissive directory cannot become recovery authority', (t) => {
  const f = fixture(t), j = f.open(); j.begin(config); j.release();
  const backup = join(f.dir, 'saved'); fs.renameSync(f.path, backup);
  fs.symlinkSync(backup, f.path); assert.throws(() => f.open()); fs.unlinkSync(f.path);
  fs.linkSync(backup, f.path); assert.throws(() => f.open()); fs.unlinkSync(f.path);
  fs.writeFileSync(f.path, ' '.repeat(16385), { mode: 0o600 }); assert.throws(() => f.open(), /size limit/);
  fs.chmodSync(f.dir, 0o755); assert.throws(() => f.open(), /0700/);
});

test('stable lifetime lock survives parent fd close while a helper is running', async (t) => {
  const f = fixture(t), j = f.open();
  const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 10000)'], { stdio: ['ignore', 'ignore', 'ignore', ...j.lockDescriptors] });
  const ended = once(child, 'exit');
  try { j.release(); assert.throws(() => f.open(), /locked/); }
  finally { child.kill('SIGKILL'); await ended; j.release(); }
  f.open().release();
});

test('second process cannot own same journal; SIGKILL releases the owner lock', (t) => {
  const f = fixture(t), j = f.open();
  const code = `import {openTunnelDnsJournal} from './scripts/lib/dns-tunnel-journal.mjs';
    openTunnelDnsJournal(${JSON.stringify(f.dir)},{coordinate:false});process.kill(process.pid,'SIGKILL');`;
  const locked = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8', timeout: 5000 });
  assert.equal(locked.status, 1); assert.match(locked.stderr, /locked/); j.release();
  const killed = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8', timeout: 5000 });
  assert.equal(killed.signal, 'SIGKILL'); f.open().release();
});
