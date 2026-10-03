import assert from 'node:assert/strict';
import test from 'node:test';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { networkdGatePath, networkdGatePaths, networkdGateText, prepareNetworkdGate, assertNetworkdGate, detachNetworkdGate, assertNetworkdClientArgs } from './lib/host-networkd-gate.mjs';

function fixture(t, { manager = 'active', otherManager = false, tun = false } = {}) {
  const root = fs.mkdtempSync(join(tmpdir(), 'meshpn-gate-test-')); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(root + '/etc/systemd/system', { recursive: true });
  const map = p => typeof p === 'string' ? root + p : p;
  const io = { ...fs, lstatSync(p) { const s = fs.lstatSync(map(p)); s.uid = 0; return s; },
    readFileSync(p, opts) { return p === '/proc/1/comm' ? 'systemd\n' : fs.readFileSync(map(p), opts); } };
  for (const name of ['mkdirSync', 'openSync', 'unlinkSync']) io[name] = (p, ...a) => fs[name](map(p), ...a);
  io.linkSync = (a, b) => fs.linkSync(map(a), map(b));
  let loaded = false, failReload = false, foreignDependency = false;
  const commands = [], path = networkdGatePath('clean-vpn');
  const ctl = (...args) => {
    commands.push(args);
    if (args[0] === 'daemon-reload') { if (failReload) throw Error('reload failure'); loaded = fs.existsSync(map(path)); return ''; }
    assert.equal(args[0], 'show'); const unit = args[1], key = args[2].slice('--property='.length);
    if (unit.startsWith('systemd-networkd.')) return ({ LoadState: 'loaded', ActiveState: manager, Requires: loaded || foreignDependency ? 'clean-vpn-killswitch.service' : '', After: loaded || foreignDependency ? 'clean-vpn-killswitch.service' : '' })[key];
    return ({ LoadState: otherManager ? 'loaded' : 'not-found', ActiveState: otherManager ? 'active' : 'inactive', UnitFileState: otherManager ? 'enabled' : '' })[key];
  };
  const run = (file, args) => file === 'ip' ? JSON.stringify([{ ifname: 'lo' }, ...(tun ? [{ ifname: 'tun0' }] : [])]) : ctl(...args.slice(1));
  return { root, path, io, run, ctl, commands, set failReload(v) { failReload = v; }, set foreignDependency(v) { foreignDependency = v; } };
}
test('networkd gate has strict scope and duplicate argument refusal', () => {
  const good = ['--role=client', '--type=tls', '--server=198.51.100.2:443', '--split-default', '--ipv6=auto'];
  assertNetworkdClientArgs(good);
  assertNetworkdClientArgs([...good, '--dns-usb=1']);
  assert.throws(() => assertNetworkdClientArgs([...good, '--dns-usb=0']));
  for (const extra of ['--type=udp', '--dns-mode=off', '--client-lan-subnet=192.168.7.0/24', '--http-vers=1.1', '--config=/tmp/a']) assert.throws(() => assertNetworkdClientArgs([...good, extra]));
  for (const bad of ['', '../bad', '-option', 'x'.repeat(201)]) assert.throws(() => networkdGatePath(bad));
});
test('networkd gate publishes only owned dependency; no network restart or firewall setter', t => {
  const f = fixture(t); prepareNetworkdGate(f);
  assert.equal(fs.readFileSync(f.root + f.path, 'utf8'), networkdGateText('clean-vpn'));
  assert.equal(networkdGatePaths('clean-vpn').length, 2);
  for (const p of networkdGatePaths('clean-vpn')) assert.equal(fs.readFileSync(f.root + p, 'utf8'), networkdGateText('clean-vpn'));
  assert.ok(f.commands.every(a => a[0] === 'show'));
  assert.throws(() => prepareNetworkdGate(f), /existing networkd gate/);
  f.ctl('daemon-reload'); assertNetworkdGate({ ...f, service: 'clean-vpn' });
  detachNetworkdGate({ ...f, service: 'clean-vpn' }); assert.equal(fs.existsSync(f.root + f.path), false);
  assert.ok(networkdGatePaths('clean-vpn').every(p => !fs.existsSync(f.root + p)));
  assert.ok(!f.commands.some(a => ['stop', 'start', 'restart'].includes(a[0])));
});
for (const options of [{ manager: 'inactive' }, { otherManager: true }, { tun: true }]) test('unsupported live environment refuses publication ' + JSON.stringify(options), t => {
  const f = fixture(t, options); assert.throws(() => prepareNetworkdGate(f)); assert.equal(fs.existsSync(f.root + f.path), false);
});
test('modified gate and cached foreign dependency refuse release', t => {
  const f = fixture(t); prepareNetworkdGate(f); f.ctl('daemon-reload');
  fs.appendFileSync(f.root + f.path, '\nRequires=foreign.service\n');
  assert.throws(() => detachNetworkdGate({ ...f, service: 'clean-vpn' }), /modified/); assert.ok(fs.existsSync(f.root + f.path));
  fs.writeFileSync(f.root + f.path, networkdGateText('clean-vpn'));
  f.foreignDependency = true; assert.throws(() => detachNetworkdGate({ ...f, service: 'clean-vpn' }), /still depends/);
});
test('failed reload after detach can be retried without deleting foreign files', t => {
  const f = fixture(t); prepareNetworkdGate(f); f.ctl('daemon-reload'); f.failReload = true;
  assert.throws(() => detachNetworkdGate({ ...f, service: 'clean-vpn' }), /reload failure/);
  f.failReload = false; detachNetworkdGate({ ...f, service: 'clean-vpn' });
});
test('unsafe gate parents refused before writes', t => {
  const f = fixture(t); fs.chmodSync(f.root + '/etc/systemd/system', 0o777);
  assert.throws(() => prepareNetworkdGate(f), /unsafe gate path/); assert.equal(fs.existsSync(f.root + f.path), false);
});
test('socket dependency must be loaded too, not merely the daemon dependency', t => {
  const f = fixture(t); prepareNetworkdGate(f); f.ctl('daemon-reload');
  assert.throws(() => assertNetworkdGate({ ...f, service: 'clean-vpn', ctl: (...args) => args[1] === 'systemd-networkd.socket' ? '' : f.ctl(...args) }), /gate not loaded/);
});
test('modified socket gate refuses before deleting either dependency', t => {
  const f = fixture(t); prepareNetworkdGate(f); f.ctl('daemon-reload');
  const socket = networkdGatePath('clean-vpn', 'systemd-networkd.socket');
  fs.appendFileSync(f.root + socket, '\nRequires=foreign.service\n');
  assert.throws(() => detachNetworkdGate({ ...f, service: 'clean-vpn' }), /modified/);
  assert.ok(networkdGatePaths('clean-vpn').every(p => fs.existsSync(f.root + p)));
});
test('pre-existing socket gate refuses before publishing daemon gate', t => {
  const f = fixture(t), socket = networkdGatePath('clean-vpn', 'systemd-networkd.socket');
  fs.mkdirSync(f.root + '/etc/systemd/system/systemd-networkd.socket.d');
  fs.writeFileSync(f.root + socket, 'foreign');
  assert.throws(() => prepareNetworkdGate(f), /existing networkd gate/);
  assert.equal(fs.existsSync(f.root + f.path), false);
});
