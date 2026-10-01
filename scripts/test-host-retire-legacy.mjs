import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { LEGACY_FILES, RETIRABLE_GUARD_HASHES, retireLegacyHost } from './lib/host-retire-legacy.mjs';

function fixture(t, options = {}) {
  const root = fs.mkdtempSync(join(tmpdir(), 'meshpn-retire-test-')); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const map = p => typeof p === 'string' ? root + p : p;
  fs.mkdirSync(map('/var'));
  for (const path of LEGACY_FILES) { fs.mkdirSync(dirname(map(path)), { recursive: true }); fs.writeFileSync(map(path), path.endsWith('killswitch.sh') ? fs.readFileSync(new URL('./autostart/killswitch.sh', import.meta.url)) : 'PRIVATE-OLD-ARGS\n', { mode: 0o644 }); }
  const commands = [], removed = [], released = [];
  const io = { ...fs, lstatSync(p) { const s = fs.lstatSync(map(p)); s.uid = 0; return s; }, fstatSync(fd) { const s = fs.fstatSync(fd); s.uid = 0; return s; },
    readFileSync(p, opts) { return p === '/proc/1/comm' ? 'systemd\n' : fs.readFileSync(map(p), opts); },
    readlinkSync(p) { return p.endsWith('/user') ? 'user:[1]' : 'net:[1]'; },
    mkdtempSync(p) { return fs.mkdtempSync(map(p)).slice(root.length); },
    unlinkSync(p) { if (options.unlinkFailure === removed.length) throw Error('injected unlink failure'); removed.push(p); fs.unlinkSync(map(p)); },
  };
  for (const name of ['mkdirSync', 'openSync', 'chmodSync']) io[name] = (p, ...args) => fs[name](map(p), ...args);
  const run = (file, args, opts) => {
    commands.push({ file, args, opts });
    if (file === 'ip') return JSON.stringify([{ ifname: 'lo' }, ...(options.tun ? [{ ifname: 'tun0' }] : [])]);
    if (file === 'iptables' || file === 'ip6tables') return '-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n-P FORWARD ACCEPT\n' + (options.rules ? '-N CLEANVPN_KS_OUT\n' : '');
    assert.equal(file, 'systemctl');
    if (args.includes('daemon-reload')) { if (options.reloadFailure) throw Error('injected reload failure'); return ''; }
    assert.equal(args[1], 'show'); const unit = args[2], index = unit === 'clean-vpn.service' ? 0 : 1;
    const props = args.find(a => a.startsWith('--property=')).slice(11).split(',');
    const result = Object.fromEntries(props.map(key => [key, '']));
    Object.assign(result, { Id: unit, LoadState: fs.existsSync(map(LEGACY_FILES[index])) ? 'loaded' : 'not-found', ActiveState: 'inactive', SubState: 'dead', UnitFileState: index ? 'static' : 'disabled', FragmentPath: LEGACY_FILES[index], MainPID: '0', ControlPID: '0', PrivateNetwork: 'no', PrivateUsers: 'no', PartOf: index ? 'clean-vpn.service' : '', ...(options.metadata?.[index] ?? {}) });
    return args.includes('--value') ? result[props[0]] : props.map(k => `${k}=${result[k]}`).join('\n');
  };
  const open = [0, 1, 2].map(i => () => {
    if (options.lockFailure === i) throw Error('lock busy');
    return { state: options.states ? options.states[i] : { stage: 'released' }, lockDescriptors: [i + 20], release() { released.push(i); } };
  });
  return { root, map, io, run, open, commands, removed, released };
}
test('legacy retirement audit never writes backup/removes files/runs old scripts', t => {
  const f = fixture(t), r = retireLegacyHost(f);
  assert.equal(r.status, 'eligible'); assert.equal(r.backupDirectory, null); assert.equal(fs.existsSync(f.map('/var/backups')), false);
  assert.deepEqual(f.removed, []); assert.deepEqual(f.released, [2, 1, 0]);
  assert.ok(f.commands.every(c => ['systemctl', 'ip', 'iptables', 'ip6tables'].includes(c.file) && !c.args.includes('daemon-reload')));
  assert.doesNotMatch(JSON.stringify(r), /PRIVATE-OLD-ARGS/);
});
test('apply creates complete private durable backup then removes exactly four files and reloads only', t => {
  const f = fixture(t), originals = LEGACY_FILES.map(p => fs.readFileSync(f.map(p)));
  const r = retireLegacyHost({ ...f, apply: true }); assert.equal(r.status, 'retired');
  assert.equal(fs.statSync(f.map(r.backupDirectory)).mode & 0o777, 0o700);
  for (const [i, path] of LEGACY_FILES.entries()) {
    const backup = f.map(`${r.backupDirectory}/${basename(path)}`);
    assert.deepEqual(fs.readFileSync(backup), originals[i]); assert.equal(fs.statSync(backup).mode & 0o777, 0o600);
    assert.equal(fs.existsSync(f.map(path)), false);
  }
  assert.equal(JSON.parse(fs.readFileSync(f.map(r.backupDirectory + '/manifest.json'))).files.length, 4);
  assert.deepEqual(f.removed, LEGACY_FILES); assert.deepEqual(f.released, [2, 1, 0]);
  const mutations = f.commands.filter(c => c.file === 'systemctl' && c.args[1] !== 'show');
  assert.deepEqual(mutations.map(c => c.args), [['--no-pager', 'daemon-reload']]);
  assert.deepEqual(mutations[0].opts.lockDescriptors, [20, 21, 22]);
});
for (const metadata of [{ ActiveState: 'active' }, { ActiveState: 'failed' }, { UnitFileState: 'enabled' }, { MainPID: '12' }, { Job: '1/start' }, { DropInPaths: '/etc/override' }, { TriggeredBy: 'timer' }, { WantedBy: 'multi-user.target' }, { RequiredBy: 'foreign.service' }, { NetworkNamespacePath: '/run/netns/other' }]) test('refuses unsafe unit before backup ' + JSON.stringify(metadata), t => {
  const f = fixture(t, { metadata: { 0: metadata } }); assert.throws(() => retireLegacyHost({ ...f, apply: true })); assert.deepEqual(f.removed, []); assert.equal(fs.existsSync(f.map('/var/backups')), false);
});
for (const options of [{ tun: true }, { rules: true }, { states: [{ stage: 'released' }, { stage: 'restoring' }, null] }, { lockFailure: 1 }]) test('refuses active/uncertain network before backup ' + JSON.stringify(options), t => {
  const f = fixture(t, options); assert.throws(() => retireLegacyHost({ ...f, apply: true })); assert.deepEqual(f.removed, []); assert.equal(fs.existsSync(f.map('/var/backups')), false); assert.ok(f.released.includes(0));
});
for (const kind of ['unknown', 'symlink', 'hardlink', 'writable', 'missing']) test('refuses unsafe or partial installed files ' + kind, t => {
  const f = fixture(t), path = f.map(LEGACY_FILES[3]);
  if (kind === 'unknown') fs.writeFileSync(path, 'unknown guard');
  if (kind === 'symlink') { fs.renameSync(path, path + '.old'); fs.symlinkSync(path + '.old', path); }
  if (kind === 'hardlink') fs.linkSync(path, path + '.old');
  if (kind === 'writable') fs.chmodSync(path, 0o666);
  if (kind === 'missing') fs.unlinkSync(path);
  assert.throws(() => retireLegacyHost({ ...f, apply: true })); assert.deepEqual(f.removed, []);
});
test('changed installed file after backup preparation refuses all deletion', t => {
  const f = fixture(t);
  assert.throws(() => retireLegacyHost({ ...f, apply: true, onProgress() { fs.appendFileSync(f.map(LEGACY_FILES[2]), 'changed'); } }), /installed file changed/);
  assert.deepEqual(f.removed, []);
});
for (const failure of ['write', 'fsync']) test('backup failure never removes installed files: ' + failure, t => {
  const f = fixture(t); let backupStarted = false;
  if (failure === 'write') f.io.writeFileSync = () => { throw Error('injected backup write failure'); };
  else f.io.fsyncSync = fd => { if (backupStarted) throw Error('injected backup fsync failure'); fs.fsyncSync(fd); };
  assert.throws(() => retireLegacyHost({ ...f, apply: true, onProgress() { backupStarted = true; } }), /injected backup/);
  assert.deepEqual(f.removed, []); assert.ok(LEGACY_FILES.every(p => fs.existsSync(f.map(p))));
  assert.deepEqual(f.released, [2, 1, 0]);
});
test('existing networkd gate prevents retirement', t => {
  const f = fixture(t), p = f.map('/etc/systemd/system/systemd-networkd.socket.d/90-clean-vpn-clean-vpn.conf');
  fs.mkdirSync(dirname(p)); fs.writeFileSync(p, 'existing gate');
  assert.throws(() => retireLegacyHost({ ...f, apply: true }), /networkd integration/);
  assert.deepEqual(f.removed, []); assert.equal(fs.existsSync(f.map('/var/backups')), false);
});
test('group-writable parent prevents retirement', t => {
  const f = fixture(t); fs.chmodSync(f.map('/usr/local/bin'), 0o777);
  assert.throws(() => retireLegacyHost({ ...f, apply: true }), /unsafe retirement path/);
  assert.deepEqual(f.removed, []);
});
for (const unlinkFailure of [0, 1, 2, 3, undefined]) test('partial unlink/reload failure retains every backup and reports progress ' + unlinkFailure, t => {
  const f = fixture(t, { unlinkFailure, reloadFailure: unlinkFailure === undefined });
  let report;
  assert.throws(() => retireLegacyHost({ ...f, apply: true }), e => { report = e.retirement; return true; });
  assert.ok(report.backupDirectory); assert.equal(report.removedPaths.length, unlinkFailure ?? 4);
  for (const path of LEGACY_FILES) assert.ok(fs.existsSync(f.map(report.backupDirectory + '/' + basename(path))));
  assert.deepEqual(f.released, [2, 1, 0]);
});
test('guard allowlist pins the reported legacy and the real current fixture bytes', () => {
  assert.ok(RETIRABLE_GUARD_HASHES.has('5b99335723dcab4a1c3b472307e61bb082496b81ab9e73d9f9ca75139f25172e'));
  assert.ok(RETIRABLE_GUARD_HASHES.has(createHash('sha256').update(fs.readFileSync(new URL('./autostart/killswitch.sh', import.meta.url))).digest('hex')));
});
test('CLI rejects mutating/unknown args without invoking retirement', () => {
  for (const args of [['--help'], ['--apply', '--apply'], ['--service=other']]) {
    const r = spawnSync(process.execPath, ['scripts/clean-vpn-retire-legacy.mjs', ...args], { timeout: 5000, encoding: 'utf8' });
    assert.equal(r.status, args[0] === '--help' ? 0 : 1); assert.doesNotMatch(r.stdout + r.stderr, /"backupDirectory"/);
  }
});
