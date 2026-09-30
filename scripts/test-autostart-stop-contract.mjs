import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { uninstallHostService } from './lib/host-uninstall.mjs';
import { assertHostSystemdVm, hostSystemdVmUnits, HOST_SYSTEMD_CHECKS, assertHostSystemdEvidence } from './lib/vpn-host-systemd-vm.mjs';

test('host systemd evidence requires the complete actual-unit cycle without deployment approval', () => {
  const e = { status: 'passed', actualTransportTested: 'tls-ipv6', hostNetworkChanged: false, checks: [...HOST_SYSTEMD_CHECKS],
    hostSystemd: { systemdPid1: true, actualInstaller: true, acceptance: 'not-ready-for-deployment',
      limitations: ['fixture-network-namespace-dropins', 'no-early-boot-or-reboot', 'explicit-recovery-not-auto-restart'] } };
  assertHostSystemdEvidence(e);
  for (let i = 0; i < e.checks.length; i++) assert.throws(() => assertHostSystemdEvidence({ ...e, checks: e.checks.filter((_, j) => i !== j) }));
  for (const field of ['systemdPid1', 'actualInstaller', 'acceptance', 'limitations'])
    assert.throws(() => assertHostSystemdEvidence({ ...e, hostSystemd: { ...e.hostSystemd, [field]: false } }));
  assert.throws(() => assertHostSystemdEvidence({ ...e, hostNetworkChanged: true }));
});

test('real-systemd host lab refuses execution on the development host', async () => {
  assert.throws(() => assertHostSystemdVm());
  const { runHostSystemdChecks } = await import('./lib/vpn-host-systemd-lab.mjs');
  await assert.rejects(runHostSystemdChecks({}));
  const child = spawnSync(process.execPath, ['scripts/lib/vpn-host-systemd-driver.mjs'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(child.status, 1);
  assert.match(child.stderr, /meshpn\.host-systemd/);
  assert.doesNotMatch(child.stdout, /INGRESS_VM_PASS/);
});
test('systemd fixture uses its own driver, not a replacement VPN unit', () => {
  const units = hostSystemdVmUnits();
  assert.ok(!Object.keys(units).some(n => n.startsWith('clean-vpn')));
  assert.match(units['host-vm-driver.service'], /vpn-host-systemd-driver\.mjs/);
  assert.match(units['host-vm-driver.service'], /TimeoutStartSec=20min/);
  assert.match(units['default.target'], /Wants=host-vm-driver.service/);
});
test('host systemd VM rejects incompatible selections before building an image', () => {
  const base = ['scripts/ingress-vm-lab.mjs', '--tools=/not-used', '--kernel=/not-used', '--resolved=/not-used', '--host-systemd'];
  for (const flags of [[], ['--ipv6'], ['--dns-conntrack=/not-used'],
    ['--ipv6', '--dns-conntrack=/not-used', '--host-joint'],
    ['--ipv6', '--dns-conntrack=/not-used', '--dns-host-only']]) {
    const child = spawnSync(process.execPath, [...base, ...flags], { encoding: 'utf8', timeout: 5000 });
    assert.equal(child.status, 1);
    assert.match(child.stderr, /invalid host systemd combination/);
    assert.doesNotMatch(child.stderr, /Ingress VM artifacts/);
  }
});

test('autostart unit template leaves all three rollback budgets and signals main process first', () => {
  const source = readFileSync(new URL('./autostart/install.sh', import.meta.url), 'utf8');
  const unit = source.split('cat > "$UNIT_PATH" <<EOF\n')[1]?.split('\nEOF')[0];
  assert.ok(unit, 'main service template exists');
  assert.match(unit, /^KillMode=mixed$/m);
  const timeout = /^TimeoutStopSec=(\d+)$/m.exec(unit);
  assert.ok(timeout); assert.ok(Number(timeout[1]) >= 120 + 120 + 120 + 60);
  assert.match(unit, /^Restart=always$/m);
  assert.match(unit, /^ExecStart=\$RUN_SH$/m);
  // This is a template contract, not an actual PID1/boot lifecycle test.
});
test('installer validates guard configuration before writes and passes management port', () => {
  const source = readFileSync(new URL('./autostart/install.sh', import.meta.url), 'utf8');
  const preflight = source.indexOf('bash "$KS_SRC" plan');
  assert.ok(preflight > 0 && preflight < source.indexOf('cat > "$RUN_SH"'));
  assert.match(source, /KS_SSH_PORT="\$\{KS_SSH_PORT:-22\}"/);
  assert.match(source, /KS_UP_ARGS="up .*--ssh-port=\$KS_SSH_PORT"/);
});
test('shell uninstaller delegates to the journal-gated implementation', () => {
  const source = readFileSync(new URL('./autostart/uninstall.sh', import.meta.url), 'utf8');
  assert.match(source, /exec "\$NODE_BIN" .*clean-vpn-uninstall\.mjs/);
  assert.doesNotMatch(source, /systemctl|rm -f| down /);
});

function uninstallFixture({ states = [null, {stage:'released'}, {stage:'released'}], openError = -1,
  fail = '', tied = false, wrongNamespace = false, customDns = false, partial = false, stillActive = false,
  metadata = {}, guardStopFailed = false } = {}) {
  const calls = [], held = new Set(), removed = [];
  const options = { log() {}, io: {
    lstatSync(path) { if (partial && path.endsWith('-run.sh')) throw Object.assign(Error('missing'), {code:'ENOENT'});
      return { isFile: () => true, isSymbolicLink: () => false }; },
    statSync(path) { return { dev: 1, ino: wrongNamespace && path !== '/proc/self/ns/net' ? 2 : 1 }; },
    readFileSync() { return customDns ? 'exec node clean-vpn.js --dns-state-dir=/private/custom' : 'exec node clean-vpn.js'; },
    unlinkSync(path) { assert.equal(held.size, 3); removed.push(path); },
  }, open: states.map((state, n) => () => {
    calls.push(`open:${n}`); if (n === openError) throw Error('corrupt or busy journal');
    held.add(n); return { state, lockDescriptors: [n + 10], release() { held.delete(n); } };
  }), run(file, args, opts) {
    const command = [file, ...args].join(' '); calls.push(command);
    if (fail && command.includes(fail)) throw Error('injected command failure');
    if (args.includes('show')) return Object.entries({ LoadState: 'loaded', ActiveState: guardStopFailed && args.includes('clean-vpn-killswitch.service') ? 'failed' : stillActive ? 'active' : 'inactive',
      PartOf: tied && args.includes('clean-vpn-killswitch.service') ? 'clean-vpn.service' : '', BindsTo: '',
      NetworkNamespacePath: '', PrivateNetwork: 'no', PrivateUsers: 'no', RootDirectory: '', RootImage: '',
      BindPaths: '', BindReadOnlyPaths: '', TemporaryFileSystem: '', Requires: '', Requisite: '', Conflicts: '',
      PropagatesStopTo: '', StopWhenUnneeded: 'no', ...metadata }).map(([k,v])=>`${k}=${v}`).join('\n');
    if (command.includes('stop clean-vpn-killswitch') || args.includes('down') || args.includes('disable')) {
      assert.equal(held.size, 3); assert.deepEqual(opts.lockDescriptors, [10,11,12]);
    }
    return '';
  } };
  return { options, calls, held, removed };
}
test('uninstall holds all released/absent journal locks through guard removal and file deletion', () => {
  const f = uninstallFixture();
  assert.equal(uninstallHostService(f.options).status, 'uninstalled');
  assert.equal(f.removed.length, 4); assert.equal(f.held.size, 0);
  assert.ok(f.calls.indexOf('open:2') < f.calls.findIndex(c=>c.includes('stop clean-vpn-killswitch')));
});
for (const stage of ['active', 'installing', 'restoring', 'parked']) for (let index = 0; index < 3; index++)
  test(`uninstall refuses journal ${index}/${stage} even if systemctl stop succeeded`, () => {
    const states = [null,null,null]; states[index] = {stage}; const f = uninstallFixture({states});
    assert.throws(()=>uninstallHostService(f.options), /unfinished VPN journal/);
    assert.deepEqual(f.removed, []); assert.equal(f.held.size, 0);
    assert.ok(!f.calls.some(c=>c.includes('stop clean-vpn-killswitch') || c.includes(' down ') || c.includes('disable')));
  });
for (const index of [0,1,2]) test(`uninstall retains guard on unreadable/locked journal ${index}`, () => {
  const f = uninstallFixture({openError:index}); assert.throws(()=>uninstallHostService(f.options), /corrupt or busy/);
  assert.equal(f.held.size, 0); assert.deepEqual(f.removed, []);
  assert.ok(!f.calls.some(c=>c.includes('stop clean-vpn-killswitch')));
});
for (const scenario of [{tied:true}, {wrongNamespace:true}, {customDns:true}, {partial:true},
  {metadata:{PrivateNetwork:'yes'}}, {metadata:{PrivateUsers:'yes'}}, {metadata:{RootDirectory:'/other'}},
  {metadata:{BindPaths:'/other:/run'}}, {metadata:{LoadState:'not-found'}}, {metadata:{StopWhenUnneeded:'yes'}},
  {metadata:{Requires:'clean-vpn.service'}}, {metadata:{PropagatesStopTo:'clean-vpn-killswitch.service'}}])
  test(`unsupported uninstall scope refuses before stop: ${JSON.stringify(scenario)}`, () => {
    const f=uninstallFixture(scenario); assert.throws(()=>uninstallHostService(f.options));
    assert.ok(!f.calls.some(c=>c.includes(' stop '))); assert.deepEqual(f.removed, []);
  });
for (const fail of ['stop clean-vpn.service', 'stop clean-vpn-killswitch.service', ' down ', 'disable'])
  test(`uninstall retains files on command failure: ${fail}`, () => {
    const f=uninstallFixture({fail}); assert.throws(()=>uninstallHostService(f.options), /injected/);
    assert.deepEqual(f.removed, []); assert.equal(f.held.size, 0);
  });
test('uninstall refuses a main unit still active after stop', () => {
  const f=uninstallFixture({stillActive:true}); assert.throws(()=>uninstallHostService(f.options), /VPN is not stopped/);
  assert.deepEqual(f.removed, []); assert.equal(f.held.size, 0);
});
test('uninstall retains rules/files when stop returns success but guard unit failed', () => {
  const f = uninstallFixture({ guardStopFailed: true });
  assert.throws(() => uninstallHostService(f.options), /guard stop failed/);
  assert.equal(f.held.size, 0); assert.deepEqual(f.removed, []);
  assert.ok(!f.calls.some(c => c.includes(' down ') || c.includes('disable')));
});
test('uninstall service name and CLI reject unsafe input before touching installed units', () => {
  for (const service of ['../other', '--help', '', 'x\nother', 'x'.repeat(201)]) {
    const f=uninstallFixture(); assert.throws(()=>uninstallHostService({...f.options, service}));
    assert.deepEqual(f.calls, []); assert.deepEqual(f.removed, []);
  }
  const p=spawnSync('/bin/bash', ['scripts/autostart/uninstall.sh', '--force'], {
    env: {...process.env, NODE_BIN: process.execPath}, encoding:'utf8', timeout:5000 });
  assert.equal(p.status, 1); assert.match(p.stderr, /root required|no command-line options accepted/);
  assert.equal(p.stdout, '');
});
