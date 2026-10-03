import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { upgradeUsbDnsGuard, usbDnsWrapper, legacyUsbGuardHash, legacyUsbSnatHash } from './lib/host-usb-dns-upgrade.mjs';
import { gatewayFiles, gatewayHelper, gatewayUnit, gatewayUnitPath } from './lib/host-usb-gateway.mjs';
import { rescueFiles } from './lib/host-usb-rescue.mjs';

const guardPath = '/usr/local/bin/clean-vpn-killswitch.sh';
const guardUnitPath = '/etc/systemd/system/clean-vpn-killswitch.service';
const oldUnit = 'ExecStart=/usr/local/bin/clean-vpn-killswitch.sh up --scope=both --ipv6=block --tun=tun0 --ssh-port=22 --server=154.62.226.216\n';
const newUnit = oldUnit.trim() + ' --usb-dns=1 --usb-strict=1\n';
const wrapperPath = '/usr/local/bin/clean-vpn-run.sh';
const oldWrapper = '#!/usr/bin/env bash\nset -euo pipefail\nexport PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin"\ncd "/repo"\nexec "/usr/bin/node" "/repo/scripts/clean-vpn.js" --role=client --type=tls --split-default --ipv6=auto --server=154.62.226.216:443\n';
const newWrapper = usbDnsWrapper(oldWrapper);
const sourceGuard = fileURLToPath(new URL('./autostart/killswitch.sh', import.meta.url));
const sourceSnat = fileURLToPath(new URL('./clean-vpn-usb-snat.mjs', import.meta.url));
const currentGuard = fs.readFileSync(sourceGuard, 'utf8'), currentSnat = fs.readFileSync(sourceSnat, 'utf8');
const oldGuard = fs.readFileSync(new URL('./fixtures/usb-dns-v2-guard.txt', import.meta.url), 'utf8');
const oldSnat = fs.readFileSync(new URL('./fixtures/usb-dns-v2-snat.txt', import.meta.url), 'utf8');

function fixture({ snat = true, upgraded = false } = {}) {
  const files = new Map([[sourceGuard, currentGuard], [sourceSnat, currentSnat], [guardPath, upgraded ? currentGuard : oldGuard], ...Object.entries(rescueFiles)]);
  files.set(guardUnitPath, upgraded ? newUnit : oldUnit);
  files.set(wrapperPath, upgraded ? newWrapper : oldWrapper);
  if (snat) { files.set(gatewayHelper, upgraded ? currentSnat : oldSnat); files.set(gatewayUnitPath, gatewayFiles('/usr/bin/node')[gatewayUnitPath]); }
  const f = { files, calls: [], versions: upgraded ? [4, 4] : [2, 2], main: 'active', snatActive: snat ? 'active' : 'inactive',
    badDrop: '', unsafe: '', journalFail: false, upFail: false, publishFail: false, unitPublishFail: false, wrapperPublishFail: false, reloadFail: false, pendingReload: false, profileFail: false };
  f.read = p => { assert.notEqual(p, f.unsafe, 'unsafe path'); return files.get(p) ?? null; };
  f.inspectProfile = opts => { assert.ok(!f.profileFail, 'foreign profile'); assert.equal(opts.guardSource, files.get(guardPath)); };
  f.run = (tool, args) => {
    f.calls.push([tool, ...args]);
    if (tool === 'ip') return JSON.stringify([{ ifname: 'usb0', address: '02:00:00:00:00:02', flags: ['UP'], addr_info: [{ family: 'inet', local: '192.168.7.1', prefixlen: 24 }] }]);
    if (tool === guardPath) {
      if (args[0] === 'status') return f.versions.map((v, i) => `[clean-vpn-killswitch] IPv${i ? 6 : 4}: cvks${v}:both:block:tun0:154.62.226.216:22`).join('\n');
      assert.equal(args[0], 'up'); assert.ok(args.includes('--usb-dns=1')); assert.equal(files.get(guardUnitPath), newUnit);
      assert.equal(f.main, 'inactive'); assert.equal(f.snatActive, 'inactive');
      assert.equal(files.get(guardPath), currentGuard); f.versions[1] = 4;
      assert.ok(!f.upFail, 'injected IPv4 commit failure'); f.versions[0] = 4; return '';
    }
    assert.equal(tool, 'systemctl');
    if (args[0] === 'daemon-reload') { assert.ok(!f.reloadFail, 'reload failure'); f.pendingReload = false; return ''; }
    const name = args[1]?.replace('@inspection.service', '@.service');
    const present = name === gatewayUnit ? files.has(gatewayUnitPath) : true;
    if (args[0] === 'is-active') return 'active';
    if (args[0] === 'stop') { assert.equal(name, gatewayUnit); f.snatActive = 'inactive'; return ''; }
    assert.equal(args[0], 'show');
    return ({ LoadState: present ? 'loaded' : 'not-found', FragmentPath: present ? '/etc/systemd/system/' + name : '',
      DropInPaths: f.badDrop, NeedDaemonReload: name === 'clean-vpn-killswitch.service' && f.pendingReload ? 'yes' : 'no', ActiveState: name === gatewayUnit ? f.snatActive : 'active' })[args[2].slice(11)];
  };
  f.lifecycle = (options, action) => {
    options.beforeStop({}); f.calls.push(['stop-main-with-guard-retained']); f.main = 'inactive';
    assert.ok(!f.journalFail, 'unfinished journal');
    return action({ command: f.run, ctl: (...args) => f.run('systemctl', args), inspect: () => ({ ActiveState: 'active' }) });
  };
  f.publish = (path, before, after, checkpoint, mode) => {
    assert.equal(files.get(path), before); f.calls.push(['publish', path]); files.set(path, after);
    if (path === guardUnitPath) { assert.equal(mode, 0o644); f.pendingReload = true; assert.ok(!f.unitPublishFail, 'unit publication failure'); }
    if (path === wrapperPath) assert.ok(!f.wrapperPublishFail, 'wrapper publication failure');
    assert.ok(!f.publishFail, 'injected crash after rename'); return { backupDirectory: '/fixture/backup' };
  };
  return f;
}
const mutations = f => f.calls.filter(c => c[0] === 'publish' || c[0] === 'stop-main-with-guard-retained' || c[1] === 'stop' || c[1] === 'up');
test('pinned legacy fixtures are exact previously deployed sources', () => {
  for (const [s, h] of [[oldGuard, legacyUsbGuardHash], [oldSnat, legacyUsbSnatHash]])
    assert.equal(createHash('sha256').update(s).digest('hex'), h);
});
test('upgrade plan is readonly; current protected installation is idempotent even with --apply', () => {
  const f = fixture(); assert.equal(upgradeUsbDnsGuard(f).status, 'planned'); assert.deepEqual(mutations(f), []);
  const current = fixture({ upgraded: true }); assert.equal(upgradeUsbDnsGuard({ ...current, apply: true }).status, 'already-protected');
  assert.deepEqual(mutations(current), []);
});
for (const snat of [false, true]) test(`upgrade preserves rescue/guard/network, SNAT installed=${snat}`, () => {
  const f = fixture({ snat }); const r = upgradeUsbDnsGuard({ ...f, apply: true });
  assert.equal(r.status, 'upgraded-stopped'); assert.equal(f.main, 'inactive'); assert.equal(f.snatActive, 'inactive');
  assert.deepEqual(f.versions, [4, 4]); assert.equal(f.files.get(guardPath), currentGuard);
  assert.equal(f.files.get(guardUnitPath), newUnit);
  assert.equal(f.files.get(wrapperPath), newWrapper);
  assert.equal(f.files.get(gatewayHelper), snat ? currentSnat : undefined);
  for (const [p, text] of Object.entries(rescueFiles)) assert.equal(f.files.get(p), text);
  assert.deepEqual(r.startUnits, ['clean-vpn.service', ...(snat ? [gatewayUnit] : [])]);
  assert.ok(!f.calls.some(c => c.includes('down') || c.includes('restart') || c.includes('disable') || c.includes('start')));
  assert.deepEqual(f.calls.filter(c => c[1] === 'stop'), snat ? [['systemctl', 'stop', gatewayUnit]] : []);
  assert.ok(f.calls.findIndex(c => c[0] === 'stop-main-with-guard-retained') < f.calls.findIndex(c => c[0] === 'publish'));
});
for (const [name, mutate] of Object.entries({
  unknownGuard: f => f.files.set(guardPath, 'foreign'), unknownSnat: f => f.files.set(gatewayHelper, 'foreign'),
  partialSnat: f => f.files.delete(gatewayUnitPath), foreignSnatUnit: f => f.files.set(gatewayUnitPath, 'foreign'),
  editedRescue: f => f.files.set(Object.keys(rescueFiles)[0], 'foreign'),
  unitDropIn: f => { f.badDrop = '/foreign'; }, unsafeSource: f => { f.unsafe = sourceGuard; },
  foreignProfile: f => { f.profileFail = true; }, missingGuardFamily: f => { f.versions[1] = 9; },
})) test(`refuse ${name} before stopping or publication`, () => {
  const f = fixture(); mutate(f); assert.throws(() => upgradeUsbDnsGuard({ ...f, apply: true })); assert.deepEqual(mutations(f), []);
});
test('unfinished journals prevent publication and firewall mutations', () => {
  const f = fixture(); f.journalFail = true;
  assert.throws(() => upgradeUsbDnsGuard({ ...f, apply: true }), /unfinished journal/);
  assert.deepEqual(mutations(f), [['stop-main-with-guard-retained']]); assert.deepEqual(f.versions, [2, 2]);
});
for (const fault of ['publishFail', 'unitPublishFail', 'wrapperPublishFail', 'reloadFail', 'upFail']) test(`${fault}: no down/rollback; explicit retry completes partial upgrade`, () => {
  const f = fixture(); f[fault] = true;
  assert.throws(() => upgradeUsbDnsGuard({ ...f, apply: true }));
  assert.equal(f.main, 'inactive'); assert.equal(f.files.get(gatewayHelper), oldSnat);
  assert.equal(f.files.get(guardPath), currentGuard); assert.ok(!f.calls.some(c => c.includes('down') || c.includes('restart')));
  f[fault] = false;
  assert.equal(upgradeUsbDnsGuard({ ...f, apply: true }).status, 'upgraded-stopped'); assert.deepEqual(f.versions, [4, 4]);
});
test('wrapper update adds only fixed DNS scope, rejects disabling/conflicting scope', () => {
  assert.equal(usbDnsWrapper(newWrapper), newWrapper);
  assert.equal(newWrapper, oldWrapper.trimEnd() + ' --dns-usb=1\n');
  for (const arg of ['--dns-mode=off', '--dns-usb=0', '--dns-usb=1 --dns-usb=1', '--client-lan-subnet=192.168.7.0/24'])
    assert.throws(() => usbDnsWrapper(oldWrapper.trimEnd() + ' ' + arg + '\n'));
});
test('installer dispatches explicit DNS upgrade before fresh-install gate', () => {
  const s = fs.readFileSync(new URL('./autostart/install.sh', import.meta.url), 'utf8');
  assert.ok(s.indexOf('"$1" == --upgrade-usb-dns') < s.indexOf('clean-vpn-install-check.mjs'));
});
