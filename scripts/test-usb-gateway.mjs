import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { gatewayFiles, gatewayUnit, gatewayUnitPath, gatewayHelper, installUsbGateway,
  inspectUsbGateway, removeUsbGateway } from './lib/host-usb-gateway.mjs';
import { rescueFiles } from './lib/host-usb-rescue.mjs';
import { assertInstalledUsbGatewayProfile } from './clean-vpn-usb-gateway.mjs';

function fixture({ installed = false, rescueInstalled = true } = {}) {
  const node = '/usr/bin/node', files = new Map([[node, 'node'], ...Object.entries(rescueInstalled ? rescueFiles : {}),
    ...Object.entries(installed ? gatewayFiles(node) : {})]);
  const writes = [], calls = [], units = new Map();
  const refresh = () => {
    for (const p of files.keys()) if (p.endsWith('.service') || p.endsWith('.socket')) units.set(p.split('/').at(-1), p);
  }; refresh();
  const f = { files, writes, calls, units, node, forwarding: '1', foreignDrop: '', unsafe: '', natFail: false, active: 'active' };
  const directories = new Set(['/', '/usr', '/usr/bin', '/usr/local', '/usr/local/lib', '/etc', '/etc/systemd', '/etc/systemd/system', '/usr/local/bin']);
  let serial = 0; const descriptors = new Map();
  f.io = {
    lstatSync: p => {
      if (!directories.has(p) && !files.has(p)) throw Object.assign(Error(p), { code: 'ENOENT' });
      return { isSymbolicLink: () => false, isDirectory: () => directories.has(p), isFile: () => files.has(p),
        uid: p === f.unsafe ? 1001 : 0, mode: p === node ? 0o755 : 0o644, nlink: 1 };
    },
    readFileSync: p => { assert.ok(files.has(p), p); return files.get(p); },
    mkdtempSync: prefix => { const path = prefix + ++serial; directories.add(path); return path; },
    openSync: (p, flag) => { if (flag === 'wx') { assert.ok(!files.has(p)); files.set(p, ''); } const fd = ++serial; descriptors.set(fd, p); return fd; },
    writeFileSync: (fd, s) => { files.set(descriptors.get(fd), s); }, fchmodSync() {}, fsyncSync() {}, closeSync() {},
    linkSync: (from, to) => { assert.ok(!files.has(to)); files.set(to, files.get(from)); writes.push(to); },
    unlinkSync: p => { files.delete(p); writes.push('remove:' + p); }, rmdirSync: p => directories.delete(p), existsSync: p => files.has(p),
  };
  f.run = (tool, args) => {
    calls.push([tool, ...args]);
    if (tool === 'ip') return JSON.stringify([{ ifname: 'usb0', address: '02:00:00:00:00:02', flags: ['UP'],
      addr_info: [{ family: 'inet', local: '192.168.7.1', prefixlen: 24 }] }]);
    if (tool === 'sysctl') return f.forwarding;
    assert.equal(tool, 'systemctl');
    if (args[0] === 'show') {
      const name = args[1].replace('@inspection.service', '@.service'), path = units.get(name);
      return ({ LoadState: path ? 'loaded' : 'not-found', FragmentPath: path || '', DropInPaths: f.foreignDrop,
        NeedDaemonReload: 'no', ActiveState: path ? f.active : 'inactive' })[args[2].slice(11)];
    }
    if (args[0] === 'daemon-reload') { units.clear(); refresh(); }
    if (args[0] === 'is-active') return 'active';
    if (args[0] === 'stop') f.active = 'inactive';
    return '';
  };
  f.rescue = ({ apply }) => { calls.push(['rescue', apply]); if (apply) { for (const [p, s] of Object.entries(rescueFiles)) files.set(p, s); refresh(); } };
  f.snat = opts => { calls.push(['snat', opts]); assert.ok(!f.natFail, 'foreign NAT'); return {}; };
  return f;
}

test('gateway unit retries delayed VPN without any main/guard/network restart or stop coupling', () => {
  const text = gatewayFiles('/usr/bin/node')[gatewayUnitPath];
  assert.match(text, /Restart=on-failure\nRestartSec=5/);
  assert.match(text, /Type=oneshot/); assert.match(text, /RemainAfterExit=yes/);
  assert.match(text, /WantedBy=multi-user.target/);
  assert.doesNotMatch(text, /ExecStop=|Requires=|PartOf=|BindsTo=|sysctl|networkd|usb-gadget/);
});
test('dry-run installs nothing; fresh preparation publishes rescue before SNAT and does not enable SNAT', () => {
  const f = fixture({ rescueInstalled: false });
  assert.equal(installUsbGateway(f).status, 'planned'); assert.equal(f.writes.length, 0);
  assert.equal(installUsbGateway({ ...f, apply: true, prepareOnly: true }).status, 'prepared');
  assert.ok(f.calls.some(c => c[0] === 'rescue' && c[1] === true));
  assert.ok(!f.calls.some(c => c[1] === 'enable' && c[2] === gatewayUnit));
  assert.equal(f.files.get(gatewayHelper), gatewayFiles(f.node)[gatewayHelper]);
});
test('additive install and repeated install preserve existing rescue and only enable/start own SNAT', () => {
  const f = fixture(), rescueBefore = Object.entries(rescueFiles).map(([p]) => f.files.get(p));
  assert.equal(installUsbGateway({ ...f, apply: true }).status, 'enabled-waiting-for-vpn');
  assert.ok(f.calls.some(c => c.join(' ') === `systemctl start --no-block ${gatewayUnit}`));
  const written = f.writes.length;
  installUsbGateway({ ...f, apply: true }); assert.equal(f.writes.length, written);
  assert.deepEqual(Object.entries(rescueFiles).map(([p]) => f.files.get(p)), rescueBefore);
  assert.ok(!f.calls.some(c => c.includes('restart') || c.includes('stop')));
});
for (const [name, mutate] of Object.entries({
  foreignHelper: f => f.files.set(gatewayHelper, 'foreign'),
  foreignRescue: f => f.files.set(Object.keys(rescueFiles)[0], 'foreign'),
  partialRescue: f => f.files.delete(Object.keys(rescueFiles)[0]),
  partialGateway: f => f.files.set(gatewayUnitPath, gatewayFiles(f.node)[gatewayUnitPath]),
  foreignUnit: f => f.units.set(gatewayUnit, '/usr/lib/systemd/system/' + gatewayUnit),
  overrides: f => { f.foreignDrop = '/etc/foreign.conf'; },
  unsafeNode: f => { f.unsafe = f.node; }, forwardingOff: f => { f.forwarding = '0'; },
  foreignNat: f => { f.natFail = true; },
})) test(`refuses ${name} before publication or service mutations`, () => {
  const f = fixture(); mutate(f);
  assert.throws(() => installUsbGateway({ ...f, apply: true })); assert.equal(f.writes.length, 0);
  assert.ok(!f.calls.some(c => ['enable', 'start', 'stop', 'daemon-reload'].includes(c[1])));
});
test('remove stops only SNAT, deletes only its rule/files and preserves rescue', () => {
  const f = fixture({ installed: true });
  assert.ok(inspectUsbGateway(f));
  assert.equal(removeUsbGateway(f).status, 'planned-removal'); assert.equal(f.writes.length, 0);
  assert.equal(removeUsbGateway({ ...f, apply: true }).status, 'removed');
  assert.ok(Object.entries(rescueFiles).every(([p, s]) => f.files.get(p) === s));
  assert.ok(!f.files.has(gatewayUnitPath) && !f.files.has(gatewayHelper));
  assert.deepEqual(f.calls.filter(c => c[1] === 'stop'), [['systemctl', 'stop', gatewayUnit]]);
  assert.equal(removeUsbGateway(f).status, 'not-installed');
});
test('general installer has opt-in fresh path and additive existing path; uninstall hooks precede guard removal', () => {
  const installer = fs.readFileSync(new URL('./autostart/install.sh', import.meta.url), 'utf8');
  assert.ok(installer.indexOf('"$1" == --usb-gateway') < installer.indexOf('clean-vpn-install-check.mjs'));
  assert.ok(installer.indexOf('--prepare --apply') < installer.indexOf('cat > "$RUN_SH"'));
  assert.ok(installer.indexOf('systemctl enable clean-vpn-usb-snat.service') > installer.indexOf('systemctl enable "$KS_UNIT_NAME"'));
  const uninstall = fs.readFileSync(new URL('./lib/host-uninstall.mjs', import.meta.url), 'utf8');
  assert.ok(uninstall.indexOf('removeExtras();') < uninstall.indexOf('if (gated) detachNetworkdGate'));
});

test('additive CLI validates the actual generated main/guard templates and refuses different profiles', () => {
  const installer = fs.readFileSync(new URL('./autostart/install.sh', import.meta.url), 'utf8');
  const mainPath = '/etc/systemd/system/clean-vpn.service', guardPath = '/etc/systemd/system/clean-vpn-killswitch.service';
  const wrapperPath = '/usr/local/bin/clean-vpn-run.sh', scriptPath = '/usr/local/bin/clean-vpn-killswitch.sh';
  const main = installer.split('cat > "$UNIT_PATH" <<EOF\n')[1].split('\nEOF')[0]
    .replaceAll('$SERVICE_NAME', 'clean-vpn').replaceAll('$RUN_SH', wrapperPath)
    .replace('${KS_DEPS}', 'Requires=clean-vpn-killswitch.service\nAfter=clean-vpn-killswitch.service');
  const guard = installer.split('cat > "$KS_UNIT_PATH" <<EOF\n')[1].split('\nEOF')[0]
    .replace('$KS_GATE_MARKER', '# clean-vpn-networkd-gate-v1').replace('$KS_STOP', '/bin/true')
    .replaceAll('$SERVICE_NAME', 'clean-vpn').replaceAll('$KS_SH', scriptPath)
    .replace('$KS_UP_ARGS', 'up --scope=both --ipv6=block --tun=tun0 --ssh-port=22 --server=154.62.226.216 --usb-dns=1 --usb-strict=1');
  const wrapper = '#!/usr/bin/env bash\nset -euo pipefail\nexport PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin"\ncd "/repo"\nexec "/usr/bin/node" "/repo/scripts/clean-vpn.js" --role=client --type=tls --split-default --ipv6=auto --server=154.62.226.216:443 \n';
  const protectedWrapper = wrapper.replace(' --server=', ' --dns-usb=1 --server=');
  const files = new Map([[mainPath, main], [guardPath, guard], [wrapperPath, protectedWrapper], [scriptPath, 'guard-source']]);
  const opts = { readInstalled: p => files.get(p), guardSource: 'guard-source', gate() {},
    ctl: (...a) => a[0] === 'is-active' ? 'active' : a[2].includes('FragmentPath') ? '/etc/systemd/system/' + a[1]
      : a[2].includes('NeedDaemonReload') ? 'no' : '' };
  assert.doesNotThrow(() => assertInstalledUsbGatewayProfile(opts));
  files.set(guardPath, guard.replace(' --usb-dns=1 --usb-strict=1', ''));
  assert.throws(() => assertInstalledUsbGatewayProfile(opts), /upgrade-usb-dns/);
  assert.doesNotThrow(() => assertInstalledUsbGatewayProfile({ ...opts, allowLegacyGuard: true }));
  files.set(guardPath, guard);
  for (const [p, text] of [[mainPath, main + '\nExecStop=/bin/false'], [guardPath, guard.replace('scope=both', 'scope=fwd')],
    [wrapperPath, wrapper.replace('ipv6=auto', 'ipv6=off')], [wrapperPath, wrapper.replace('type=tls', 'type=combo-tls')],
    [wrapperPath, wrapper.replace('154.62.226.216', '198.51.100.1')], [scriptPath, 'foreign']]) {
    const saved = files.get(p); files.set(p, text); assert.throws(() => assertInstalledUsbGatewayProfile(opts)); files.set(p, saved);
  }
  assert.throws(() => assertInstalledUsbGatewayProfile({ ...opts, gate() { throw Error('missing gate'); } }));
  assert.throws(() => assertInstalledUsbGatewayProfile({ ...opts, ctl: () => 'foreign' }));
});
