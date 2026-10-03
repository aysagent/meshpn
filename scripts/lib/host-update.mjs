/** Release switch only: same argv, node binary, units and guard. No automatic
 * restart, recovery, guard mutation or in-place source copying. One atomic
 * wrapper rename is the publication point; a private old-wrapper copy remains.
 */
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { withStoppedHostService } from './host-uninstall.mjs';
import { usesNetworkdGate, assertNetworkdGate } from './host-networkd-gate.mjs';

const hash = b => createHash('sha256').update(b).digest('hex');
const pathPattern = '/[A-Za-z0-9_./-]+';
function safePath(path) {
  assert.equal(typeof path, 'string'); assert.match(path, new RegExp(`^${pathPattern}$`));
  assert.equal(resolve(path), path); assert.notEqual(path, '/'); return path;
}
function trusted(path, directory = false) {
  const s = fs.lstatSync(path);
  assert.ok(!s.isSymbolicLink() && (directory ? s.isDirectory() : s.isFile()), `unsafe type: ${path}`);
  assert.ok(s.uid === 0 && !(s.mode & 0o022), `root-owned, non-writable-by-others path required: ${path}`);
  if (!directory) assert.equal(s.nlink, 1, `hardlinked file refused: ${path}`);
  return s;
}
function trustedParents(path) {
  for (let p = dirname(path); ; p = dirname(p)) { trusted(p, true); if (p === '/') break; }
}
export function inspectHostRelease(root) {
  safePath(root); trustedParents(root); trusted(root, true);
  let files = 0, bytes = 0;
  const digest = createHash('sha256');
  const walk = path => {
    for (const name of fs.readdirSync(path).sort()) {
      assert.match(name, /^[A-Za-z0-9_@.-]+$/, 'release contains an unsupported name');
      const p = join(path, name), s = fs.lstatSync(p);
      assert.ok(++files <= 10000, 'release too large');
      if (s.isDirectory()) { trusted(p, true); walk(p); }
      else {
        trusted(p); bytes += s.size; assert.ok(bytes <= 256 * 1024 * 1024, 'release too large');
        digest.update(JSON.stringify([p.slice(root.length), s.mode & 0o777, hash(fs.readFileSync(p))]));
      }
    }
  };
  walk(root);
  for (const p of ['scripts/clean-vpn.js', 'package.json', 'native/tun_linux/build/Release/tun_linux.node']) trusted(join(root, p));
  return { sha256: digest.digest('hex'), entries: files, bytes };
}

export function switchHostWrapper(source, release) {
  safePath(release); assert.ok(source.length <= 32768);
  assert.ok(source.startsWith('#!/usr/bin/env bash\n'), 'unrecognized wrapper interpreter');
  const lines = source.split('\n').filter(l => l && !l.startsWith('#'));
  assert.equal(lines.length, 4, 'unrecognized installed wrapper');
  assert.equal(lines[0], 'set -euo pipefail');
  assert.equal(lines[1], 'export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin"');
  const cd = new RegExp(`^cd "(${pathPattern})"$`).exec(lines[2]); assert.ok(cd, 'unrecognized wrapper directory');
  const oldRoot = safePath(cd[1]);
  const exec = new RegExp(`^exec "(${pathPattern})" "(${pathPattern})" (.+?) *$`).exec(lines[3]);
  assert.ok(exec, 'unrecognized wrapper exec'); safePath(exec[1]);
  assert.equal(exec[2], `${oldRoot}/scripts/clean-vpn.js`);
  // This intentionally supports only plain generated arguments, never shell
  // expansion/eval or arbitrary edited wrappers. Keep their bytes unchanged.
  const args = exec[3].split(' ');
  assert.ok(args.every(a => /^--[A-Za-z0-9_-]+(?:=[A-Za-z0-9_./,:@+=-]+)?$/.test(a)), 'complex wrapper argv requires manual review');
  assert.equal(new Set(args.map(a => a.split('=')[0])).size, args.length, 'duplicate option');
  assert.ok(args.includes('--role=client') && args.includes('--split-default'), 'host split-default client required');
  assert.ok(!args.some(a => /^--(?:dns-state-dir|config|from-tun|client-lan-subnet|client-lan-interface)(?:=|$)/.test(a)), 'custom client scope refused');
  const server = args.find(a => a.startsWith('--server='));
  assert.match(server || '', /^--server=\d+\.\d+\.\d+\.\d+:\d+$/);
  assert.ok(release !== oldRoot && !release.startsWith(`${oldRoot}/`) && !oldRoot.startsWith(`${release}/`), 'separate release directory required');
  const contents = source.replace(lines[2], `cd "${release}"`)
    .replace(lines[3], lines[3].replace(`"${oldRoot}/scripts/clean-vpn.js"`, `"${release}/scripts/clean-vpn.js"`));
  return { contents, oldRoot, node: exec[1], serverIp: server.slice(9).split(':')[0] };
}

// Strict unit templates, ignoring comments only. Limited fixture/log drop-ins
// may set namespace and output destinations, never commands/dependencies.
function assignments(text) { return text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')); }
export function checkHostUpdateUnits(service, main, guard) {
  const gs = `/usr/local/bin/${service}-killswitch.sh`;
  assert.deepEqual(assignments(main), ['[Unit]', `Description=clean-vpn (${service})`, 'After=network.target',
    `Requires=${service}-killswitch.service`, `After=${service}-killswitch.service`, 'StartLimitIntervalSec=0',
    '[Service]', 'Type=simple', `ExecStart=/usr/local/bin/${service}-run.sh`, 'Restart=always', 'RestartSec=2',
    'KillMode=mixed', 'TimeoutStopSec=420', '[Install]', 'WantedBy=multi-user.target'], 'main unit template requires review');
  const g = assignments(guard);
  const up = g.find(l => l.startsWith('ExecStart='));
  const m = new RegExp(`^ExecStart=${gs.replaceAll('.', '\\.')} up --scope=both --ipv6=block --tun=tun0 --ssh-port=(\\d+) --server=([0-9.,]+)( --usb-dns=1( --usb-strict=1)?)?$`).exec(up || '');
  assert.ok(m, 'persist both/block guard required');
  assert.deepEqual(g, ['[Unit]', `Description=clean-vpn kill-switch (${service}, persist)`, 'DefaultDependencies=no',
    'Before=network-pre.target', 'Wants=network-pre.target', 'Conflicts=shutdown.target', 'Before=shutdown.target',
    '[Service]', 'Type=oneshot', 'RemainAfterExit=yes', up, usesNetworkdGate(guard) ? 'ExecStop=/bin/true' : `ExecStop=${gs} down --tun=tun0`, '[Install]', 'WantedBy=multi-user.target']);
  return `cvks${m[4] ? 4 : m[3] ? 3 : 2}:both:block:tun0:${m[2]}:${m[1]}`;
}

export function publishHostWrapper(path, before, after, checkpoint = () => {}, mode = 0o755) {
  assert.ok(mode === 0o755 || mode === 0o644, 'unsupported publication mode');
  trustedParents(path); trusted(path);
  assert.equal(fs.readFileSync(path, 'utf8'), before, 'wrapper changed before publication');
  const backupDirectory = fs.mkdtempSync(join(dirname(path), '.clean-vpn-update-'));
  fs.chmodSync(backupDirectory, 0o700);
  const write = (name, contents, mode) => {
    const fd = fs.openSync(join(backupDirectory, name), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, mode);
    try { fs.writeFileSync(fd, contents); fs.fchmodSync(fd, mode); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  };
  const sync = p => { const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } };
  write('previous-wrapper', before, 0o600); write('next-wrapper', after, mode);
  sync(backupDirectory); sync(dirname(path));
  checkpoint('prepared'); // internal VM fault injection, not a CLI option
  // Only publication mutation. A crash leaves the old OR the complete new
  // wrapper; no deletion of the old release, units, guard or network journals.
  fs.renameSync(join(backupDirectory, 'next-wrapper'), path);
  checkpoint('renamed');
  sync(dirname(path)); sync(backupDirectory);
  return { backupDirectory, previousSha256: hash(before), currentSha256: hash(after) };
}

export function updateHostService({ service = 'clean-vpn', release, log = console.error,
  lifecycle = withStoppedHostService, inspectRelease = inspectHostRelease, publish = publishHostWrapper,
  guardSource = fs.readFileSync(new URL('../autostart/killswitch.sh', import.meta.url), 'utf8'),
  read = p => { trustedParents(p); trusted(p); return fs.readFileSync(p, 'utf8'); } } = {}) {
  assert.match(service, /^[A-Za-z0-9_][A-Za-z0-9._-]*$/); assert.ok(service.length <= 200);
  const inventory = inspectRelease(release);
  let source, next, marker, pinned;
  const unchanged = paths => assert.deepEqual(paths.map(read), pinned, 'installed files changed during update');
  return lifecycle({ service, requireGuard: true, log, beforeStop({ paths, ctl, inspect }) {
    pinned = paths.map(read); source = pinned[2]; next = switchHostWrapper(source, release);
    marker = checkHostUpdateUnits(service, pinned[0], pinned[1]);
    if (usesNetworkdGate(pinned[1])) assertNetworkdGate({ service, ctl });
    assert.equal(pinned[3], guardSource, 'installed guard implementation requires review');
    assert.ok(marker.split(':')[4].split(',').includes(next.serverIp), 'exit not allowed by installed guard');
    assert.equal(inspect(`${service}-killswitch.service`).ActiveState, 'active', 'guard is not active');
    // Reject effective drop-ins that could replace commands or propagate stop.
    for (const [i, unit] of [`${service}.service`, `${service}-killswitch.service`].entries()) {
      const fragment = ctl('show', unit, '--property=FragmentPath', '--value').trim(); assert.equal(fragment, paths[i]);
      assert.equal(ctl('show', unit, '--property=NeedDaemonReload', '--value').trim(), 'no', 'loaded unit differs from disk');
      const drops = ctl('show', unit, '--property=DropInPaths', '--value').trim();
      for (const path of drops ? drops.split(' ') : []) {
        const lines = assignments(read(path)); assert.equal(lines.shift(), '[Service]');
        assert.ok(lines.every(l => /^(?:NetworkNamespacePath=\/[A-Za-z0-9_./-]+|Standard(?:Output|Error)=append:\/[A-Za-z0-9_./-]+)$/.test(l)), 'unsupported service override');
      }
    }
  } }, ({ paths, inspect, command }) => {
    unchanged(paths);
    assert.equal(inspect(`${service}-killswitch.service`).ActiveState, 'active', 'guard stopped during update');
    const status = command(paths[3], ['status']);
    for (const family of [4, 6]) assert.ok(status.split('\n').includes(`[clean-vpn-killswitch] IPv${family}: ${marker}`), 'effective guard missing or differs');
    assert.deepEqual(inspectRelease(release), inventory, 'candidate release changed');
    unchanged(paths);
    log('Journals released; guard audited; publishing wrapper (service remains stopped)');
    const result = publish(paths[2], source, next.contents);
    return { status: 'updated-stopped', service, release, releaseSha256: inventory.sha256, ...result,
      guardChanged: false, automaticRecovery: false, startPerformed: false };
  });
}
