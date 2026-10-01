/** Retire ONLY an already inactive, disabled default tied installation.
 * No stop/start/disable, no execution of installed scripts, no firewall setters.
 * Concurrent administrators/automatic external activators are not supported.
 * A durable private copy of ALL files precedes any unlink; partial failure needs
 * explicit review of backupDirectory, never automatic install or rollback.
 */
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { dirname, basename } from 'node:path';
import { createHash } from 'node:crypto';
import { openHostRoutes } from './vpn-host-routes.mjs';
import { openTunnelDnsJournal } from './dns-tunnel-journal.mjs';
import { openIpv6Runtime } from './vpn-ipv6-runtime.mjs';
import { runTunnelDnsCommand } from './dns-tunnel-command.mjs';
import { networkdGatePaths } from './host-networkd-gate.mjs';

export const LEGACY_FILES = ['/etc/systemd/system/clean-vpn.service', '/etc/systemd/system/clean-vpn-killswitch.service', '/usr/local/bin/clean-vpn-run.sh', '/usr/local/bin/clean-vpn-killswitch.sh'];
export const RETIRABLE_GUARD_HASHES = new Set([
  '5b99335723dcab4a1c3b472307e61bb082496b81ab9e73d9f9ca75139f25172e', // a47c939, reported Radxa
  'edd7637a3babbfc595e513a88974c4da9047e589336cd2859782f779abf07fbd', // v2, stopped tied fixture
  'a46ebd191032da2e2205a5babfbad31d3daa274d3e857b8327e1e4ba6078164b', // v2 with read-only active-client audit
]);
const hash = b => createHash('sha256').update(b).digest('hex');
const units = ['clean-vpn.service', 'clean-vpn-killswitch.service'];
const keys = ['Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'FragmentPath', 'DropInPaths', 'PartOf', 'BindsTo', 'MainPID', 'ControlPID', 'Job', 'TriggeredBy', 'WantedBy', 'RequiredBy', 'UpheldBy', 'NetworkNamespacePath', 'PrivateNetwork', 'PrivateUsers', 'RootDirectory', 'RootImage', 'BindPaths', 'BindReadOnlyPaths', 'TemporaryFileSystem'];
export function retireLegacyHost({ apply = false, io = fs, run = runTunnelDnsCommand,
  open = [openHostRoutes, openTunnelDnsJournal, openIpv6Runtime], onProgress = () => {} } = {}) {
  const journals = [], removedPaths = []; let backupDirectory = null;
  const command = (file, args) => run(file, args, { timeoutMs: 15000, lockDescriptors: journals.flatMap(j => j.lockDescriptors) });
  const ctl = (...args) => command('systemctl', ['--no-pager', ...args]);
  const trusted = (s, directory) => assert.ok(s.uid === 0 && !(s.mode & 0o022) && !s.isSymbolicLink() && (directory ? s.isDirectory() : s.isFile() && s.nlink === 1), 'unsafe retirement path');
  const parents = path => { for (let p = dirname(path); ; p = dirname(p)) { trusted(io.lstatSync(p), true); if (p === '/') break; } };
  const absent = path => { try { io.lstatSync(path); return false; } catch (e) { if (e.code !== 'ENOENT') throw e; return true; } };
  const read = path => {
    parents(path); trusted(io.lstatSync(path), false);
    const fd = io.openSync(path, io.constants.O_RDONLY | io.constants.O_NOFOLLOW | io.constants.O_NONBLOCK);
    try {
      const s = io.fstatSync(fd); trusted(s, false); assert.ok(s.size > 0 && s.size <= 1024 * 1024, 'oversized/empty installed file');
      const data = Buffer.alloc(s.size + 1), n = io.readSync(fd, data, 0, data.length, 0); assert.equal(n, s.size, 'file size changed');
      const bytes = data.subarray(0, n);
      return { bytes, metadata: { path, sha256: hash(bytes), mode: s.mode & 0o777, uid: s.uid, gid: s.gid, dev: s.dev, ino: s.ino, size: s.size } };
    } finally { io.closeSync(fd); }
  };
  const syncDirectory = path => { const fd = io.openSync(path, io.constants.O_RDONLY | io.constants.O_DIRECTORY | io.constants.O_NOFOLLOW); try { io.fsyncSync(fd); } finally { io.closeSync(fd); } };
  const save = (path, bytes) => {
    const fd = io.openSync(path, io.constants.O_WRONLY | io.constants.O_CREAT | io.constants.O_EXCL | io.constants.O_NOFOLLOW, 0o600);
    try { io.writeFileSync(fd, bytes); io.fsyncSync(fd); } finally { io.closeSync(fd); }
  };
  function inspectUnits() {
    for (const [index, unit] of units.entries()) {
      const properties = Object.fromEntries(ctl('show', unit, `--property=${keys.join(',')}`).split('\n').filter(Boolean).map(line => {
        const at = line.indexOf('='); assert.ok(at > 0, 'invalid unit response'); return [line.slice(0, at), line.slice(at + 1)];
      }));
      for (const key of keys) assert.equal(typeof properties[key], 'string', `missing property ${key}`);
      for (const [key, expected] of Object.entries({ Id: unit, LoadState: 'loaded', ActiveState: 'inactive', SubState: 'dead', FragmentPath: LEGACY_FILES[index], MainPID: '0', ControlPID: '0', PrivateNetwork: 'no', PrivateUsers: 'no', PartOf: index ? units[0] : '' })) assert.equal(properties[key], expected, `unexpected ${unit} ${key}`);
      assert.ok((index ? ['static', 'disabled'] : ['disabled']).includes(properties.UnitFileState), 'disable legacy VPN before retirement');
      for (const key of ['DropInPaths', 'BindsTo', 'Job', 'TriggeredBy', 'WantedBy', 'UpheldBy', 'NetworkNamespacePath', 'RootDirectory', 'RootImage', 'BindPaths', 'BindReadOnlyPaths', 'TemporaryFileSystem']) assert.equal(properties[key], '', `unsupported ${unit} ${key}`);
      assert.ok(properties.RequiredBy.split(/\s+/).filter(Boolean).every(n => index === 1 && n === units[0]), 'external unit requires legacy VPN');
    }
  }
  function inspectNetwork() {
    const links = JSON.parse(command('ip', ['-j', '-d', 'link', 'show']));
    assert.ok(Array.isArray(links) && links.length > 0 && links.every(l => l && typeof l.ifname === 'string' && l.ifname !== 'tun0' && l.linkinfo?.info_kind !== 'tun'), 'existing/uncertain TUN; stop manual VPN first');
    for (const tool of ['iptables', 'ip6tables']) {
      const rules = command(tool, ['-w', '5', '-t', 'filter', '-S']);
      assert.match(rules, /(?:^|\n)-P OUTPUT (?:ACCEPT|DROP)(?:\n|$)/, 'incomplete firewall inventory');
      assert.ok(!rules.includes('CLEANVPN_KS_'), 'guard rules/references remain; no removal');
    }
    for (const path of networkdGatePaths('clean-vpn')) assert.ok(absent(path), 'networkd integration already installed; not legacy retirement');
  }
  try {
    assert.equal(io.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd', 'systemd PID1 required');
    for (const ns of ['net', 'user']) assert.equal(io.readlinkSync(`/proc/self/ns/${ns}`), io.readlinkSync(`/proc/1/ns/${ns}`), 'host namespace required');
    const pinned = LEGACY_FILES.map(read);
    assert.ok(RETIRABLE_GUARD_HASHES.has(pinned[3].metadata.sha256), 'unknown installed guard version; review before retirement');
    inspectUnits();
    for (const acquire of open) {
      const j = acquire(); journals.push(j);
      assert.ok(!j.state || j.state.stage === 'released', 'unfinished VPN journal; explicit recovery required');
    }
    inspectNetwork();
    const report = { schema: 1, kind: 'clean-vpn-retire-legacy', status: 'eligible', networkSettingsChanged: false,
      servicesStoppedOrStarted: false, files: pinned.map(f => f.metadata), journalAudit: 'released-or-absent', guardRules: 'absent', backupDirectory: null,
      limitations: ['default-stopped-tied-service-only', 'not-an-installer', 'no-concurrent-administrators', 'partial-file-failure-requires-manual-review'] };
    if (!apply) return report;
    parents('/var/backups');
    if (absent('/var/backups')) { io.mkdirSync('/var/backups', { mode: 0o755 }); syncDirectory('/var'); }
    trusted(io.lstatSync('/var/backups'), true);
    backupDirectory = io.mkdtempSync('/var/backups/clean-vpn-legacy-'); io.chmodSync(backupDirectory, 0o700);
    syncDirectory('/var/backups');
    onProgress({ stage: 'backup', backupDirectory });
    for (const file of pinned) save(`${backupDirectory}/${basename(file.metadata.path)}`, file.bytes);
    save(`${backupDirectory}/manifest.json`, JSON.stringify({ schema: 1, kind: report.kind, files: report.files }, null, 2) + '\n');
    syncDirectory(backupDirectory);
    // Recheck ALL prerequisites after backup, before the first unlink.
    inspectUnits(); inspectNetwork();
    for (const file of pinned) assert.deepEqual(read(file.metadata.path).metadata, file.metadata, 'installed file changed; backup retained');
    for (const file of pinned) {
      assert.deepEqual(read(file.metadata.path).metadata, file.metadata, 'installed file changed during retirement');
      io.unlinkSync(file.metadata.path); removedPaths.push(file.metadata.path); syncDirectory(dirname(file.metadata.path));
    }
    ctl('daemon-reload');
    for (const unit of units) {
      assert.equal(ctl('show', unit, '--property=LoadState', '--value').trim(), 'not-found', 'unit still loaded after removal; review before install');
      assert.equal(ctl('show', unit, '--property=ActiveState', '--value').trim(), 'inactive', 'unit not inactive after removal');
    }
    return { ...report, status: 'retired', backupDirectory, removedPaths };
  } catch (error) {
    error.retirement = { schema: 1, kind: 'clean-vpn-retire-legacy', status: 'refused-or-incomplete', networkSettingsChanged: false, backupDirectory, removedPaths, reason: error.message };
    throw error;
  } finally { for (const j of journals.reverse()) j.release(); }
}
