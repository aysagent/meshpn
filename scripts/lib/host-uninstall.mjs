/** Stop is not proof of rollback: keep journal locks until guard/files are removed.
 * No automatic recovery, no global firewall flush, no evaluation of wrapper argv.
 * Only the generated persist guard is supported; tied guards need a different
 * stop protocol because PartOf may remove protection before journals are checked.
 */
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { openHostRoutes } from './vpn-host-routes.mjs';
import { openTunnelDnsJournal } from './dns-tunnel-journal.mjs';
import { openIpv6Runtime } from './vpn-ipv6-runtime.mjs';
import { runTunnelDnsCommand } from './dns-tunnel-command.mjs';
import { usesNetworkdGate, assertNetworkdGate, detachNetworkdGate } from './host-networkd-gate.mjs';

const properties = ['LoadState', 'ActiveState', 'PartOf', 'BindsTo', 'NetworkNamespacePath', 'PrivateNetwork', 'PrivateUsers',
  'RootDirectory', 'RootImage', 'BindPaths', 'BindReadOnlyPaths', 'TemporaryFileSystem',
  'Requires', 'Requisite', 'Conflicts', 'PropagatesStopTo', 'StopWhenUnneeded'];
export function uninstallHostService({ service = 'clean-vpn', io = fs, run = runTunnelDnsCommand,
  open = [openHostRoutes, openTunnelDnsJournal, openIpv6Runtime], log = console.error } = {}) {
  let gated = false;
  return withStoppedHostService({ service, io, run, open, log, beforeStop({ installed, paths, ctl }) {
    gated = installed[1] && usesNetworkdGate(io.readFileSync(paths[1], 'utf8'));
    if (gated) assertNetworkdGate({ service, io, ctl, allowDetached: true });
  } }, ({ installed, ctl, command, exists, inspect, paths }) => {
    const [unitPath, guardPath, wrapper, guardScript] = paths;
    const unit = `${service}.service`, guard = `${service}-killswitch.service`;
    if (gated) detachNetworkdGate({ service, io, ctl });
    if (installed[1]) { ctl('stop', guard); assert.equal(inspect(guard).ActiveState, 'inactive', 'guard stop failed; protection retained'); }
    if (installed[3]) command(guardScript, ['down', '--tun=tun0']);
    if (installed[0]) ctl('disable', unit);
    if (installed[1]) ctl('disable', guard);
    for (const [index, path] of paths.entries()) {
      if (installed[index]) { assert.ok(exists(path), 'installed file changed'); io.unlinkSync(path); }
    }
    ctl('daemon-reload');
    return { status: 'uninstalled', journalAudit: 'released-or-absent', automaticRecovery: false };
  });
}

/** The action runs only after stop and released-state proof, with all three
 * lifetime locks held. beforeStop is inspection only; it must not change state. */
export function withStoppedHostService({ service = 'clean-vpn', io = fs, run = runTunnelDnsCommand,
  open = [openHostRoutes, openTunnelDnsJournal, openIpv6Runtime], log = console.error,
  requireGuard = false, beforeStop = () => {} } = {}, action) {
  assert.match(service, /^[A-Za-z0-9_][A-Za-z0-9._-]*$/);
  assert.ok(service.length <= 200);
  const unit = `${service}.service`, guard = `${service}-killswitch.service`;
  const unitPath = `/etc/systemd/system/${unit}`, guardPath = `/etc/systemd/system/${guard}`;
  const wrapper = `/usr/local/bin/${service}-run.sh`, guardScript = `/usr/local/bin/${service}-killswitch.sh`;
  const journals = [];
  const command = (file, args, timeoutMs = 20000) => run(file, args, {
    timeoutMs, lockDescriptors: journals.flatMap(j => j.lockDescriptors),
  });
  const ctl = (...args) => command('systemctl', ['--no-pager', ...args], args[0] === 'stop' ? 450000 : 20000);
  const exists = path => {
    try { const s = io.lstatSync(path); assert.ok(s.isFile() && !s.isSymbolicLink(), `unsafe installed file: ${path}`); return true; }
    catch (e) { if (e.code === 'ENOENT') return false; throw e; }
  };
  const inspect = name => {
    const text = ctl('show', name, `--property=${properties.join(',')}`);
    const result = Object.fromEntries(text.split('\n').filter(Boolean).map(line => {
      const i = line.indexOf('='); assert.ok(i > 0); return [line.slice(0, i), line.slice(i + 1)];
    }));
    for (const key of properties) assert.equal(typeof result[key], 'string', `missing systemd property ${key}`);
    assert.equal(result.LoadState, 'loaded', `unit unavailable: ${name}`);
    assert.equal(result.PrivateNetwork, 'no', 'private network requires manual review');
    assert.equal(result.PrivateUsers, 'no', 'private user namespace requires manual review');
    for (const key of ['RootDirectory', 'RootImage', 'BindPaths', 'BindReadOnlyPaths', 'TemporaryFileSystem'])
      assert.equal(result[key], '', `${key} requires manual review`);
    // An audit in the wrong netns would inspect empty, unrelated journals.
    const target = io.statSync(result.NetworkNamespacePath || '/proc/1/ns/net');
    const self = io.statSync('/proc/self/ns/net');
    assert.ok(target.dev === self.dev && target.ino === self.ino, 'run uninstall in the service network namespace');
    return result;
  };
  try {
    const installed = [unitPath, guardPath, wrapper, guardScript].map(exists);
    if (requireGuard) assert.ok(installed.every(Boolean), 'complete persist installation required');
    if (installed.every(v => !v)) return { status: 'not-installed', automaticRecovery: false };
    assert.ok(installed[0] === installed[2] && installed[1] === installed[3] && (!installed[1] || installed[0]),
      'partial installation requires manual review; no guard removal');
    if (installed[2]) assert.ok(!io.readFileSync(wrapper, 'utf8').includes('--dns-state-dir'),
      'custom DNS journal directory requires manual review; no guard removal');
    if (installed[0]) assert.equal(inspect(unit).PropagatesStopTo, '', 'stop propagation requires manual review');
    if (installed[1]) {
      const g = inspect(guard);
      assert.ok(g.PartOf === '' && g.BindsTo === '', 'tied guard uninstall refused before stop; persist lifecycle required');
      assert.equal(g.StopWhenUnneeded, 'no', 'automatic guard stop requires manual review');
      for (const key of ['Requires', 'Requisite', 'Conflicts'])
        assert.ok(!g[key].split(/\s+/).includes(unit), 'guard dependency on VPN requires manual review');
    }
    const context = { installed, ctl, command, exists, inspect, paths: [unitPath, guardPath, wrapper, guardScript] };
    beforeStop(context);
    if (installed[0]) { log('Stopping VPN; guard retained until released-journal audit'); ctl('stop', unit); }
    // Nonblocking locks: live client/recovery, damaged files, or any unfinished
    // transaction refuses uninstall. Absence is allowed for never-used modes.
    for (const acquire of open) {
      const j = acquire(); journals.push(j);
      assert.ok(!j.state || j.state.stage === 'released', 'unfinished VPN journal; explicit recovery required; guard and installed files retained');
    }
    if (installed[0]) assert.equal(inspect(unit).ActiveState, 'inactive', 'VPN is not stopped');
    return action(context);
  } finally { for (const j of journals.reverse()) j.release(); }
}
