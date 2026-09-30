/** Opt-in host-client boot dependency. No network configuration rewrite.
 * Persist-mode stop retains firewall rules; explicit audited uninstall detaches
 * this owned dependency before deliberately releasing protection.
 * Concurrent administrators and network configured by initramfs are out of scope.
 */
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { runTunnelDnsCommand } from './dns-tunnel-command.mjs';

export const NETWORKD_GATE_MARKER = '# clean-vpn-networkd-gate-v1';
export const NETWORKD_GATED_UNITS = ['systemd-networkd.service', 'systemd-networkd.socket'];
export function assertNetworkdClientArgs(args) {
  const accepted = new Set(['role', 'type', 'server', 'split-default', 'ipv6', 'tls-client-sni', 'tls-public-name', 'tls-server-name', 'tls-cert-dir', 'shared-hmac-key', 'keep-alive', 'dns-mode', 'dns-server']);
  const values = new Map();
  for (const arg of args) {
    const m = /^--([a-z][a-z0-9-]*)(?:=([^\r\n]+))?$/.exec(arg);
    assert.ok(m && accepted.has(m[1]) && !values.has(m[1]), 'unsupported/duplicate networkd candidate option');
    assert.ok(m[1] === 'split-default' ? m[2] === undefined : typeof m[2] === 'string', 'option value required'); values.set(m[1], m[2] ?? true);
  }
  for (const [key, value] of [['role', 'client'], ['type', 'tls'], ['split-default', true], ['ipv6', 'auto']]) assert.equal(values.get(key), value, `networkd candidate requires ${key}`);
  assert.match(values.get('server') ?? '', /^\d+\.\d+\.\d+\.\d+:\d+$/);
  assert.equal(values.get('dns-mode') ?? 'tunnel', 'tunnel');
}
export function networkdGatePath(service, unit = 'systemd-networkd.service') {
  assert.match(service, /^[A-Za-z0-9_][A-Za-z0-9._-]*$/); assert.ok(service.length <= 200);
  assert.ok(NETWORKD_GATED_UNITS.includes(unit));
  return `/etc/systemd/system/${unit}.d/90-clean-vpn-${service}.conf`;
}
export const networkdGatePaths = service => NETWORKD_GATED_UNITS.map(unit => networkdGatePath(service, unit));
export function networkdGateText(service) {
  networkdGatePath(service);
  return `${NETWORKD_GATE_MARKER}\n[Unit]\nRequires=${service}-killswitch.service\nAfter=${service}-killswitch.service\n`;
}
export function usesNetworkdGate(unit) { return unit.split('\n').includes(NETWORKD_GATE_MARKER); }
function trusted(io, path, directory = false) {
  const s = io.lstatSync(path);
  assert.ok(!s.isSymbolicLink() && (directory ? s.isDirectory() : s.isFile()) && s.uid === 0 && !(s.mode & 0o022), `unsafe gate path: ${path}`);
  if (!directory) assert.equal(s.nlink, 1, 'hardlinked gate refused');
}
function parents(io, path) { for (let p = dirname(path); ; p = dirname(p)) { trusted(io, p, true); if (p === '/') break; } }
function maybeRead(io, path) {
  try { trusted(io, path); return io.readFileSync(path, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
}
export function assertNetworkdGate({ service, io = fs, ctl, allowDetached = false }) {
  return NETWORKD_GATED_UNITS.map(unit => {
    const path = networkdGatePath(service, unit); parents(io, path);
    const text = maybeRead(io, path);
    assert.ok(text !== null || allowDetached, 'networkd gate missing');
    if (text !== null) assert.equal(text, networkdGateText(service), 'foreign/modified networkd gate');
    if (!allowDetached) for (const key of ['Requires', 'After'])
      assert.ok(ctl('show', unit, `--property=${key}`, '--value').trim().split(/\s+/).includes(`${service}-killswitch.service`), `networkd ${key} gate not loaded`);
    return { path, present: text !== null };
  });
}
export function prepareNetworkdGate({ service = 'clean-vpn', io = fs, run = runTunnelDnsCommand } = {}) {
  const paths = networkdGatePaths(service);
  assert.equal(io.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd', 'systemd PID1 required');
  const show = (unit, key) => run('systemctl', ['--no-pager', 'show', unit, `--property=${key}`, '--value'], { timeoutMs: 20000 }).trim();
  assert.equal(show('systemd-networkd.service', 'LoadState'), 'loaded'); assert.equal(show('systemd-networkd.service', 'ActiveState'), 'active', 'active networkd required');
  assert.equal(show('systemd-networkd.socket', 'LoadState'), 'loaded', 'vendor networkd socket required');
  const links = JSON.parse(run('ip', ['-j', '-d', 'link', 'show'], { timeoutMs: 20000 }));
  assert.ok(Array.isArray(links) && links.length > 0);
  assert.ok(links.every(l => l.ifname !== 'tun0' && l.linkinfo?.info_kind !== 'tun'), 'stop existing TUN clients before installation');
  for (const unit of ['NetworkManager.service', 'networking.service', 'connman.service', 'wicked.service']) {
    const load = show(unit, 'LoadState'), active = show(unit, 'ActiveState'), enabled = show(unit, 'UnitFileState');
    assert.ok(['not-found', 'masked'].includes(load) || load === 'loaded' && active === 'inactive' && ['disabled', 'masked'].includes(enabled), `another network manager requires review: ${unit}`);
  }
  // Validate both existing objects before publication. The pair is NOT atomic.
  for (const path of paths) {
    parents(io, dirname(path));
    try { trusted(io, dirname(path), true); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    assert.equal(maybeRead(io, path), null, 'existing networkd gate; installation refused');
  }
  // Atomic exclusive file publication: an interrupted installer leaves a dependency
  // on a missing/failed guard, not a silently unprotected network boot.
  for (const path of paths) publish(path);
  return { status: 'dependency-published', guardStop: 'retain-rules', networkManagerRestarted: false };
  function publish(path) {
  const parent = dirname(path);
  parents(io, parent);
  try { io.mkdirSync(parent, { mode: 0o755 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  trusted(io, parent, true); assert.equal(maybeRead(io, path), null, 'existing networkd gate; installation refused');
  const ancestor = io.openSync(dirname(parent), io.constants.O_RDONLY | io.constants.O_DIRECTORY | io.constants.O_NOFOLLOW);
  try { io.fsyncSync(ancestor); } finally { io.closeSync(ancestor); }
  const temporary = `${parent}/.clean-vpn-${randomBytes(12).toString('hex')}`;
  const fd = io.openSync(temporary, io.constants.O_WRONLY | io.constants.O_CREAT | io.constants.O_EXCL | io.constants.O_NOFOLLOW, 0o644);
  try { io.writeFileSync(fd, networkdGateText(service)); io.fchmodSync(fd, 0o644); io.fsyncSync(fd); } finally { io.closeSync(fd); }
  try { io.linkSync(temporary, path); } finally { io.unlinkSync(temporary); }
  const d = io.openSync(parent, io.constants.O_RDONLY | io.constants.O_DIRECTORY | io.constants.O_NOFOLLOW);
  try { io.fsyncSync(d); } finally { io.closeSync(d); }
  }
}
export function detachNetworkdGate({ service, io = fs, ctl }) {
  const entries = assertNetworkdGate({ service, io, ctl, allowDetached: true });
  for (const { path, present } of entries) if (present) {
    // Caller holds all released VPN journal locks and has stopped the client.
    io.unlinkSync(path);
    const d = io.openSync(dirname(path), io.constants.O_RDONLY | io.constants.O_DIRECTORY | io.constants.O_NOFOLLOW);
    try { io.fsyncSync(d); } finally { io.closeSync(d); }
  }
  // Also required on retry after a reload failure. Do not stop guard until the
  // manager no longer depends on it (including any foreign drop-in).
  ctl('daemon-reload');
  for (const unit of NETWORKD_GATED_UNITS) for (const key of ['Requires', 'After']) assert.ok(!ctl('show', unit, `--property=${key}`, '--value').trim().split(/\s+/).includes(`${service}-killswitch.service`), 'networkd still depends on guard; protection retained');
}
