/** Fixed, opt-in Radxa profile. No gadget, route, guard or main-service restart. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { publishHostWrapper } from './host-update.mjs';
import { rescueFiles, rescueUnits, rescueProbeUnit, installUsbRescue, validateUsbAddress } from './host-usb-rescue.mjs';
import { changeUsbSnat } from '../clean-vpn-usb-snat.mjs';

export const gatewayUnit = 'clean-vpn-usb-snat.service';
export const gatewayUnitPath = `/etc/systemd/system/${gatewayUnit}`;
export const gatewayHelper = '/usr/local/bin/clean-vpn-usb-snat.mjs';
const helperSource = fs.readFileSync(new URL('../clean-vpn-usb-snat.mjs', import.meta.url), 'utf8');
export const preMssHelperHash = '500b3ed1162af018cf8e53823ee690840d0518dd4161265e8f94cd835524d304';
export const gatewayRun = (file, args) => execFileSync(file, args, { encoding: 'utf8', timeout: 30000,
  maxBuffer: 1024 * 1024, env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' } });

export function gatewayFiles(node) {
  assert.match(node, /^\/[A-Za-z0-9_./-]+$/); assert.equal(resolve(node), node);
  return { [gatewayHelper]: helperSource, [gatewayUnitPath]: `[Unit]
Description=Reviewed Radxa USB SNAT (wait for protected host VPN)
After=clean-vpn.service clean-vpn-usb-rescue.socket
Wants=clean-vpn-usb-rescue.socket
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=${node} ${gatewayHelper} --apply
RemainAfterExit=yes
Restart=on-failure
RestartSec=5
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
` };
}

function trusted(io, path, directory = false) {
  const s = io.lstatSync(path);
  assert.ok(!s.isSymbolicLink() && (directory ? s.isDirectory() : s.isFile()) && s.uid === 0
    && !(s.mode & 0o022), `unsafe root-owned path: ${path}`);
  if (!directory) assert.equal(s.nlink, 1, `hardlinked file: ${path}`);
  return s;
}
function parents(io, path) {
  for (let p = dirname(path); ; p = dirname(p)) { trusted(io, p, true); if (p === '/') break; }
}
export function readGatewayFile(io, path) {
  parents(io, path);
  try { trusted(io, path); return io.readFileSync(path, 'utf8'); }
  catch (e) { if (e.code === 'ENOENT') return null; throw e; }
}
const read = readGatewayFile;
function inspectUnit(run, name, present) {
  const get = prop => run('systemctl', ['show', rescueProbeUnit(name), `--property=${prop}`, '--value']).trim();
  assert.equal(get('DropInPaths'), '', `unit overrides require review: ${name}`);
  if (present) {
    assert.equal(get('LoadState'), 'loaded', `unit not loaded: ${name}`);
    assert.equal(get('FragmentPath'), `/etc/systemd/system/${name}`, `foreign unit: ${name}`);
    assert.equal(get('NeedDaemonReload'), 'no', `reload required before installation: ${name}`);
  } else {
    assert.equal(get('LoadState'), 'not-found', `existing unit: ${name}`);
    assert.equal(get('FragmentPath'), '', `foreign unit: ${name}`);
    assert.equal(get('ActiveState'), 'inactive', `unit unexpectedly active: ${name}`);
  }
}
function inventory(io, expected) {
  const actual = Object.entries(expected).map(([path, text]) => {
    const old = read(io, path);
    if (old !== null) assert.equal(old, text, `existing file differs; no replacement: ${path}`);
    return old !== null;
  });
  assert.ok(actual.every(Boolean) || actual.every(x => !x), 'partial installation requires review');
  return actual.every(Boolean);
}

export function inspectUsbGateway({ io = fs, run = gatewayRun } = {}) {
  const unit = read(io, gatewayUnitPath), helper = read(io, gatewayHelper);
  if (unit === null && helper === null) { inspectUnit(run, gatewayUnit, false); return null; }
  assert.ok(unit !== null && helper !== null, 'partial USB gateway installation requires review');
  const node = /^ExecStart=(\/[^\s]+) /m.exec(unit)?.[1];
  assert.ok(node, 'unrecognized USB gateway unit');
  const files = gatewayFiles(node);
  assert.equal(unit, files[gatewayUnitPath], 'unknown USB gateway unit');
  assert.ok(helper === files[gatewayHelper] || createHash('sha256').update(helper).digest('hex') === preMssHelperHash,
    'unknown USB gateway helper; no replacement');
  inspectUnit(run, gatewayUnit, true);
  return { ...files, [gatewayHelper]: helper };
}

function publish(io, path, contents) {
  assert.equal(read(io, path), null, `file appeared during installation: ${path}`);
  const stage = io.mkdtempSync(join(dirname(path), '.usb-gateway-'));
  const temp = join(stage, 'new');
  try {
    const fd = io.openSync(temp, 'wx', 0o644);
    try { io.writeFileSync(fd, contents); io.fchmodSync(fd, 0o644); io.fsyncSync(fd); } finally { io.closeSync(fd); }
    io.linkSync(temp, path);
  } finally { if (io.existsSync(temp)) io.unlinkSync(temp); io.rmdirSync(stage); }
  const fd = io.openSync(dirname(path), 'r'); try { io.fsyncSync(fd); } finally { io.closeSync(fd); }
}

/** prepareOnly is used by the fresh installer before publishing its main unit.
 * Activation occurs only after the main installer has installed/enabled the guard.
 * Existing deployments use this same code, but never republish the VPN or guard. */
export function installUsbGateway({ apply = false, prepareOnly = false, node = process.execPath,
  io = fs, run = gatewayRun, rescue = installUsbRescue, snat = changeUsbSnat, replace = publishHostWrapper } = {}) {
  parents(io, node); const nodeStat = trusted(io, node);
  assert.ok(nodeStat.mode & 0o111, 'Node must be executable');
  const files = gatewayFiles(node);
  const previous = inspectUsbGateway({ io, run });
  const installed = previous !== null;
  if (installed) assert.equal(previous[gatewayUnitPath], files[gatewayUnitPath], 'installed Node path differs');
  const upgrade = installed && previous[gatewayHelper] !== files[gatewayHelper];
  const rescueInstalled = inventory(io, rescueFiles);
  for (const unit of Object.keys(rescueUnits)) inspectUnit(run, unit, rescueInstalled);
  validateUsbAddress(JSON.parse(run('ip', ['-j', 'address', 'show', 'dev', 'usb0'])));
  assert.equal(run('sysctl', ['-n', 'net.ipv4.ip_forward']).trim(), '1',
    'reviewed profile requires existing IPv4 forwarding; this installer does not change sysctl');
  snat({ remove: true }); // audit NAT ownership only; do not require a ready TUN
  if (!rescueInstalled) rescue({ apply: false, run });
  if (!apply) return { status: 'planned', files: Object.keys(files), rescueInstalled, prepareOnly, upgrade,
    tcpMss: 1360, restarts: !prepareOnly && installed ? [gatewayUnit] : [] };
  if (!rescueInstalled) rescue({ apply: true, run });
  else {
    // start is idempotent; never restart an existing rescue connection/socket.
    run('systemctl', ['enable', 'clean-vpn-usb-rescue.socket']);
    run('systemctl', ['start', 'clean-vpn-usb-rescue.socket']);
  }
  for (const unit of ['clean-vpn-usb-rescue.socket', 'clean-vpn-usb-rescue-address.service'])
    assert.equal(run('systemctl', ['is-active', unit]).trim(), 'active', 'rescue is not ready');
  assert.deepEqual(inspectUsbGateway({ io, run }), previous, 'gateway changed before publication');
  const backups = [];
  if (!installed) for (const [path, text] of Object.entries(files)) publish(io, path, text);
  else if (upgrade) backups.push(replace(gatewayHelper, previous[gatewayHelper], files[gatewayHelper], undefined, 0o644));
  run('systemctl', ['daemon-reload']);
  if (!prepareOnly) {
    run('systemctl', ['enable', gatewayUnit]);
    // Only this oneshot is restarted; it has no ExecStop or dependency that
    // restarts VPN/guard/USB. Reapply also repairs an incomplete prior publish.
    run('systemctl', [installed ? 'restart' : 'start', '--no-block', gatewayUnit]);
  }
  return { status: prepareOnly ? 'prepared' : 'enabled-waiting-for-vpn', persistent: !prepareOnly,
    tcpMss: 1360, upgrade, backups, restarts: !prepareOnly && installed ? [gatewayUnit] : [],
    rescue: '192.168.7.1:2222; listening is not proof of login',
    untouched: ['VPN process', 'guard', 'networkd', 'gadget', 'existing SSH', 'routes', 'sysctl'],
    limitations: ['fixed-reviewed-Radxa-profile', 'requires-existing-forwarding-at-each-boot',
      'no-concurrent-administrators', 'not-forwarded-DNS-or-IPv6-acceptance'] };
}

export function removeUsbGateway({ apply = false, io = fs, run = gatewayRun,
  snat = changeUsbSnat } = {}) {
  const files = inspectUsbGateway({ io, run });
  if (!files) return { status: 'not-installed', rescueRetained: true };
  snat({ remove: true }); // read-only NAT preflight before stopping anything
  if (!apply) return { status: 'planned-removal', rescueRetained: true };
  run('systemctl', ['disable', gatewayUnit]);
  run('systemctl', ['stop', gatewayUnit]);
  assert.equal(run('systemctl', ['show', gatewayUnit, '--property=ActiveState', '--value']).trim(), 'inactive');
  snat({ remove: true, apply: true });
  for (const [path, text] of Object.entries(files)) {
    assert.equal(read(io, path), text, 'USB gateway files changed during removal'); io.unlinkSync(path);
  }
  run('systemctl', ['daemon-reload']);
  return { status: 'removed', rescueRetained: true };
}
