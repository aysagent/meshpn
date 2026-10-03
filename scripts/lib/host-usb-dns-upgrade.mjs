/** Explicit fixed-profile migration. Stop VPN with journal locks, retain guard,
 * atomically publish approved files, replace owned rules without a down/flush.
 * Never restart guard/networkd/USB. Leaves VPN and an existing SNAT unit stopped.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { withStoppedHostService } from './host-uninstall.mjs';
import { publishHostWrapper, switchHostWrapper } from './host-update.mjs';
import { assertInstalledUsbGatewayProfile } from '../clean-vpn-usb-gateway.mjs';
import { gatewayFiles, gatewayHelper, gatewayUnit, gatewayUnitPath, gatewayRun, readGatewayFile } from './host-usb-gateway.mjs';
import { rescueFiles, rescueProbeUnit, validateUsbAddress } from './host-usb-rescue.mjs';

export const legacyUsbGuardHash = 'a46ebd191032da2e2205a5babfbad31d3daa274d3e857b8327e1e4ba6078164b';
export const legacyUsbSnatHash = '57724bcb4615c76ffe545db12a818775f34f898601d2e5d806c9c613f16a2df7';
const guardPath = '/usr/local/bin/clean-vpn-killswitch.sh';
const guardUnitPath = '/etc/systemd/system/clean-vpn-killswitch.service';
const wrapperPath = '/usr/local/bin/clean-vpn-run.sh';
const oldStart = 'ExecStart=/usr/local/bin/clean-vpn-killswitch.sh up --scope=both --ipv6=block --tun=tun0 --ssh-port=22 --server=154.62.226.216';
const profile = 'both:block:tun0:154.62.226.216:22';
const digest = text => createHash('sha256').update(text).digest('hex');
const sourceGuardPath = fileURLToPath(new URL('../autostart/killswitch.sh', import.meta.url));
const sourceSnatPath = fileURLToPath(new URL('../clean-vpn-usb-snat.mjs', import.meta.url));

export function usbDnsWrapper(source) {
  switchHostWrapper(source, '/var/lib/clean-vpn-usb-gateway-inspection');
  const line = source.split('\n').find(l => l.startsWith('exec '));
  const args = line.trim().split(' ');
  assert.ok(!args.some(a => a.startsWith('--dns-mode=') && a !== '--dns-mode=tunnel'), 'USB requires tunnel DNS');
  const flags = args.filter(a => a.startsWith('--dns-usb'));
  assert.ok(flags.length === 0 || flags.length === 1 && flags[0] === '--dns-usb=1', 'unknown USB DNS option');
  return flags.length ? source : source.replace(line, line.trimEnd() + ' --dns-usb=1');
}

export function upgradeUsbDnsGuard({ apply = false, read = p => readGatewayFile(fs, p), run = gatewayRun,
  inspectProfile = assertInstalledUsbGatewayProfile, lifecycle = withStoppedHostService,
  publish = publishHostWrapper, log = console.error } = {}) {
  const currentGuard = read(sourceGuardPath), currentSnat = read(sourceSnatPath);
  assert.ok(currentGuard && currentSnat, 'missing trusted upgrade sources');
  const ctl = (...args) => run('systemctl', args).trim();
  const unit = (name, path) => {
    const concrete = rescueProbeUnit(name);
    assert.equal(ctl('show', concrete, '--property=LoadState', '--value'), 'loaded');
    assert.equal(ctl('show', concrete, '--property=FragmentPath', '--value'), path);
    assert.equal(ctl('show', concrete, '--property=DropInPaths', '--value'), '', 'unit overrides refused');
    assert.equal(ctl('show', concrete, '--property=NeedDaemonReload', '--value'), 'no');
  };
  const preflight = () => {
    const guard = read(guardPath);
    assert.ok(guard && (guard === currentGuard || digest(guard) === legacyUsbGuardHash), 'unknown installed guard; no changes');
    inspectProfile({ readInstalled: read, ctl, guardSource: guard, allowLegacyGuard: true, allowPendingReload: true });
    const guardUnit = read(guardUnitPath);
    const starts = [oldStart, oldStart + ' --usb-dns=1', oldStart + ' --usb-dns=1 --usb-strict=1'];
    assert.ok(guardUnit?.split('\n').some(l => starts.includes(l)), 'unknown guard ExecStart');
    const upgradedUnit = guardUnit.split('\n').map(l => starts.includes(l) ? starts[2] : l).join('\n');
    const wrapper = read(wrapperPath), upgradedWrapper = usbDnsWrapper(wrapper);
    const pendingReload = ctl('show', 'clean-vpn-killswitch.service', '--property=NeedDaemonReload', '--value') === 'yes';
    validateUsbAddress(JSON.parse(run('ip', ['-j', 'address', 'show', 'dev', 'usb0'])));
    for (const [path, contents] of Object.entries(rescueFiles)) {
      assert.equal(read(path), contents, 'exact installed USB rescue required');
      if (!path.endsWith('.sh')) unit(path.split('/').at(-1), path);
    }
    for (const name of ['clean-vpn-usb-rescue.socket', 'clean-vpn-usb-rescue-address.service'])
      assert.equal(ctl('is-active', name), 'active', 'keep working USB rescue before upgrade');
    const snatUnit = read(gatewayUnitPath), snat = read(gatewayHelper);
    assert.equal(snatUnit === null, snat === null, 'partial USB SNAT installation refused');
    if (snatUnit !== null) {
      const node = /^ExecStart=(\/[^\s]+) /m.exec(snatUnit)?.[1];
      assert.ok(node, 'unknown SNAT unit');
      assert.equal(snatUnit, gatewayFiles(node)[gatewayUnitPath], 'unknown SNAT unit');
      assert.ok(snat === currentSnat || digest(snat) === legacyUsbSnatHash, 'unknown SNAT helper');
      unit(gatewayUnit, gatewayUnitPath);
    } else {
      assert.equal(ctl('show', gatewayUnit, '--property=LoadState', '--value'), 'not-found');
      assert.equal(ctl('show', gatewayUnit, '--property=DropInPaths', '--value'), '');
      assert.equal(ctl('show', gatewayUnit, '--property=ActiveState', '--value'), 'inactive');
    }
    const status = run(guardPath, ['status']).trim().split('\n');
    const versions = [4, 6].map(family => {
      const matches = [2, 3, 4].filter(v => status.includes(`[clean-vpn-killswitch] IPv${family}: cvks${v}:${profile}`));
      assert.equal(matches.length, 1, 'missing or unexpected guard profile'); return matches[0];
    });
    return { guard, guardUnit, upgradedUnit, wrapper, upgradedWrapper, pendingReload, snat, snatUnit, versions };
  };
  const before = preflight();
  const already = before.guard === currentGuard && (before.snat === null || before.snat === currentSnat)
    && before.versions.every(v => v === 4) && before.guardUnit === before.upgradedUnit && before.wrapper === before.upgradedWrapper && !before.pendingReload;
  if (!apply || already) return { status: already ? 'already-protected' : 'planned',
    guardVersions: before.versions, snatInstalled: before.snat !== null,
    changes: 'USB IPv4 forwarded only through TUN; USB IPv6 forwarding blocked; USB DNS intercepted through host tunnel DNS; local USB access retained',
    applyStops: ['clean-vpn.service', ...(before.snat !== null ? [gatewayUnit] : [])],
    automaticStart: false, requires: 'authenticated USB rescue verified by operator' };

  return lifecycle({ service: 'clean-vpn', requireGuard: true, log,
    beforeStop() { assert.deepEqual(preflight(), before, 'installation changed before stop'); },
  }, ({ command, ctl: lockedCtl, inspect }) => {
    assert.equal(inspect('clean-vpn-killswitch.service').ActiveState, 'active', 'guard must remain active');
    assert.deepEqual(preflight(), before, 'installation changed while stopping');
    if (before.snat !== null) {
      lockedCtl('stop', gatewayUnit);
      assert.equal(lockedCtl('show', gatewayUnit, '--property=ActiveState', '--value').trim(), 'inactive');
    }
    assert.equal(read(sourceGuardPath), currentGuard); assert.equal(read(sourceSnatPath), currentSnat);
    const backups = [];
    if (before.guard !== currentGuard) backups.push(publish(guardPath, before.guard, currentGuard));
    if (before.guardUnit !== before.upgradedUnit)
      backups.push(publish(guardUnitPath, before.guardUnit, before.upgradedUnit, undefined, 0o644));
    if (before.wrapper !== before.upgradedWrapper)
      backups.push(publish(wrapperPath, before.wrapper, before.upgradedWrapper));
    // Reload definitions only: no restart of guard or its network dependents.
    lockedCtl('daemon-reload');
    assert.equal(lockedCtl('show', 'clean-vpn-killswitch.service', '--property=NeedDaemonReload', '--value').trim(), 'no');
    // Current implementation audits exact v2/v3 chains and tests both families
    // before per-family atomic --noflush commits. No down/guard service restart.
    command(guardPath, ['up', '--scope=both', '--ipv6=block', '--tun=tun0', '--ssh-port=22', '--server=154.62.226.216', '--usb-dns=1', '--usb-strict=1']);
    const status = command(guardPath, ['status']).trim().split('\n');
    for (const f of [4, 6]) assert.ok(status.includes(`[clean-vpn-killswitch] IPv${f}: cvks4:${profile}`));
    if (before.snat !== null && before.snat !== currentSnat) {
      assert.equal(read(gatewayHelper), before.snat, 'SNAT changed during upgrade');
      backups.push(publish(gatewayHelper, before.snat, currentSnat));
    }
    return { status: 'upgraded-stopped', policy: 'cvks4-usb-tunnel-only', backups,
      startUnits: ['clean-vpn.service', ...(before.snat !== null ? [gatewayUnit] : [])],
      guardRetained: true, rescueRetained: true, networkdRestarted: false, automaticRecovery: false,
      limitation: 'USB ingress only; local services on Radxa and other Mac interfaces are not application-isolated' };
  });
}
