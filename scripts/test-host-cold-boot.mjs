import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { BOOT_FILES, hostBootVmUnits, assertHostBootVm } from './lib/vpn-host-boot-vm.mjs';
import { hostBootChecks, assertHostBootEvidence } from './lib/vpn-host-boot-evidence.mjs';

const evidence = () => ({ nic: 'none', hostSharedFilesystem: false, acceptance: 'lab-ready-for-host-review',
  boots: [0, 1, 2].map(phase => ({ phase, exitCode: 0, kernelRestart: phase < 2, powerDown: phase === 2, synced: true, unmounted: true,
    events: [{ event: 'prepared', phase, linkInitiallyDown: true }, ...hostBootChecks(phase).map(name => ({ event: 'check', phase, name })),
      { event: phase < 2 ? 'reboot-ready' : 'passed', phase, bootId: `11111111-1111-1111-1111-11111111111${phase}`, checks: hostBootChecks(phase), actualNetworkdInstaller: true, acceptance: phase < 2 ? 'matrix-pending' : 'lab-ready-for-host-review',
        limitations: ['virtual-ethernet-not-wifi', 'no-initramfs-network', 'no-power-cut', 'host-preflight-and-console-review-required'] }] })) });

test('cold boot mutations refuse development host before topology or files', () => {
  for (const mode of ['prepare', 'fixture', 'run']) {
    assert.throws(() => assertHostBootVm(mode), /meshpn.host-cold-boot/);
    const p = spawnSync(process.execPath, ['scripts/lib/vpn-host-boot-vm.mjs', mode], { encoding: 'utf8', timeout: 5000 });
    assert.equal(p.status, 1); assert.match(p.stderr, /meshpn.host-cold-boot/);
  }
});
test('cold boot evidence requires three independent synchronized kernel boots', () => {
  assertHostBootEvidence(evidence());
  for (const key of ['synced', 'unmounted']) { const r = evidence(); r.boots[1][key] = false; assert.throws(() => assertHostBootEvidence(r)); }
  for (const key of ['kernelRestart', 'powerDown']) { const r = evidence(); r.boots[1][key] = !r.boots[1][key]; assert.throws(() => assertHostBootEvidence(r)); }
  const repeated = evidence(); repeated.boots[1].events.at(-1).bootId = repeated.boots[0].events.at(-1).bootId; assert.throws(() => assertHostBootEvidence(repeated));
  const truncated = evidence(); truncated.boots.pop(); assert.throws(() => assertHostBootEvidence(truncated));
});
test('cold boot evidence rejects missing assertions, duplicate terminals and readiness claims', () => {
  for (const phase of [0, 1, 2]) for (const name of hostBootChecks(phase)) {
    const r = evidence(); r.boots[phase].events = r.boots[phase].events.filter(e => e.name !== name); assert.throws(() => assertHostBootEvidence(r), name);
  }
  for (const phase of [0, 1, 2]) {
    const r = evidence(); r.boots[phase].events.push(r.boots[phase].events.at(-1)); assert.throws(() => assertHostBootEvidence(r));
    const failed = evidence(); failed.boots[phase].events.push({ event: 'failed' }); assert.throws(() => assertHostBootEvidence(failed));
    const ready = evidence(); ready.boots[phase].events.at(-1).acceptance = 'ready'; assert.throws(() => assertHostBootEvidence(ready));
  }
});
test('fixture uses real networkd/udev socket activation, not a container marker or namespace override', () => {
  const image = readFileSync(new URL('./lib/dns-vm-image.mjs', import.meta.url), 'utf8');
  assert.match(image, /if \(!hostColdBoot\) await symlink\('\/dev\/null'/);
  for (const unit of ['systemd-udevd.service', 'systemd-udev-trigger.service', 'systemd-networkd.socket']) assert.ok(image.includes(unit));
  const source = readFileSync(new URL('./lib/vpn-host-boot-vm.mjs', import.meta.url), 'utf8');
  assert.match(source, /DHCP=ipv4/); assert.match(source, /--dhcp-range=192\.0\.2\.2/);
  assert.doesNotMatch(source, /put\('\/run\/systemd\/container'/);
  assert.match(source, /copyFileSync\('\/' \+ name, dst\)/);
  assert.equal(BOOT_FILES.length, 6); assert.equal(new Set(BOOT_FILES).size, 6);
  assert.ok(BOOT_FILES.every(p => /^(?:etc\/systemd\/system\/|usr\/local\/bin\/)/.test(p) && !p.includes('..')));
  assert.ok(hostBootVmUnits()['default.target'].includes('systemd-networkd.service'));
});
test('cold boot runner rejects missing/ambiguous flags before QEMU or disk creation', () => {
  for (const a of [[], ['--apply'], ['--tools=/tmp/a', '--tools=/tmp/b'], ['--tools=relative']]) {
    const p = spawnSync(process.execPath, ['scripts/clean-vpn-host-boot-lab.mjs', ...a], { encoding: 'utf8', timeout: 5000 });
    assert.equal(p.status, 1); assert.doesNotMatch(p.stderr, /Host boot VM artifacts/);
  }
});
