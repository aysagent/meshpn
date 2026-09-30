import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
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
test('uninstaller retains recovery files when stop or guard removal fails', () => {
  const source = readFileSync(new URL('./autostart/uninstall.sh', import.meta.url), 'utf8');
  assert.match(source, /systemctl stop "\$SERVICE_NAME" \|\| die/);
  assert.match(source, /systemctl stop "\$KS_UNIT_NAME" \|\| die/);
  assert.match(source, /"\$KS_SH" down --tun=tun0 \|\| die/);
  assert.ok(source.indexOf('"$KS_SH" down') < source.indexOf('systemctl disable "$SERVICE_NAME"'));
  assert.ok(source.indexOf('"$KS_SH" down') < source.indexOf('rm -f "$f"'));
});
