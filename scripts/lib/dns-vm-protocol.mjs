import assert from 'node:assert/strict';

export function vmSerialEvent(line) {
  // PID1 can write a non-newline-terminated status message before a service's
  // complete JSON line. Do not silently lose that result on a shared console.
  const at = line.indexOf('DNS_VM_EVENT ');
  return at < 0 ? null : JSON.parse(line.slice(at + 13));
}

export const VM_CUT_POINTS = Object.freeze([
  'prepared:file-synced', 'prepared:renamed', 'apply:DNSEx:intent:dir-synced',
  'apply:DNSEx:set', 'apply:Domains:ack:dir-synced', 'restore:DNSEx:set',
  'restore:DefaultRoute:ack:dir-synced', 'guard-removed',
]);
export const VM_FAULTS = Object.freeze(['guard-unavailable', 'storage-readonly', 'corrupt-journal', 'adapter-unready']);
export const VM_COUPLED_CUTS = Object.freeze(['apply:DNSEx:set', 'restore:DNSEx:set', 'link-released']);
export const VM_RADXA_CUTS = Object.freeze(['resolver:apply:set', 'resolver:restore:set', 'dnsmasq:restore:daemon:set']);
export const VM_RADXA_CHECKS = Object.freeze(['failed-guard-prevents-services', 'paired-readiness-and-dhcp',
  'controller-restart-same-transaction', 'exit-outage-preserves-dhcp', 'adapter-sigkill-preserves-dhcp',
  'dnsmasq-sigkill-recovered', 'foreign-resolver-preserves-four-journals', 'offline-rollback-verifies-daemon-before-release',
  'restored-start-refused', 'stale-four-journals-refused',
  'unprivileged-system-dns-and-private-journal', 'unprivileged-baseline-after-restore', 'cross-mount-resolver-rejected']);
export const VM_RADXA_GUARD_CHECKS = Object.freeze(['boot-guard-cli-before-network', 'cli-adapter-readiness-and-isolation',
  'active-dns-refuses-release', 'missing-guard-journal-retains-protection']);
export function assertVmRadxaEvidence(e, cut) {
  assert.equal(e.phase, cut ? 'radxa-inspect' : 'radxa');
  assert.ok(cut ? VM_RADXA_CUTS.includes(e.point) : e.point === 'lifecycle');
  for (const key of ['systemdPid1', 'fourJournalsPreserved', 'exactLocalhostBaselineRestored', 'verifiedGuardRelease',
    'baselinePositiveControl', 'unprivilegedAdapter', 'sharedGuardDnsLock']) assert.equal(e[key], true, key);
  assert.equal(e.bootGuardImplementation, 'cli'); assert.equal(e.adapterImplementation, 'cli');
  assert.equal(e.dhcpPreservedOnAdapterFailure, !cut);
  assert.equal(e.automaticStaleAdoption, false); assert.equal(e.baselineQueriesDuringProtection, 0);
  const once = ['stale-four-journals-refused', 'paired-readiness-and-dhcp', 'offline-rollback-verifies-daemon-before-release',
    'unprivileged-system-dns-and-private-journal', 'unprivileged-baseline-after-restore', 'cross-mount-resolver-rejected'];
  assert.deepEqual([...e.checks].sort(), (cut ? [...once, ...VM_RADXA_GUARD_CHECKS.slice(0, 2), ...VM_RADXA_GUARD_CHECKS]
    : [...VM_RADXA_CHECKS, ...once.slice(1), ...VM_RADXA_GUARD_CHECKS, ...VM_RADXA_GUARD_CHECKS]).sort());
  if (cut) {
    assert.equal(cut.event, 'cut-ready'); assert.equal(cut.point, e.point); assert.deepEqual(e.inspected, { ...cut.journals, guard: cut.guard });
    assert.equal(cut.guard.stage, 'active'); assert.equal(cut.guard.input.client, 'radxa');
    assert.equal(cut.guard.context.bootId, e.previousBootId);
    const { root, dnsmasq: d, resolver: s } = cut.journals;
    assert.equal(root.id, d.id); assert.equal(root.id, s.id);
    assert.equal(root.dnsmasq.context.bootId, e.previousBootId);
    assert.equal(d.context.bootId, e.previousBootId); assert.equal(s.context.bootId, e.previousBootId);
    assert.deepEqual([root.phase, d.direction, d.cursor, d.pending, s.phase], ({
      'resolver:apply:set': ['resolver', 'apply', 2, false, 'apply-intent'],
      'resolver:restore:set': ['restore-resolver', 'apply', 2, false, 'restore-intent'],
      'dnsmasq:restore:daemon:set': ['restore-dnsmasq', 'restore', 1, true, 'restored'],
    })[e.point]);
  }
}
export const VM_COUPLED_CHECKS = Object.freeze(['failed-guard-prevents-services', 'readiness-owned-link-and-protected-dns',
  'controller-stop-retains-protection', 'exit-outage-no-baseline-fallback', 'adapter-sigkill-recovery-same-transaction',
  'foreign-policy-preserved', 'disable-removes-owned-link-before-baseline-release', 'released-journal-start-refused',
  'stale-journals-preserved-start-refused']);
export const VM_COUPLED_GUARD_CHECKS = Object.freeze(['boot-guard-cli-before-network', 'cli-adapter-readiness-and-isolation',
  'bound-guard-refuses-active-link', 'missing-guard-journal-retains-protection']);
export const VM_INSTALLED_CHECKS = Object.freeze(['boot-guard-cli-before-network',
  'installed-cli-baseline-and-refusals', 'installed-controller-start-disable']);
export const VM_DEPLOYMENT_CHECKS = Object.freeze(['fresh-inactive-systemd-and-firewall',
  'loaded-inactive-service-accepted', 'running-service-refused', 'owned-link-refused', 'owned-guard-refused',
  'runtime-history-refused', 'fresh-state-rechecked-after-cleanup']);
export function assertVmDeploymentEvidence(e) {
  assert.equal(e.phase, 'coupled'); assert.equal(e.point, 'deployment');
  assert.equal(e.systemdPid1, true); assert.equal(e.freshDeploymentCheck, true);
  assert.equal(e.installationTested, false); assert.equal(e.dnsQueriesSent, 0); assert.equal(e.resolvConfUnchanged, true);
  assert.deepEqual([...e.checks].sort(), [...VM_DEPLOYMENT_CHECKS, ...VM_DEPLOYMENT_CHECKS].sort());
}
export const VM_PUBLICATION_CHECKS = Object.freeze(['full-code-and-client-files-published',
  'installed-entrypoint-imports', 'inactive-config-revoked-code-retained']);
export function assertVmPublicationEvidence(e) {
  assert.equal(e.phase, 'coupled'); assert.equal(e.point, 'publication');
  assert.equal(e.systemdPid1, true); assert.equal(e.filePublicationTested, true); assert.equal(e.activationTested, false);
  assert.equal(e.dnsQueriesSent, 0); assert.equal(e.resolvConfUnchanged, true);
  assert.deepEqual([...e.checks].sort(), [...VM_PUBLICATION_CHECKS, ...VM_PUBLICATION_CHECKS].sort());
}
export function assertVmInstalledEvidence(e) {
  assert.equal(e.phase, 'coupled'); assert.ok(['installed', 'installed-units'].includes(e.point));
  assert.equal(e.systemdPid1, true); assert.equal(e.installedController, true);
  assert.equal(e.resolvConfUnchanged, true); assert.equal(e.activeTransactionRebootTested, false);
  const checks = e.point === 'installed-units' ? [...VM_INSTALLED_CHECKS, 'installed-service-stop-restart-adapter-failure'] : VM_INSTALLED_CHECKS;
  assert.deepEqual([...e.checks].sort(), [...checks, ...checks].sort());
}
export function assertVmCoupledEvidence(evidence, cut) {
  assert.equal(evidence.phase, cut ? 'coupled-inspect' : 'coupled');
  assert.ok(cut ? VM_COUPLED_CUTS.includes(evidence.point) : evidence.point === 'lifecycle');
  for (const key of ['systemdPid1', 'baselinePositiveControl', 'explicitDisablePassed', 'ownedLinkRemoved',
    'bothJournalsPreservedOnRefusal', 'resolvConfUnchanged', 'unprivilegedAdapter', 'persistentBootGuardJournal',
    'sharedGuardDnsLock', 'coupledRestoreProof', 'threeJournalsPreservedOnRefusal']) assert.equal(evidence[key], true, key);
  assert.equal(evidence.bootGuardImplementation, 'cli'); assert.equal(evidence.adapterImplementation, 'cli');
  assert.equal(evidence.automaticStaleAdoption, false); assert.equal(evidence.baselineQueriesDuringProtection, 0);
  const once = ['stale-journals-preserved-start-refused', 'readiness-owned-link-and-protected-dns', 'disable-removes-owned-link-before-baseline-release'];
  const expected = cut ? [...once, ...VM_COUPLED_GUARD_CHECKS.slice(0, 2), ...VM_COUPLED_GUARD_CHECKS]
    : [...VM_COUPLED_CHECKS, ...once.slice(1), ...VM_COUPLED_GUARD_CHECKS, ...VM_COUPLED_GUARD_CHECKS,
      'installed-cli-baseline-and-refusals', 'installed-cli-baseline-and-refusals', 'installed-controller-start-disable'];
  assert.deepEqual([...evidence.checks].sort(), expected.sort());
  if (cut) {
    assert.equal(cut.event, 'cut-ready'); assert.equal(cut.point, evidence.point);
    assert.deepEqual(evidence.inspected, { root: cut.root, child: cut.child, guard: cut.guard });
    const r = cut.root, child = cut.child;
    assert.equal(child.id, r.id); assert.deepEqual(child.context, r.context);
    assert.equal(r.context.bootId, evidence.previousBootId);
    assert.equal(cut.guard.context.bootId, evidence.previousBootId); assert.equal(cut.guard.input.id, 'b'.repeat(32));
    assert.equal(cut.guard.stage, 'active');
    assert.deepEqual([r.phase, r.direction, r.level, r.pending, child.stage], ({
      'apply:DNSEx:set': ['settings', 'apply', 4, true, 'created'],
      'restore:DNSEx:set': ['settings', 'restore', 5, true, 'created'],
      'link-released': ['unlink', 'restore', 0, false, 'released'],
    })[evidence.point]);
  }
}
export const VM_SYSTEMD_CHECKS = Object.freeze([
  'boot-guard-cli-before-network', 'boot-guard-stop-retains-owned-rules',
  'boot-journal-release-refuses-active-dns',
  'missing-guard-journal-retains-protection',
  'cli-start-refuses-unready-exit',
  'failed-guard-prevents-network-and-consumer', 'real-service-readiness-before-consumer',
  'controller-stop-retains-guard-and-restart-recovers', 'exit-outage-no-baseline-fallback',
  'adapter-sigkill-stops-dependents-restart-recovers', 'foreign-policy-not-overwritten',
  'explicit-disable-restores-owned-baseline', 'reboot-stale-journal-refused-with-guard',
  'released-journal-restart-refused-under-guard',
]);
export function assertVmSystemdEvidence(evidence) {
  assert.equal(evidence.phase, 'systemd'); assert.equal(evidence.point, 'lifecycle');
  assert.equal(evidence.systemdPid1, true); assert.equal(evidence.automaticStaleAdoption, false);
  assert.equal(evidence.adapterImplementation, 'cli'); assert.equal(evidence.separateExitFixture, true);
  assert.equal(evidence.readinessQueriesPerStart, 4);
  assert.equal(evidence.unprivilegedAdapter, true); assert.equal(evidence.systemdCredentials, true);
  assert.equal(evidence.bootGuardImplementation, 'cli'); assert.equal(evidence.bootGuardBeforeNetwork, true);
  assert.equal(evidence.persistentBootGuardJournal, true); assert.equal(evidence.sharedGuardDnsLock, true);
  assert.equal(evidence.exactRestoreProof, true);
  assert.equal(evidence.baselineQueriesDuringProtection, 0); assert.equal(evidence.baselinePositiveControl, true);
  assert.equal(evidence.explicitDisablePassed, true); assert.equal(evidence.resolvConfUnchanged, true);
  assert.deepEqual([...new Set(evidence.checks)].sort(), [...VM_SYSTEMD_CHECKS].sort());
  for (const label of VM_SYSTEMD_CHECKS) assert.equal(evidence.checks.filter((v) => v === label).length,
    ['boot-guard-cli-before-network', 'boot-guard-stop-retains-owned-rules', 'boot-journal-release-refuses-active-dns', 'missing-guard-journal-retains-protection', 'real-service-readiness-before-consumer', 'explicit-disable-restores-owned-baseline'].includes(label) ? 2 : 1, label);
}
export const VM_DNSMASQ_CHECKS = Object.freeze([
  'failed-guard-prevents-services', 'service-readiness-and-usb-dhcp', 'controller-stop-retains-protection',
  'exit-outage-preserves-dhcp-local-name', 'adapter-sigkill-preserves-dhcp-and-stops-consumer',
  'daemon-sigkill-and-journal-recovery', 'foreign-config-not-overwritten', 'explicit-disable-restores-baseline',
  'released-journal-start-refused', 'reboot-stale-journal-refused',
]);
export function assertVmDnsmasqEvidence(evidence) {
  assert.equal(evidence.phase, 'dnsmasq'); assert.equal(evidence.point, 'lifecycle');
  for (const key of ['systemdPid1', 'dhcpPreservedOnAdapterFailure', 'explicitDisablePassed', 'resolvConfUnchanged', 'baselinePositiveControl']) assert.equal(evidence[key], true, key);
  assert.equal(evidence.automaticStaleAdoption, false); assert.equal(evidence.baselineQueriesDuringProtection, 0);
  assert.deepEqual([...new Set(evidence.checks)].sort(), [...VM_DNSMASQ_CHECKS].sort());
  for (const label of VM_DNSMASQ_CHECKS) assert.equal(evidence.checks.filter((v) => v === label).length,
    ['service-readiness-and-usb-dhcp', 'explicit-disable-restores-baseline'].includes(label) ? 2 : 1);
}
export function vmCases(selected = 'all') {
  if (selected === 'all') return ['none', ...VM_CUT_POINTS];
  if (selected === 'faults') return [...VM_FAULTS];
  if (selected === 'cycle') return ['none'];
  if (selected === 'systemd') return ['lifecycle'];
  if (selected === 'dnsmasq') return ['lifecycle'];
  if (selected === 'radxa') return ['lifecycle'];
  if (selected === 'radxa-cuts') return [...VM_RADXA_CUTS];
  if (selected.startsWith('radxa-cut:')) {
    const point = selected.slice('radxa-cut:'.length); assert.ok(VM_RADXA_CUTS.includes(point)); return [point];
  }
  if (selected === 'coupled') return ['lifecycle'];
  if (selected === 'installed') return ['installed'];
  if (selected === 'installed-units') return ['installed-units'];
  if (selected === 'deployment') return ['deployment'];
  if (selected === 'publication') return ['publication'];
  if (selected === 'coupled-cuts') return [...VM_COUPLED_CUTS];
  if (selected.startsWith('coupled-cut:')) {
    const point = selected.slice('coupled-cut:'.length);
    assert.ok(VM_COUPLED_CUTS.includes(point), 'unknown coupled VM cut'); return [point];
  }
  assert.ok([...VM_CUT_POINTS, ...VM_FAULTS].includes(selected), 'unknown VM case');
  return [selected];
}
export function assertVmFaultEvidence(point, evidence) {
  assert.ok(VM_FAULTS.includes(point));
  assert.equal(evidence.point, point); assert.equal(evidence.status, 'passed');
  for (const key of ['dnsUnchangedOnFailure', 'noSettersOnFailure', 'blockedAfterFailure', 'explicitRecoveryPassed']) assert.equal(evidence[key], true, key);
  assert.equal(evidence.failure, ({ 'guard-unavailable': 'permission-denied', 'storage-readonly': 'EROFS',
    'corrupt-journal': 'SyntaxError', 'adapter-unready': 'readiness-failed' })[point]);
  if (point === 'guard-unavailable') {
    assert.equal(evidence.guardClaimedInstalledOnFailure, false); assert.equal(evidence.loopbackStayedDown, true);
    assert.equal(evidence.consumersStartedOnFailure, false);
  } else assert.equal(evidence.guardRetained, true);
  if (point === 'corrupt-journal') assert.equal(evidence.corruptBytesPreserved, true);
  if (point === 'adapter-unready') assert.equal(evidence.sameTransactionRecovered, true);
}
export function assertVmJournalCheckpoint(record, point) {
  const states = {
    none: ['apply', 3, false, 'complete'],
    'prepared:renamed': ['apply', 0, false, 'running'],
    'apply:DNSEx:intent:dir-synced': ['apply', 0, true, 'running'],
    'apply:DNSEx:set': ['apply', 0, true, 'running'],
    'apply:Domains:ack:dir-synced': ['apply', 2, false, 'running'],
    'restore:DNSEx:set': ['restore', 0, true, 'running'],
    'restore:DefaultRoute:ack:dir-synced': ['restore', 3, false, 'complete'],
    'guard-removed': ['restore', 3, false, 'complete'],
  };
  assert.ok(Object.hasOwn(states, point), 'unexpected committed journal');
  assert.deepEqual([record.direction, record.cursor, record.pending, record.stage], states[point]);
}
export function vmBootOptions(cmdline) {
  const fields = cmdline.trim().split(/\s+/).filter((v) => v.startsWith('meshpn_'));
  assert.equal(fields.length, 3, 'VM fixture parameters required');
  const get = (name) => {
    const entries = fields.filter((v) => v.startsWith(`${name}=`)); assert.equal(entries.length, 1);
    return entries[0].slice(name.length + 1);
  };
  assert.equal(get('meshpn_dns_vm'), 'isolated-v1');
  const phase = get('meshpn_phase'), point = get('meshpn_point');
  assert.ok(['cycle', 'cut', 'inspect', 'fault', 'systemd', 'dnsmasq', 'coupled', 'coupled-cut', 'coupled-inspect', 'radxa', 'radxa-cut', 'radxa-inspect'].includes(phase));
  assert.ok(phase === 'cycle' ? point === 'none' : phase === 'fault' ? VM_FAULTS.includes(point)
    : phase === 'coupled' ? ['lifecycle', 'installed', 'installed-units', 'deployment', 'publication'].includes(point)
      : ['systemd', 'dnsmasq', 'radxa'].includes(phase) ? point === 'lifecycle'
      : phase.startsWith('radxa-') ? VM_RADXA_CUTS.includes(point)
        : phase.startsWith('coupled-') ? VM_COUPLED_CUTS.includes(point) : VM_CUT_POINTS.includes(point));
  return { phase, point };
}
// A shutdown request may terminate the driver before systemctl returns. This
// only classifies the log: actual sync/unmount/reboot and result evidence remain
// mandatory in the launcher, including after an expected signal termination.
export function vmDriverFailureIsFatal(line, terminalRequested = false) {
  if (!/dns-vm-driver\.service: Failed with result/.test(line)) return false;
  return !(terminalRequested && /dns-vm-driver\.service: Failed with result 'signal'\.$/.test(line));
}
export function qemuDnsArgs({ root, kernel, initrd, disk, phase, point }) {
  vmBootOptions(`meshpn_dns_vm=isolated-v1 meshpn_phase=${phase} meshpn_point=${point}`);
  for (const path of [root, kernel, initrd, disk]) assert.ok(path.startsWith('/') && !/[,\n\r\0]/.test(path));
  return ['-nodefaults', '-no-user-config', '-nic', 'none', '-display', 'none', '-monitor', 'none',
    // Only the parent may launch another boot; unexpected reboot/panic cannot hide a failed attempt.
    '-no-reboot',
    // The real CLI keeps its 1500ms production deadline. Give the synthetic
    // client and separate exit/origin CPU execution capacity as on two hosts;
    // other historical fault/fixture cases retain their original single vCPU.
    '-serial', 'stdio', '-accel', phase === 'systemd' || /^(coupled|radxa)/.test(phase) ? 'tcg,thread=multi' : 'tcg',
    '-cpu', 'max', '-m', '1024', '-smp', phase === 'systemd' || /^(coupled|radxa)/.test(phase) ? '2' : '1',
    '-machine', 'pc,dump-guest-core=off', '-bios', `${root}/usr/share/seabios/bios-256k.bin`,
    '-L', `${root}/usr/share/qemu`, '-kernel', kernel, '-initrd', initrd,
    '-append', `console=ttyS0 quiet panic=-1 reboot=t random.trust_cpu=on meshpn_dns_vm=isolated-v1 meshpn_phase=${phase} meshpn_point=${point}`,
    '-drive', `file=${disk},format=raw,if=virtio,cache=writeback`];
}
