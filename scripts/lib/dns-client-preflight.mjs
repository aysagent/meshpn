/** One support bundle for the explicitly selected DNS v1 client. Read-only, never an installer. */
import assert from 'node:assert/strict';
import { collectDnsDiagnostic } from './dns-diagnostic.mjs';
import { collectDnsClientOwnership } from './dns-client-ownership.mjs';

export function parseClientPreflightArgs(args) {
  if (args.length === 1 && args[0] === '--help') return { help: true };
  const result = { probe: false }, seen = new Set();
  for (const arg of args) {
    if (arg === '--probe' && !seen.has('probe')) { result.probe = true; seen.add('probe'); continue; }
    const match = /^--client=(vps2|radxa)$/.exec(arg);
    assert.ok(match && !seen.has('client'), 'Usage: node scripts/dns-client-preflight.mjs --client=vps2|radxa [--probe]');
    result.client = match[1]; seen.add('client');
  }
  assert.ok(result.client, 'Explicit --client=vps2 or --client=radxa required'); return result;
}

export function assessClientPreflight(client, diagnostic, ownership) {
  assert.ok(['vps2', 'radxa'].includes(client));
  const issues = new Set(), pending = ['independent-emergency-access', 'explicit-live-change-approval',
    'numeric-exit-and-authenticated-upstream-config', 'live-client-units-and-guard-review', 'bounded-24h-client-pilot'];
  const inspection = diagnostic.inspection ?? {};
  if (inspection.environment?.pid1 !== 'systemd') issues.add('actual-systemd-client-not-confirmed');
  if (diagnostic.runtime?.uid !== 0) issues.add('non-root-report-may-omit-ownership-evidence');
  if (diagnostic.deadlineExceeded || ownership.deadlineExceeded) issues.add('collection-deadline-exceeded');
  if (inspection.resolver?.mountpoint !== false) issues.add('resolver-mountpoint-or-unknown');
  if (inspection.nss?.status !== 'ok' || inspection.nss.customService || inspection.nss.entries !== 1) issues.add('nss-policy-review-required');
  for (const name of ['NetworkManager.service', 'resolvconf.service']) {
    if (!['inactive', 'not-found'].includes(inspection.units?.[name])) issues.add('other-DNS-manager-active-or-unknown');
  }
  if (ownership.status !== 'collected') issues.add('ownership-collection-incomplete');
  const fields = (name) => ownership.units?.[name]?.fields;
  for (const name of client === 'vps2' ? ['systemd-resolved.service', 'systemd-networkd.service'] : ['dnsmasq.service']) {
    const unit = fields(name);
    if (!unit || unit.ActiveState !== 'active' || unit.LoadState !== 'loaded' || !unit.MainPID || !unit.InvocationID) issues.add(`${name}:no-active-identity`);
    if (!unit || unit.NeedDaemonReload !== 'no') issues.add(`${name}:unit-reload-or-unknown`);
    if (unit && (unit.RootDirectory !== '' || unit.RootImage !== '' || unit.NetworkNamespacePath !== '' || unit.PrivateNetwork !== 'no')) issues.add(`${name}:namespace-or-root-policy-review`);
  }
  if (diagnostic.probes?.length) {
    if (diagnostic.probes.length !== 5 || diagnostic.probes.some((p) => p.result?.status !== 'ok'
      || (p.kind === 'system-nss-A' ? !p.result.stdout?.trim() : !/status: NOERROR[,\s]/.test(p.result.stdout ?? '')
        || !/ANSWER: [1-9]\d*[,\s]/.test(p.result.stdout ?? '')))) issues.add('baseline-probes-incomplete-or-failed');
  } else pending.push('explicit-baseline-DNS-probes');
  if (client === 'vps2') {
    pending.push('explicit-cloud-name-policy');
    if (inspection.resolver?.status !== 'ok' || inspection.resolver?.targetKind !== 'resolved-stub') issues.add('resolved-stub-baseline-not-confirmed');
    if (diagnostic.resolved?.owner?.status !== 'ok') issues.add('resolved-bus-owner-unavailable');
    if (!['inactive', 'not-found'].includes(fields('dnsmasq.service')?.ActiveState)
      && fields('dnsmasq.service')?.LoadState !== 'not-found') issues.add('additional-dnsmasq-service-or-unknown');
    if (ownership.networkdLinksTruncated || ownership.networkdLinkListUnavailable) issues.add('networkd-link-inventory-incomplete');
    const uplink = ownership.networkd?.find((l) => l.name === 'eth0');
    if (!uplink || uplink.status !== 'ok' || !uplink.stable || uplink.selectedConfig?.status !== 'ok'
      || uplink.state?.ADMIN_STATE !== 'configured') issues.add('eth0-selected-network-file-not-confirmed');
    if (uplink?.selectedConfig?.metadata && (uplink.selectedConfig.metadata.uid !== 0 || uplink.selectedConfig.metadata.writableByGroupOrOther)) issues.add('eth0-network-file-ownership-review');
    pending.push('networkd-selected-file-and-dropin-policy-review');
  } else {
    pending.push('dnsmasq-unit-and-config-review', 'explicit-USB-DHCP-DNS-policy', 'healthy-localhost-baseline-plan');
    const daemon = ownership.dnsmasq;
    if (daemon?.status !== 'ok' || !daemon.cgroupMatchesUnit || !['net', 'mnt', 'pid'].every((k) => daemon.namespacesMatch?.[k] === true)) issues.add('dnsmasq-running-owner-not-confirmed');
    if (!daemon?.sourceGraphComplete) issues.add('dnsmasq-config-source-inventory-incomplete');
    for (const r of Object.values(daemon?.configs ?? {})) {
      if (r.status !== 'ok' || r.metadata?.uid !== 0 || r.metadata?.writableByGroupOrOther) issues.add('dnsmasq-config-ownership-review');
    }
    if (inspection.resolver?.object === 'symlink' && inspection.resolver.targetStatus === 'missing') issues.add('dangling-resolver-needs-separate-baseline-repair');
    else if (inspection.resolver?.status !== 'ok') issues.add('system-resolver-baseline-unavailable');
    if (!['inactive', 'not-found'].includes(inspection.units?.['systemd-resolved.service'])) issues.add('resolved-competes-with-dnsmasq-or-unknown');
    if (diagnostic.dnsmasq?.assessment?.reasons?.includes('multiple-dhcp-dns-declarations-in-inventory-review-effective-offer')) issues.add('DHCP-DNS-declarations-need-explicit-normalization');
  }
  return { status: issues.size ? 'needs-evidence-or-repair' : 'ready-for-manual-review', observedIssues: [...issues], pendingOperatorDecisions: pending,
    installationAllowed: false, dnsV1Complete: false, next: 'review-report-then-prepare-explicit-client-plan',
    note: 'Even a complete stable inventory is not proof of loaded config, approval to mutate, or a DNS leak test.' };
}

export async function collectClientPreflight(options, { diagnostic = collectDnsDiagnostic, ownership = collectDnsClientOwnership } = {}) {
  assert.ok(['vps2', 'radxa'].includes(options.client));
  const startedAt = new Date().toISOString(), d = await diagnostic({ probe: options.probe === true }), o = await ownership(d);
  return { schema: 1, kind: 'clean-vpn-dns-client-preflight', client: options.client, mode: 'read-only', startedAt,
    finishedAt: new Date().toISOString(), systemSettingsChanged: false, installationAttempted: false,
    privacy: 'Contains IPs, domains, config paths and selected DNS argv options; no raw argv, environment, credentials or journals. Review before sharing.',
    diagnostic: d, ownership: o, assessment: assessClientPreflight(options.client, d, o) };
}
