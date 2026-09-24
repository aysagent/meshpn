/** Read-only evidence collection. Never selects or applies an OS DNS backend. */
import { constants } from 'node:fs';
import { open, lstat, realpath, readlink } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { isIP } from 'node:net';
import { runCommand } from './transparent-acceptance.mjs';

export const DNS_INSPECT_FILES = Object.freeze({
  resolver: '/etc/resolv.conf', nss: '/etc/nsswitch.conf', init: '/proc/1/comm', mounts: '/proc/self/mountinfo',
});
export const DNS_INSPECT_UNITS = Object.freeze(['systemd-resolved.service', 'NetworkManager.service',
  'systemd-networkd.service', 'resolvconf.service']);

function errorKind(error) {
  return ({ ENOENT: 'missing', ENOTDIR: 'missing', EACCES: 'permission-denied', EPERM: 'permission-denied',
    ELOOP: 'symlink-loop' })[error.code] ?? 'unavailable';
}
export async function inspectResolverMetadata(path = DNS_INSPECT_FILES.resolver) {
  const stat = await lstat(path), kind = stat.isSymbolicLink() ? 'symlink' : stat.isFile() ? 'regular' : 'other';
  // Preserve the symlink and its declared target even if realpath fails.
  let declaredTarget;
  if (kind === 'symlink') {
    try { declaredTarget = resolve(dirname(path), await readlink(path)); }
    catch (error) { return { kind, targetStatus: errorKind(error) }; }
  }
  try { return { kind, declaredTarget, target: await realpath(path), targetStatus: 'available' }; }
  catch (error) { return { kind, declaredTarget, targetStatus: errorKind(error) }; }
}

export async function boundedInspectRead(path, limit = 65536) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = await fd.stat();
    if (!stat.isFile() || stat.size > limit) throw new Error('unsafe or oversized input');
    // proc files commonly report size=0; never rely on stat.size to bound reads.
    const buffer = Buffer.alloc(limit + 1); let used = 0;
    while (used < buffer.length) {
      const { bytesRead } = await fd.read(buffer, used, buffer.length - used, null);
      if (!bytesRead) break;
      used += bytesRead;
    }
    if (used > limit) throw new Error('oversized input');
    return buffer.subarray(0, used).toString('utf8');
  } finally { await fd.close(); }
}

function targetKind(path) {
  if (['/run/systemd/resolve/stub-resolv.conf', '/usr/lib/systemd/resolv.conf', '/lib/systemd/resolv.conf'].includes(path)) return 'resolved-stub';
  if (path === '/run/systemd/resolve/resolv.conf') return 'resolved-uplink';
  if (path === '/run/NetworkManager/resolv.conf') return 'networkmanager';
  if (path === '/run/resolvconf/resolv.conf') return 'resolvconf';
  return path === '/etc/resolv.conf' ? 'regular-path' : 'other';
}
function resolverSummary(contents) {
  const result = { nameservers: { ipv4: 0, ipv6: 0, loopback: 0, invalid: 0 },
    resolvedStubAddress: false, searchConfigured: false, hints: [] };
  for (const line of contents.split('\n')) {
    if (/^\s*[#;]/.test(line)) {
      for (const [pattern, hint] of [[/systemd-resolved/i, 'resolved'], [/NetworkManager/i, 'networkmanager'], [/resolvconf/i, 'resolvconf']]) {
        if (pattern.test(line) && !result.hints.includes(hint)) result.hints.push(hint);
      }
    }
    const fields = line.split(/[#;]/, 1)[0].trim().split(/\s+/);
    if (['search', 'domain'].includes(fields[0]) && fields.length > 1) result.searchConfigured = true;
    if (fields[0] !== 'nameserver') continue;
    const address = fields[1] ?? '', family = isIP(address);
    result.nameservers[family === 4 ? 'ipv4' : family === 6 ? 'ipv6' : 'invalid']++;
    if ((family === 4 && address.startsWith('127.')) || address === '::1') result.nameservers.loopback++;
    if (address === '127.0.0.53' || address === '127.0.0.54') result.resolvedStubAddress = true;
  }
  return result;
}
function nssSummary(contents) {
  const lines = contents.split('\n').map((line) => line.split('#', 1)[0]).filter((line) => /^\s*hosts\s*:/.test(line));
  const known = new Set(['files', 'dns', 'resolve', 'myhostname', 'mymachines', 'mdns', 'mdns4', 'mdns6', 'mdns_minimal', 'mdns4_minimal', 'mdns6_minimal']);
  const services = [];
  for (const line of lines) for (const token of line.replace(/^\s*hosts\s*:/, '').replace(/\[[^\]]*\]/g, '').trim().split(/\s+/)) {
    if (token) services.push(known.has(token) ? token : 'other');
  }
  return { entries: lines.length, services: services.slice(0, 64), customService: services.includes('other') };
}

export function analyzeDnsInspection(evidence) {
  const candidates = new Set(), reasons = [];
  const resolver = evidence.resolver.status === 'ok' ? resolverSummary(evidence.resolver.text) : null;
  const nss = evidence.nss.status === 'ok' ? nssSummary(evidence.nss.text) : null;
  const initIsSystemd = evidence.init.status === 'ok' && evidence.init.text.trim() === 'systemd';
  const target = evidence.metadata.status === 'ok' ? targetKind(evidence.metadata.target ?? evidence.metadata.declaredTarget) : 'unknown';
  if (target.startsWith('resolved-') || resolver?.resolvedStubAddress || resolver?.hints.includes('resolved')
    || nss?.services.includes('resolve') || evidence.units['systemd-resolved.service'] === 'active') candidates.add('systemd-resolved');
  if (target === 'networkmanager' || resolver?.hints.includes('networkmanager') || evidence.units['NetworkManager.service'] === 'active') candidates.add('NetworkManager');
  if (target === 'resolvconf' || resolver?.hints.includes('resolvconf') || evidence.units['resolvconf.service'] === 'active') candidates.add('resolvconf');
  if (!initIsSystemd) reasons.push('non-systemd-or-unknown-pid1: confirm this is the actual VPN client, not a container/lab');
  if (!candidates.size) reasons.push('no-manager-evidence-is-not-proof-of-unmanaged-DNS');
  if (candidates.size > 1) reasons.push('multiple-components-may-form-a-manager-to-resolver-chain');
  for (const key of ['resolver', 'nss', 'init', 'mounts', 'metadata']) if (evidence[key].status !== 'ok') reasons.push(`${key}-unavailable`);
  if (evidence.metadata.kind === 'symlink' && evidence.metadata.targetStatus === 'missing') reasons.push('dangling-resolver-symlink');
  const mountTargets = ['/etc/resolv.conf', evidence.metadata.target, evidence.metadata.declaredTarget]
    .filter((path) => typeof path === 'string' && path.startsWith('/'));
  const mount = evidence.mounts.status === 'ok' ? evidence.mounts.text.split('\n').some((line) => {
    if (!line.includes(' - ')) return false;
    const fields = line.split(' - ')[0].split(' ');
    const mountPath = fields[4]?.replace(/\\(040|011|012|134)/g, (_, octal) => String.fromCharCode(parseInt(octal, 8)));
    return typeof mountPath === 'string' && mountTargets.includes(mountPath);
  }) : null;
  if (mount) reasons.push('resolver-is-a-mountpoint: do-not-replace-it-as-an-ordinary-file');
  if (Object.values(evidence.units).some((value) => value === 'unknown')) reasons.push('service-state-incomplete');
  return { schema: 1, kind: 'clean-vpn-dns-inspection', mode: 'read-only', systemDnsChanged: false,
    dnsQueriesSent: 0, backend: 'unselected', actualClientConfirmed: false,
    environment: { pid1: initIsSystemd ? 'systemd' : evidence.init.status === 'ok' ? 'other' : 'unknown' },
    resolver: { status: evidence.resolver.status, object: evidence.metadata.kind ?? 'unknown', targetKind: target,
      readError: evidence.resolver.error ?? null, targetStatus: evidence.metadata.targetStatus ?? 'unknown',
      mountpoint: mount, ...(resolver ?? {}) },
    nss: { status: evidence.nss.status, ...(nss ?? {}) }, units: evidence.units,
    assessment: { candidates: [...candidates], requiresReview: true, reasons,
      next: 'confirm-client-and-review-manager-ownership-before-implementing-a-backend' },
    limitations: ['point-in-time-evidence-not-ownership-proof', 'no-effective-manager-config-or-split-DNS-policy',
      'no-listener-or-upstream-health-check', 'no-VPN-routing-or-kill-switch-check', 'no-network-access'] };
}

export async function inspectSystemDns({ read = boundedInspectRead, metadata = inspectResolverMetadata, probe = async (unit) => {
  // Minimal environment avoids inherited remote bus/proxy/Node settings and pagers.
  const result = await runCommand('/usr/bin/systemctl', ['--system', '--no-pager', 'is-active', unit],
    { env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C', SYSTEMD_PAGER: 'cat' }, timeoutMs: 2000, maxBytes: 4096 });
  if (result.reason) return 'unknown';
  const value = result.stdout.trim();
  if (result.code === 0 && value === 'active') return value;
  if (result.code === 3 && ['inactive', 'failed', 'activating', 'deactivating'].includes(value)) return value;
  return 'unknown';
} } = {}) {
  const evidence = { units: {} };
  await Promise.all(Object.entries(DNS_INSPECT_FILES).map(async ([key, path]) => {
    try { evidence[key] = { status: 'ok', text: await read(path, key === 'mounts' ? 1048576 : 65536) }; }
    catch (error) { evidence[key] = { status: 'unavailable', error: errorKind(error) }; }
  }));
  try { evidence.metadata = { status: 'ok', ...await metadata() }; }
  catch { evidence.metadata = { status: 'unavailable' }; }
  // Do not contact a host bus exposed inside a container with a different init.
  await Promise.all(DNS_INSPECT_UNITS.map(async (unit) => {
    if (evidence.init.text?.trim() !== 'systemd') { evidence.units[unit] = 'not-probed'; return; }
    try { evidence.units[unit] = await probe(unit); } catch { evidence.units[unit] = 'unknown'; }
  }));
  return analyzeDnsInspection(evidence);
}
