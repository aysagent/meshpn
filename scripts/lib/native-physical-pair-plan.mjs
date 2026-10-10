/** Compose two read-only physical preflights into a non-mutating pair plan. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { verifyCertificatePair } from './native-pair-certificates.mjs';

const pathPattern = /^\/[A-Za-z0-9_./-]+$/;
const hash = value => createHash('sha256').update(value).digest('hex');

function absolute(value) {
  assert.ok(pathPattern.test(value ?? '') && path.normalize(value) === value, 'absolute safe path required');
  return value;
}

export function parseNativePhysicalPairArgs(args) {
  if (args.length === 1 && args[0] === '--help') return { help: true };
  const out = {}, seen = new Set();
  for (const arg of args) {
    const match = /^--(client|exit)=(.+)$/.exec(arg);
    assert.ok(match && !seen.has(match[1]), 'invalid or duplicate argument');
    seen.add(match[1]); out[match[1]] = absolute(match[2]);
  }
  assert.ok(out.client && out.exit && out.client !== out.exit, 'distinct client and exit reports required');
  return out;
}

function source(io, file) {
  const stat = io.lstatSync(file);
  assert.ok(stat.isFile() && !stat.isSymbolicLink?.(), 'regular report required');
  assert.equal(io.realpathSync(file), file, 'symlink report refused');
  assert.equal(stat.uid, process.getuid?.(), 'report owner must match collector uid');
  assert.ok(stat.size > 0 && stat.size <= 4 * 1024 * 1024, 'report size refused');
  assert.equal(stat.mode & 0o022, 0, 'group/other writable report refused');
  const bytes = io.readFileSync(file);
  assert.equal(bytes.length, stat.size, 'short report read');
  return { bytes, evidence: { path: file, size: stat.size, sha256: hash(bytes), uid: stat.uid,
    gid: stat.gid, mode: (stat.mode & 0o777).toString(8).padStart(3, '0'),
    mtime: stat.mtime?.toISOString?.() ?? null } };
}

function parseReport(bytes) {
  const text = bytes.toString('utf8').trim();
  const begin = '=== CLEAN-VPN NATIVE PHYSICAL PREFLIGHT BEGIN ===';
  const end = '=== CLEAN-VPN NATIVE PHYSICAL PREFLIGHT END ===';
  let json = text;
  if (text.startsWith(begin)) {
    assert.ok(text.endsWith(end), 'incomplete wrapped preflight report');
    json = text.slice(begin.length, -end.length).trim();
  }
  const report = JSON.parse(json);
  assert.ok(report && typeof report === 'object' && !Array.isArray(report), 'report object required');
  return report;
}

function ipv4Number(value) {
  const parts = String(value).split('.');
  if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return null;
  return parts.reduce((number, part) => ((number << 8) | Number(part)) >>> 0, 0);
}

function parseCidr(value) {
  const [address, prefixText, extra] = String(value).split('/');
  const ip = ipv4Number(address), prefix = Number(prefixText);
  if (extra !== undefined || ip === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { address, ip, prefix, mask, network: (ip & mask) >>> 0 };
}

function contains(cidr, address) {
  const range = parseCidr(cidr), ip = ipv4Number(address);
  return range !== null && ip !== null && ((ip & range.mask) >>> 0) === range.network;
}

function overlaps(left, right) {
  const a = parseCidr(left), b = parseCidr(right);
  if (!a || !b) return null;
  const prefix = Math.min(a.prefix, b.prefix);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return ((a.ip & mask) >>> 0) === ((b.ip & mask) >>> 0);
}

function validPreflight(report, role, issues) {
  if (report.schema !== 1 || report.kind !== 'clean-vpn-native-physical-preflight') issues.add(`${role}:unsupported-report`);
  if (report.request?.role !== role || report.engine?.role !== role || report.site?.role !== role) issues.add(`${role}:role-mismatch`);
  if (report.engine?.transport !== 'combo-tls' || report.site?.transport !== 'combo-tls') issues.add(`${role}:transport-mismatch`);
  if (report.status !== 'ready-for-reviewed-trial-plan' || report.observedIssues?.length) issues.add(`${role}:preflight-not-ready`);
  if (report.mutationAllowed !== false || report.systemSettingsChanged !== false || report.networkProbesSent !== 0 || report.installationAttempted !== false)
    issues.add(`${role}:read-only-contract-not-proven`);
  if (report.aborted !== false || report.engine?.architectureMatchesHost !== true || report.engine?.capabilitiesStatus !== 'ok'
      || report.engine?.configCheck !== 'ok' || report.offlineInstallDryRun?.status !== 'eligible') issues.add(`${role}:local-validation-incomplete`);
  const combo = report.engine?.capability?.combo;
  if (report.engine?.capability?.engine !== 'clean-vpn-native-m1' || report.engine?.capability?.packet_ipc !== false
      || report.engine?.capability?.service_mode !== true || combo?.single_exit_listener !== true
      || combo?.packet_ipc !== false || combo?.site_provisioning !== true) issues.add(`${role}:capability-contract-mismatch`);
}

export function composeNativePhysicalPair(client, exit, { now = Date.now(), maxAgeMs = 60 * 60 * 1000 } = {}) {
  const issues = new Set(), warnings = new Set();
  validPreflight(client, 'client', issues); validPreflight(exit, 'exit', issues);
  if (client.request?.name === exit.request?.name) issues.add('instance-names-must-differ');
  if (!client.site?.endpoint || client.site.endpoint !== exit.site?.endpoint) issues.add('exit-endpoint-mismatch');
  if (!Number.isInteger(client.site?.port) || client.site.port !== exit.site?.port || client.site.port !== exit.site?.listenPort)
    issues.add('exit-port-mismatch');
  if (!client.engine?.publicName || client.engine.publicName !== exit.engine?.publicName) issues.add('transparent-public-name-mismatch');
  const clientTun = parseCidr(client.site?.tunAddress), exitTun = parseCidr(exit.site?.tunAddress);
  if (!clientTun || clientTun.prefix !== 32 || !exitTun || exitTun.prefix >= 32 || !contains(exit.site.tunAddress, clientTun?.address))
    issues.add('client-tun-address-not-covered-by-exit-subnet');
  if (!client.site?.lan?.subnet || overlaps(client.site.lan.subnet, exit.site?.tunAddress) !== false) issues.add('client-lan-missing-or-overlaps-tunnel');
  if (client.engine?.capability?.dns_socket_mark !== exit.engine?.capability?.dns_socket_mark) issues.add('engine-dns-mark-mismatch');
  if (client.plan?.fingerprints?.config !== client.evidence?.config?.sha256
      || exit.plan?.fingerprints?.config !== exit.evidence?.config?.sha256
      || client.plan?.fingerprints?.siteProfile !== client.evidence?.siteProfile?.sha256
      || exit.plan?.fingerprints?.siteProfile !== exit.evidence?.siteProfile?.sha256) issues.add('source-fingerprint-mismatch');
  for (const [role, report] of [['client', client], ['exit', exit]]) {
    const timestamp = Date.parse(report.timestamp);
    if (!Number.isFinite(timestamp) || timestamp > now + 5 * 60 * 1000 || now - timestamp > maxAgeMs) issues.add(`${role}:stale-or-invalid-timestamp`);
    if (report.warnings?.length) warnings.add(`${role}:preflight-warnings-require-review`);
  }
  const clientProof = client.pairProof, exitProof = exit.pairProof;
  let pskProof = 'not-provided';
  if (clientProof || exitProof) {
    const clientPeer = clientProof?.boring?.find(item => item?.peerIpv4 === clientTun?.address);
    const exitPeer = exitProof?.boring?.find(item => item?.peerIpv4 === clientTun?.address);
    if (clientProof?.version !== 1 || exitProof?.version !== 1 || !/^[0-9a-f]{64}$/.test(clientProof?.challenge ?? '')
        || clientProof.challenge !== exitProof?.challenge || !/^[0-9a-f]{64}$/.test(clientPeer?.value ?? '')
        || clientPeer.value !== exitPeer?.value || !/^[0-9a-f]{64}$/.test(clientProof?.relay ?? '')
        || clientProof.relay !== exitProof?.relay) issues.add('cross-host-psk-proof-mismatch');
    else pskProof = 'matched-one-use-challenge';
  }
  if (pskProof !== 'matched-one-use-challenge') warnings.add('cross-host-psk-equivalence-not-proven-by-preflight');
  let certificateProof = 'not-provided';
  if (client.pairCertificates || exit.pairCertificates) {
    if (client.pairCertificates?.role !== 'client' || exit.pairCertificates?.role !== 'exit'
        || client.pairCertificates.serverName !== client.engine?.serverName) issues.add('cross-host-certificate-evidence-mismatch');
    else {
      const verification = verifyCertificatePair({ serverName: client.pairCertificates.serverName,
        exitChain: exit.pairCertificates.certificates, clientTrust: client.pairCertificates.certificates, now });
      if (verification.status !== 'verified') issues.add('cross-host-certificate-verification-failed');
      else certificateProof = 'verified-name-validity-and-trust-chain';
    }
  }
  if (certificateProof !== 'verified-name-validity-and-trust-chain') warnings.add('exit-certificate-chain-and-name-pair-not-proven-by-preflight');
  warnings.add('provider-firewall-console-and-management-reachability-remain-unverified');
  const status = issues.size ? 'blocked' : 'ready-for-human-approved-transient-design';
  return { status, observedIssues: [...issues], warnings: [...warnings], mutationAllowed: false,
    pair: { endpoint: client.site?.endpoint ?? null, port: client.site?.port ?? null,
      publicName: client.engine?.publicName ?? null, clientTun: client.site?.tunAddress ?? null,
      exitTun: exit.site?.tunAddress ?? null, clientLan: client.site?.lan?.subnet ?? null,
      clientInstance: client.request?.name ?? null, exitInstance: exit.request?.name ?? null, pskProof, certificateProof },
    requiredProofsBeforeMutation: ['independent-console-or-rescue-on-both-hosts', 'provider-firewall-reviewed',
      'management-reachability-policy-reviewed', ...(pskProof === 'matched-one-use-challenge' ? [] : ['cross-host-psk-equivalence-proved-without-disclosing-secret']),
      ...(certificateProof === 'verified-name-validity-and-trust-chain' ? [] : ['exit-certificate-chain-and-name-pair-proved']),
      'bounded-timeout-and-independent-rollback-owner',
      'fresh-preflight-immediately-before-trial', 'independent-egress-capture-approved'],
    next: issues.size ? 'repair-or-recollect-preflights; do-not-build-or-run-a-trial' : 'design-separate-transient-lifecycle; this-plan-does-not-authorize-mutation' };
}

export function collectNativePhysicalPairPlan(options, { io = fs, now = Date.now(), maxAgeMs } = {}) {
  const clientSource = source(io, options.client), exitSource = source(io, options.exit);
  const client = parseReport(clientSource.bytes), exit = parseReport(exitSource.bytes);
  const assessment = composeNativePhysicalPair(client, exit, { now, maxAgeMs });
  return { schema: 1, kind: 'clean-vpn-native-physical-pair-plan', timestamp: new Date(now).toISOString(),
    mode: 'offline-read-only-composition', systemSettingsChanged: false, networkProbesSent: 0,
    sourceEvidence: { client: clientSource.evidence, exit: exitSource.evidence },
    sourcePreflights: { client: { timestamp: client.timestamp ?? null, name: client.request?.name ?? null,
      binarySha256: client.evidence?.binary?.sha256 ?? null, configSha256: client.evidence?.config?.sha256 ?? null,
      siteProfileSha256: client.evidence?.siteProfile?.sha256 ?? null },
    exit: { timestamp: exit.timestamp ?? null, name: exit.request?.name ?? null,
      binarySha256: exit.evidence?.binary?.sha256 ?? null, configSha256: exit.evidence?.config?.sha256 ?? null,
      siteProfileSha256: exit.evidence?.siteProfile?.sha256 ?? null } },
    privacy: 'Contains source paths, hashes, endpoint, ports and subnets; no raw config, key or certificate bytes.',
    limitations: ['offline-report-composition-only', 'input-reports-are-not-cryptographically-attested',
      'no-cross-host-network-probe', 'no-secret-equivalence-proof', 'no-console-or-provider-firewall-proof'],
    ...assessment };
}
