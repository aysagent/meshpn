/** Temporary M1 trial, not an installer. This module never handles packet data. */
import path from 'node:path';
import { isIPv4 } from 'node:net';
import { validateBlockedTrialIpv6 } from './native-trial-ipv6.mjs';

export function requireTrial(condition, code) { if (!condition) throw Error(code); }

// ss decorates SO_BINDTODEVICE endpoints with %interface (our rescue socket
// uses BindToDevice=usb0). Match parsed endpoints, not address substrings.
// Input is IPv4-only, headerless, established TCP output; some versions retain
// the ESTAB column even with the state filter.
export function hasUsbRescueConnection(output, ssh) {
  const port = s => /^\d{1,5}$/.test(s) && Number(s) > 0 && Number(s) <= 65535;
  if (!Array.isArray(ssh) || ssh.length !== 4 || !isIPv4(ssh[0]) || !ssh[0].startsWith('192.168.7.')
      || !port(ssh[1]) || ssh[2] !== '192.168.7.1' || ssh[3] !== '2222') return false;
  const endpoint = token => {
    const m = /^(\d+\.\d+\.\d+\.\d+)(?:%([a-zA-Z0-9_.-]{1,15}))?:(\d{1,5})$/.exec(token);
    return m && isIPv4(m[1]) && port(m[3]) && (!m[2] || m[2] === 'usb0')
      ? { address: m[1], port: Number(m[3]) } : null;
  };
  return output.split('\n').some(line => {
    const fields = line.trim().split(/\s+/);
    if (fields[0] === 'ESTAB') fields.shift();
    if (fields.length !== 4 || !/^\d+$/.test(fields[0]) || !/^\d+$/.test(fields[1])) return false;
    const local = endpoint(fields[2]), peer = endpoint(fields[3]);
    return local?.address === ssh[2] && local.port === 2222
      && peer?.address === ssh[0] && peer.port === Number(ssh[1]);
  });
}

export function summarizeTrialProbe(data, code) {
  const p = data.probes ?? {}, https = [p.egress, p.repeatHttps];
  return { status: code === 0 ? data.status : 'incomplete-or-failed',
    exitIp: p.egress?.observedExitIp ?? null, nss: p.nss?.status ?? 'missing',
    dnsPassed: (p.dns ?? []).filter(d => d.status === 'passed').length, dnsTotal: (p.dns ?? []).length,
    httpsPassed: https.filter(h => h?.status === 'passed').length,
    httpsSeconds: https.map(h => h?.seconds ?? null),
    download: { status: p.download?.status ?? 'missing', bytes: p.download?.downloadedBytes ?? 0,
      seconds: p.download?.seconds ?? null },
    ...(data.status !== 'ipv4-smoke-passed' ? { checks: data.checks } : {}) };
}

// Read the actual running argv, not shell text: no eval/source, no secret argv
// copied into a report. Mirror only the reviewed TLS client configuration.
export function deriveTrialConfig(argv, { cwd, root, exists, ipv6Evidence }) {
  requireTrial(argv.length >= 3 && path.resolve(cwd, argv[1]) === path.join(root, 'scripts/clean-vpn.js'), 'unsupported_service_command');
  const flags = new Map();
  for (const arg of argv.slice(2)) {
    requireTrial(arg.startsWith('--'), 'unsupported_service_arguments');
    const at = arg.indexOf('='), key = at < 0 ? arg : arg.slice(0, at);
    requireTrial(!flags.has(key), 'duplicate_service_option');
    flags.set(key, at < 0 ? true : arg.slice(at + 1));
  }
  requireTrial(flags.get('--role') === 'client', 'client_service_required');
  requireTrial(['tls', 'boring-tls'].includes(flags.get('--type')), 'trial_requires_tls_or_boring_tls_not_combo');
  requireTrial(flags.get('--server') === '154.62.226.216:443', 'unsupported_exit');
  requireTrial(flags.get('--split-default') === true && !flags.has('--from-tun'), 'split_default_required');
  requireTrial((flags.get('--dns-mode') ?? 'tunnel') === 'tunnel' && flags.get('--dns-usb') === '1', 'usb_tunnel_dns_required');
  requireTrial(!flags.has('--dns-state-dir') && !flags.has('--dns-server'), 'custom_dns_not_supported');
  requireTrial(!flags.has('--http-vers') || flags.get('--http-vers') === '2', 'h2_required');
  requireTrial(!flags.has('--ipv6') || ['off', 'auto'].includes(flags.get('--ipv6')), 'ipv6_tunnel_not_supported');
  if (flags.get('--ipv6') === 'auto') validateBlockedTrialIpv6(ipv6Evidence);
  requireTrial(!flags.has('--client-lan-subnet') || flags.get('--client-lan-subnet') === '192.168.7.0/24', 'unsupported_lan');
  const certs = path.resolve(cwd, flags.get('--tls-cert-dir') || flags.get('--quic-certs-dir') || path.join(root, 'certs'));
  const fullchain = path.join(certs, 'fullchain.pem');
  const ca = exists(fullchain) ? fullchain : path.join(certs, 'ca.pem');
  const explicitKey = flags.get('--shared-hmac-key') || flags.get('--quic-ext-crypto-key');
  const standardKey = path.join(certs, 'clean-vpn-hmac.key');
  const secret = explicitKey ? path.resolve(cwd, explicitKey) : exists(standardKey) ? standardKey : path.join(certs, 'quic-ext-hmac.key');
  const explicitName = flags.get('--tls-server-name');
  const publicName = String(flags.get('--tls-public-name') || '').split(',')[0].trim().toLowerCase();
  const name = explicitName ? (String(explicitName).trim().toLowerCase() === 'www.google.com' ? 'clean-vpn' : String(explicitName).trim())
    : publicName && exists(fullchain) ? publicName : 'clean-vpn';
  const sni = String(flags.get('--tls-client-sni') || (name === 'clean-vpn' ? 'www.google.com' : name)).trim();
  for (const host of [name, sni]) requireTrial(/^[a-zA-Z0-9.-]{1,253}$/.test(host), 'invalid_tls_name');
  requireTrial(exists(ca) && exists(secret), 'existing_credentials_missing');
  return { version: 1, role: 'client', address: '154.62.226.216', port: 443,
    tun: 'tun0', secret_path: secret, server_name: name, sni, ca, dns: true };
}

// Pure config composition for the direct Radxa combo trial. The caller copies
// both secrets into its private scratch directory and compares their bytes
// before any service is stopped. This helper never generates or reads keys.
export function deriveComboTrialConfig(packet, { relaySecretPath, publicName, listenPort = 33002, denyIpv4 = [] }) {
  requireTrial(packet?.version === 1 && packet.role === 'client', 'invalid_packet_config');
  requireTrial(packet.tun === 'tun0' && packet.dns === true, 'unsupported_packet_profile');
  requireTrial(typeof relaySecretPath === 'string' && path.isAbsolute(relaySecretPath)
    && relaySecretPath !== packet.secret_path, 'separate_relay_secret_required');
  requireTrial(typeof publicName === 'string' && /^[a-zA-Z0-9.-]{1,253}$/.test(publicName), 'invalid_public_name');
  requireTrial(Number.isInteger(listenPort) && listenPort >= 1024 && listenPort <= 65535
    && ![1053, 2222, packet.port].includes(listenPort), 'invalid_combo_listener');
  requireTrial(Array.isArray(denyIpv4) && denyIpv4.length <= 64
    && denyIpv4.every(value => typeof value === 'string'), 'invalid_combo_deny_list');
  const endpoint = { ipv4: packet.address, port: packet.port };
  return { version: 1, transport: 'combo-tls', role: 'client',
    boring: { ...packet, sni: publicName },
    transparent: { version: 1, transport: 'transparent-tls', role: 'client', public_name: publicName,
      secret_path: relaySecretPath, listen: { ipv4: '0.0.0.0', port: listenPort }, exit: endpoint,
      destination_policy: { mode: 'public-https', deny_ipv4: [...denyIpv4] } } };
}

export function parseComboTrialProfile(value) {
  requireTrial(value && typeof value === 'object' && !Array.isArray(value), 'invalid_combo_profile');
  requireTrial(JSON.stringify(Object.keys(value).sort()) === JSON.stringify(
    ['deny_ipv4', 'listen_port', 'public_name', 'relay_secret_path', 'version'].sort()), 'invalid_combo_profile_fields');
  requireTrial(value.version === 1, 'invalid_combo_profile_version');
  requireTrial(typeof value.relay_secret_path === 'string' && path.isAbsolute(value.relay_secret_path)
    && path.normalize(value.relay_secret_path) === value.relay_secret_path, 'invalid_relay_secret_path');
  requireTrial(typeof value.public_name === 'string' && value.public_name === value.public_name.toLowerCase(),
    'lowercase_public_name_required');
  requireTrial(Array.isArray(value.deny_ipv4), 'invalid_combo_deny_list');
  // Reuse the composition contract here; native --check-config and the
  // redirect compiler perform the full policy validation before service stop.
  deriveComboTrialConfig({ version: 1, role: 'client', tun: 'tun0', dns: true,
    address: '154.62.226.216', port: 443, secret_path: '/packet-secret' }, {
    relaySecretPath: value.relay_secret_path, publicName: value.public_name,
    listenPort: value.listen_port, denyIpv4: value.deny_ipv4 });
  return structuredClone(value);
}

// Injectable lifecycle: failures after stop never blindly start another client
// on top of an unaudited native TUN/journal. The guard is NEVER released here.
export async function runTrial(io, { holdSeconds = 0, cancelled = () => false, progress = () => {} } = {}) {
  const report = { schema: 1, kind: 'clean-vpn-native-radxa-trial', status: 'running',
    transport: io.transport ?? 'boring-tls',
    stage: 'preflight', checks: {}, rollback: 'not-needed', guard: 'not-checked',
    limitations: ['host-smoke-not-usb-peer-acceptance', 'not-speedtest-or-throughput-benchmark',
      'not-a-leak-or-crash-test', 'native-client-only-existing-exit', 'no-browser-profile-fidelity'] };
  let stopped = false, tunIndex, session;
  if (io.peer) report.usb = { status: 'running', phases: {},
    scope: 'authenticated-Mac-USB-observations-not-independent-leak-capture' };
  const snapshotNative = phase => {
    if (!session?.diagnostics) return;
    // Diagnostic failure must never prevent shutdown/rollback.
    try { (report.nativeDiagnostics ??= {})[phase] = session.diagnostics(); }
    catch { (report.nativeDiagnostics ??= {})[phase] = { unavailable: true }; }
  };
  const step = async (name, fn, interruptible = true) => {
    report.stage = name; progress(name);
    if (interruptible) requireTrial(!cancelled(), 'cancelled');
    return await fn();
  };
  const releaseCrash = async () => {
    requireTrial(session?.crashRequested?.(), 'crash_not_requested');
    await step('crash-stop-audit', () => session.stop(), false);
    if (tunIndex !== undefined) {
      await step('crash-network-recovery', () => io.recoverCrash(tunIndex), false);
      tunIndex = undefined;
    }
  };
  try {
    await step('preflight', () => io.preflight());
    report.guard = 'verified';
    report.checks.old = await step('old-client-check', () => io.probe());
    requireTrial(report.checks.old.status === 'ipv4-smoke-passed', 'baseline_failed');
    if (io.peer) await step('usb-baseline', () => io.peer.phase('baseline', report.usb.phases));
    await step('before-stop', () => io.beforeStop());
    // Mark BEFORE issuing stop: an interrupted systemctl may leave its job running.
    await step('stop-old', async () => { stopped = true; await io.stopOld(); });
    await step('old-cleanup-audit', () => io.auditReleased());
    await step('require-no-tun', () => io.requireNoTun());
    await step('old-ipv6-cleanup-audit', () => io.auditIpv6Released());
    tunIndex = await step('create-test-tun', () => io.createTun());
    await step('configure-test-tun', () => io.configureTun());
    session = await step('launch-native', () => io.launch());
    await step('native-ready', () => session.ready(cancelled));
    report.checks.native = await step('native-client-check', () => io.probe());
    requireTrial(report.checks.native.status === 'ipv4-smoke-passed', 'native_smoke_failed');
    report.hold = {};
    await step('native-hold', () => io.hold(holdSeconds, cancelled, session, report.hold));
    if (io.peer) await step('native-usb-peer', () => io.peer.native(session, report.usb, releaseCrash));
    report.status = 'passed';
  } catch (error) {
    report.status = 'failed';
    // Only allow fixed diagnostic codes; never echo child stderr, argv or keys.
    report.failure = { stage: report.stage, code: /^[a-z0-9_]{1,100}$/.test(error.message) ? error.message : 'operation_failed' };
  } finally {
    snapshotNative('beforeStop');
    if (stopped) {
      report.rollback = 'in-progress';
      try {
        if (session) await step('stop-native', () => session.stop(), false);
        if (session?.crashRequested?.()) await releaseCrash();
        await step('rollback-service-audit', () => io.requireOldInactive(), false);
        // If launch never happened, journals still describe the deleted OLD
        // interface. Remove only our unused test TUN before auditing them.
        if (!session && tunIndex !== undefined) {
          await step('remove-unused-test-tun', () => io.removeTun(tunIndex), false);
          tunIndex = undefined;
        }
        await step('rollback-journal-audit', () => io.auditReleased(), false);
        if (tunIndex !== undefined) await step('remove-test-tun', () => io.removeTun(tunIndex), false);
        await step('rollback-no-tun', () => io.requireNoTun(), false);
        // The IPv6 journal still records the OLD ifindex, not native's TUN.
        await step('rollback-ipv6-audit', () => io.auditIpv6Released(), false);
        await step('start-old', () => io.startOld(), false);
        report.rollback = 'service-restored';
        report.restorationReadiness = await step('old-ready', () => io.waitOld(), false);
        report.checks.restored = await step('restored-client-check', () => io.probe(), false);
        requireTrial(report.checks.restored.status === 'ipv4-smoke-passed', 'restored_smoke_failed');
        report.rollback = 'verified';
        if (io.peer) await step('usb-restored', () => io.peer.phase('restored', report.usb.phases), false);
      } catch (error) {
        report.status = 'failed';
        report.rollbackFailure = { stage: report.stage, code: /^[a-z0-9_]{1,100}$/.test(error.message) ? error.message : 'operation_failed' };
        if (!['service-restored', 'verified'].includes(report.rollback)) report.rollback = 'manual-review-required';
      }
    }
    try { await io.verifyGuard(); report.guard = 'verified'; }
    catch { report.guard = 'verification-failed'; report.status = 'failed'; }
    snapshotNative('afterStop');
  }
  report.stage = 'finished';
  if (io.peer) report.usb.status = (io.peer.requiredPhases ?? ['baseline', 'native', 'blocked', 'recovered', 'restored'])
    .every(p => report.usb.phases[p]?.status === 'passed') ? 'passed' : 'failed';
  if (report.usb?.status === 'failed') report.status = 'failed';
  return report;
}
