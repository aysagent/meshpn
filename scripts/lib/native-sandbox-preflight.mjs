/** Read-only eligibility inventory for an isolated physical network-namespace trial. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { isIPv4 } from 'node:net';
import { createHash } from 'node:crypto';
import { runCommand } from './transparent-acceptance.mjs';
import { DIAGNOSTIC_ENV } from './dns-diagnostic.mjs';

const requiredTools = ['ip', 'ss', 'systemctl', 'sysctl', 'iptables', 'ip6tables',
  'iptables-save', 'ip6tables-save', 'iptables-restore', 'ip6tables-restore'];
const optionalTools = ['nft'];

export function parseNativeSandboxPreflightArgs(args) {
  if (args.length === 1 && args[0] === '--help') return { help: true };
  const out = {}, seen = new Set();
  for (const arg of args) {
    const match = /^--(role|name|endpoint|port|sandbox-cidr)=(.+)$/.exec(arg);
    assert.ok(match && !seen.has(match[1]), 'invalid or duplicate argument');
    seen.add(match[1]); out[match[1] === 'sandbox-cidr' ? 'sandboxCidr' : match[1]] = match[2];
  }
  assert.ok(['client', 'exit'].includes(out.role), 'client or exit role required');
  assert.match(out.name ?? '', /^[a-z][a-z0-9-]{0,7}$/, 'short safe sandbox name required');
  assert.ok(isIPv4(out.endpoint), 'IPv4 endpoint required');
  assert.match(out.port ?? '', /^\d{1,5}$/, 'port required'); out.port = Number(out.port);
  assert.ok(out.port >= 1024 && out.port <= 65535 && ![2222, 443].includes(out.port), 'unprivileged non-primary non-rescue trial port required');
  assert.ok(parseCidr(out.sandboxCidr)?.prefix === 30, 'IPv4 /30 sandbox CIDR required');
  return out;
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
function overlap(left, right) {
  const a = parseCidr(left), b = parseCidr(right); if (!a || !b) return false;
  const prefix = Math.min(a.prefix, b.prefix), mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return ((a.ip & mask) >>> 0) === ((b.ip & mask) >>> 0);
}
function routeConflict(route, cidr) {
  const candidate = parseCidr(route?.dst), sandbox = parseCidr(cidr);
  if (!candidate || !sandbox || !overlap(route.dst, cidr)) return false;
  return candidate.prefix >= 16 || route?.protocol === 'kernel' || route?.scope === 'link';
}
function status(result) {
  return { status: result?.code === 0 && !result?.reason && !result?.signal ? 'ok' : 'failed',
    code: result?.code ?? null, reason: result?.reason ?? null, signal: result?.signal ?? null,
    durationMs: result?.durationMs ?? null };
}
function json(result, fallback = null) {
  if (result?.code !== 0 || result.reason || result.signal) return fallback;
  try { return JSON.parse(result.stdout); } catch { return fallback; }
}
function properties(result) {
  if (result?.code !== 0 || result.reason || result.signal) return null;
  return Object.fromEntries(result.stdout.split('\n').filter(Boolean).map(line => {
    const at = line.indexOf('='); return at > 0 ? [line.slice(0, at), line.slice(at + 1)] : [line, ''];
  }));
}
function listeners(text) {
  if (typeof text !== 'string') return null;
  return text.split('\n').filter(Boolean).map(line => {
    const fields = line.trim().split(/\s+/), local = fields[4] ?? '';
    const match = /^(.*):(\d+)$/.exec(local);
    return match ? { protocol: fields[0], state: fields[1], local: match[1], port: Number(match[2]) } : null;
  }).filter(Boolean);
}
function listenerBusy(items, port) {
  return !Array.isArray(items) || items.some(item => item.port === port);
}
function compactLinks(items) {
  return Array.isArray(items) ? items.map(item => ({ ifindex: item?.ifindex ?? null, ifname: item?.ifname ?? null,
    kind: item?.linkinfo?.info_kind ?? item?.link_type ?? null, up: item?.flags?.includes('UP') ?? false,
    operstate: item?.operstate ?? null, mtu: item?.mtu ?? null })) : null;
}
function compactAddresses(items) {
  return Array.isArray(items) ? items.map(item => ({ ifname: item?.ifname ?? null,
    addresses: (item?.addr_info ?? []).map(address => ({ family: address?.family ?? null,
      address: address?.local ?? null, prefix: address?.prefixlen ?? null, scope: address?.scope ?? null })) })) : null;
}
function compactRoutes(items) {
  return Array.isArray(items) ? items.map(route => Object.fromEntries(['type', 'dst', 'gateway', 'dev', 'table', 'protocol', 'scope', 'prefsrc', 'metric']
    .filter(key => route?.[key] !== undefined).map(key => [key, route[key]]))) : null;
}
function firewallSummary(text) {
  if (typeof text !== 'string') return null;
  const tables = {}, ownedRules = []; let table = null, rules = 0;
  for (const raw of text.split('\n')) {
    const line = raw.replaceAll('"', '');
    if (line.startsWith('*')) { table = line.slice(1); tables[table] ??= { chains: 0, rules: 0 }; }
    else if (table && line.startsWith(':')) tables[table].chains++;
    else if (table && line.startsWith('-A ')) { tables[table].rules++; rules++;
      if (/CLEANVPN|CVPN|clean-vpn|cvks[234]/.test(line) && ownedRules.length < 128) ownedRules.push(`${table}:${line}`); }
    else if (line === 'COMMIT') table = null;
  }
  return { tables, rules, ownedRules, ownedRulesTruncated: ownedRules.length === 128 };
}
export function sanitizeLegacyArgv(argv, endpoint) {
  if (!Array.isArray(argv) || !argv.length) return null;
  const flags = new Map(); let unknownOptions = 0;
  for (const arg of argv) {
    if (!arg.startsWith('--')) continue;
    const at = arg.indexOf('='), key = at < 0 ? arg : arg.slice(0, at), value = at < 0 ? true : arg.slice(at + 1);
    if (['--role', '--type', '--server', '--ipv6', '--dns-mode', '--dns-usb', '--split-default', '--from-tun'].includes(key)) flags.set(key, value);
    else unknownOptions++;
  }
  const server = /^(\d+\.\d+\.\d+\.\d+):(\d+)$/.exec(flags.get('--server') ?? '');
  return { role: ['client', 'exit'].includes(flags.get('--role')) ? flags.get('--role') : 'unknown',
    type: ['tls', 'boring-tls', 'transparent-tls', 'combo-tls'].includes(flags.get('--type')) ? flags.get('--type') : 'unknown',
    endpointMatchesRequest: server?.[1] === endpoint, port: server ? Number(server[2]) : null,
    splitDefault: flags.get('--split-default') === true, ipv6: flags.get('--ipv6') ?? null,
    dnsMode: flags.get('--dns-mode') ?? null, dnsUsb: flags.get('--dns-usb') ?? null,
    fromTun: typeof flags.get('--from-tun') === 'string', unknownOptions };
}
function inspectLegacy(io, state, endpoint) {
  const pid = state?.['clean-vpn.service']?.MainPID;
  if (!/^[1-9]\d*$/.test(pid ?? '')) return null;
  try {
    const bytes = io.readFileSync(`/proc/${pid}/cmdline`);
    if (bytes.length > 65536) return null;
    return sanitizeLegacyArgv(bytes.toString().split('\0').filter(Boolean), endpoint);
  } catch { return null; }
}
function killswitchProfile(...summaries) {
  for (const summary of summaries) for (const line of summary?.ownedRules ?? []) {
    const match = /\b(cvks[234]:(?:both|fwd):(?:block|leave):[A-Za-z0-9_.-]+:[0-9.,]+:\d+)\b/.exec(line);
    if (match) return match[1];
  }
  return null;
}
function planned(name, role) {
  const token = name.replaceAll('-', '');
  return { namespace: `cvpn-${name}`, hostVeth: `cvh-${token}`, namespaceVeth: `cvn-${token}`,
    unit: `clean-vpn-native-sandbox-${name}.service`, rollbackUnit: `clean-vpn-native-sandbox-${name}-rollback.service`,
    firewallPrefix: `CVPNSB_${role === 'client' ? 'C' : 'E'}_${token.toUpperCase()}` };
}

export function assessNativeSandboxPreflight(report) {
  const issues = new Set(), warnings = new Set();
  if (report.runtime.platform !== 'linux' || report.runtime.uid !== 0 || report.host.pid1 !== 'systemd' || !report.host.sameNetworkNamespace)
    issues.add('root-systemd-host-network-namespace-required');
  if (report.aborted) issues.add('collection-aborted');
  if (requiredTools.some(name => report.tools[name] === null)) issues.add('required-tools-missing');
  if (!report.host.tunDevice) issues.add('tun-device-unavailable');
  if (report.host.namespaceNames?.includes(report.plan.namespace)) issues.add('sandbox-namespace-already-present');
  for (const link of [report.plan.hostVeth, report.plan.namespaceVeth])
    if (report.host.links?.some(item => item?.ifname === link)) issues.add(`sandbox-link-already-present:${link}`);
  for (const [name, state] of Object.entries(report.host.plannedUnits))
    if (!state || state.LoadState !== 'not-found' || state.ActiveState !== 'inactive') issues.add(`sandbox-unit-conflict:${name}`);
  if (report.host.routes4 === null) issues.add('route-inventory-unavailable');
  else if (report.host.routes4.some(route => routeConflict(route, report.request.sandboxCidr))) issues.add('sandbox-cidr-conflicts-with-specific-host-route');
  if (report.request.role === 'client') {
    if (!report.host.endpointRoute?.[0]?.dev || report.host.endpointRoute[0].dev === 'lo'
        || report.host.endpointRoute[0].dev.startsWith('tun')) issues.add('endpoint-uplink-route-unavailable');
    const services = report.host.existingServices, profile = report.host.legacyClientProfile;
    if (services?.['clean-vpn.service']?.ActiveState !== 'active' || profile?.role !== 'client' || profile?.type !== 'tls'
        || profile?.endpointMatchesRequest !== true || profile?.port !== 443 || profile?.splitDefault !== true)
      issues.add('existing-type-tls-client-profile-unconfirmed');
    if (services?.['clean-vpn-killswitch.service']?.ActiveState !== 'active'
        || report.host.killswitchProfile !== `cvks4:both:block:tun0:${report.request.endpoint}:22`)
      issues.add('existing-killswitch-profile-unconfirmed');
    if (services?.['clean-vpn-usb-rescue.socket']?.ActiveState !== 'active') issues.add('existing-usb-rescue-unconfirmed');
  } else {
    if (!report.host.addresses?.some(link => link?.addresses?.some(address => address?.family === 'inet' && address.address === report.request.endpoint)))
      issues.add('exit-endpoint-not-owned-by-host');
    if (listenerBusy(report.host.listeners, report.request.port)) issues.add('trial-port-in-use');
  }
  const activeManagers = Object.entries(report.host.firewallManagers).filter(([, value]) => value?.ActiveState === 'active').map(([name]) => name);
  if (Object.values(report.host.firewallManagers).some(value => value === null)) issues.add('firewall-manager-state-unavailable');
  if (activeManagers.length) issues.add(`concurrent-firewall-manager-active:${activeManagers.join(',')}`);
  if (!['0', '1'].includes(report.host.forwarding)) issues.add('forwarding-state-unavailable');
  if (report.host.iptablesVersion === null) issues.add('firewall-backend-version-unavailable');
  if (report.host.firewallSnapshots.ipv4Sha256 === null || report.host.firewallSnapshots.ipv6Sha256 === null) issues.add('firewall-snapshot-unavailable');
  if (report.tools.nft !== null && report.host.firewallSnapshots.nftSha256 === null) issues.add('nft-snapshot-unavailable');
  if (report.tools.nft === null && report.host.iptablesVersion?.includes('nf_tables')) warnings.add('nft-cli-unavailable-using-iptables-nft-snapshots');
  if (report.host.routes4?.some(route => !routeConflict(route, report.request.sandboxCidr) && overlap(route?.dst, report.request.sandboxCidr)))
    warnings.add('sandbox-cidr-covered-by-broad-host-route-more-specific-connected-route-required');
  if (report.host.defaultRoutes6 > 0) warnings.add('host-has-ipv6-default-sandbox-must-not-acquire-global-ipv6');
  if (report.host.forwarding === '1') warnings.add('host-forwarding-already-enabled-must-not-be-restored-to-zero');
  if (report.request.role === 'client') warnings.add('existing-type-tls-client-and-killswitch-must-remain-active');
  warnings.add('provider-firewall-and-console-availability-not-machine-verifiable');
  warnings.add('read-only-host-state-does-not-establish-host-integrity');
  return { status: issues.size ? 'blocked' : 'ready-for-sandbox-design-review', observedIssues: [...issues], warnings: [...warnings],
    mutationAllowed: false, systemSettingsChanged: false, networkProbesSent: 0,
    requiredOperatorDecisions: ['host-integrity-accepted-or-host-rebuilt', 'trial-port-provider-firewall-policy',
      'independent-rollback-unit-reviewed', 'existing-SSH-and-VPN-must-remain-running', 'bounded-runtime-and-cleanup-readback'],
    next: issues.size ? 'review blockers; do not create namespace or firewall rules' : 'review additive namespace design; this report does not authorize apply' };
}

export async function collectNativeSandboxPreflight(options, {
  io = fs, run = runCommand, signal, deadlineMs = 30000,
  runtime = { node: process.version, platform: process.platform, arch: process.arch, uid: process.getuid?.() },
  hostFacts, tools: injectedTools, legacyProfile: injectedLegacyProfile,
} = {}) {
  const plan = planned(options.name, options.role), controller = new AbortController(), abort = () => controller.abort();
  const timer = setTimeout(abort, deadlineMs); signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
  const command = async (file, args, { timeoutMs = 5000, maxBytes = 512 * 1024 } = {}) => {
    try { return await run(file, args, { env: DIAGNOSTIC_ENV, signal: controller.signal, timeoutMs, maxBytes }); }
    catch { return { code: null, reason: 'unavailable', signal: null, stdout: '', stderr: '', durationMs: null }; }
  };
  try {
    const facts = hostFacts ?? (() => {
      const read = file => { try { return io.readFileSync(file, 'utf8'); } catch { return null; } };
      let sameNetworkNamespace = null, tunDevice = false;
      try { sameNetworkNamespace = io.readlinkSync('/proc/1/ns/net') === io.readlinkSync('/proc/self/ns/net'); } catch {}
      try { tunDevice = io.statSync('/dev/net/tun').isCharacterDevice(); } catch {}
      return { pid1: read('/proc/1/comm')?.trim() ?? null, sameNetworkNamespace, tunDevice };
    })();
    const tools = injectedTools ?? Object.fromEntries([...requiredTools, ...optionalTools].map(name => {
      for (const directory of ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin']) {
        try { io.accessSync(`${directory}/${name}`, io.constants.X_OK); return [name, `${directory}/${name}`]; } catch {}
      }
      return [name, null];
    }));
    const results = {};
    for (const [name, file, args] of [
      ['links', 'ip', ['-j', '-d', 'link', 'show']], ['addresses', 'ip', ['-j', 'address', 'show']],
      ['routes4', 'ip', ['-j', '-4', 'route', 'show', 'table', 'all']], ['routes6', 'ip', ['-j', '-6', 'route', 'show', 'table', 'all']],
      ['rules4', 'ip', ['-j', '-4', 'rule', 'show']], ['rules6', 'ip', ['-j', '-6', 'rule', 'show']],
      ['endpointRoute', 'ip', ['-j', '-4', 'route', 'get', options.endpoint]], ['namespaces', 'ip', ['netns', 'list']],
      ['listeners', 'ss', ['-H', '-lntu']], ['forwarding', 'sysctl', ['-n', 'net.ipv4.ip_forward']],
      ['iptablesVersion', 'iptables', ['--version']], ['nftVersion', 'nft', ['--version']],
      ['iptables', 'iptables-save', []], ['ip6tables', 'ip6tables-save', []], ['nftRules', 'nft', ['list', 'ruleset']],
    ]) results[name] = await command(file, args);
    const unitNames = [plan.unit, plan.rollbackUnit], plannedUnits = {};
    for (const name of unitNames) plannedUnits[name] = properties(await command('systemctl', ['--no-pager', 'show', name,
      '--property=LoadState,ActiveState,UnitFileState,FragmentPath']));
    const firewallManagers = {};
    for (const name of ['firewalld.service', 'ufw.service', 'nftables.service', 'netfilter-persistent.service',
      'docker.service', 'podman.service', 'libvirtd.service', 'fail2ban.service', 'kubelet.service']) firewallManagers[name] = properties(await command('systemctl',
      ['--no-pager', 'show', name, '--property=LoadState,ActiveState,UnitFileState,FragmentPath']));
    const existingServices = {};
    for (const name of ['clean-vpn.service', 'clean-vpn-killswitch.service', 'clean-vpn-usb-rescue.socket',
      'clean-vpn-usb-rescue-address.service']) existingServices[name] = properties(await command('systemctl', ['--no-pager', 'show', name,
      '--property=LoadState,ActiveState,SubState,UnitFileState,FragmentPath,MainPID']));
    const rawLinks = json(results.links, null), rawAddresses = json(results.addresses, null), rawRoutes4 = json(results.routes4, null);
    const rawRoutes6 = json(results.routes6, null), rawEndpointRoute = json(results.endpointRoute, null);
    const ipv4Firewall = results.iptables?.code === 0 ? firewallSummary(results.iptables.stdout) : null;
    const ipv6Firewall = results.ip6tables?.code === 0 ? firewallSummary(results.ip6tables.stdout) : null;
    const legacyClientProfile = options.role === 'client'
      ? (injectedLegacyProfile ?? inspectLegacy(io, existingServices, options.endpoint)) : null;
    const report = { schema: 1, kind: 'clean-vpn-native-sandbox-preflight', timestamp: new Date().toISOString(),
      mode: 'read-only-host-inventory', request: options, runtime, tools, plan, aborted: controller.signal.aborted,
      privacy: 'Contains IPs, interface/unit names, route metadata and firewall snapshot hashes; no argv, environment, keys, config bytes, journals or packet payload.',
      host: { ...facts, links: compactLinks(rawLinks), addresses: compactAddresses(rawAddresses), routes4: compactRoutes(rawRoutes4),
        routes6: compactRoutes(rawRoutes6), rules4: json(results.rules4, null), rules6: json(results.rules6, null),
        endpointRoute: compactRoutes(rawEndpointRoute), namespaceNames: results.namespaces?.code === 0
          ? results.namespaces.stdout.split('\n').filter(Boolean).map(line => line.trim().split(/\s+/)[0]) : null,
        listeners: results.listeners?.code === 0 ? listeners(results.listeners.stdout) : null,
        forwarding: results.forwarding?.code === 0 ? results.forwarding.stdout.trim() : null,
        defaultRoutes6: (rawRoutes6 ?? []).filter(route => route?.dst === 'default').length,
        iptablesVersion: results.iptablesVersion?.code === 0 ? results.iptablesVersion.stdout.trim() : null,
        nftVersion: results.nftVersion?.code === 0 ? results.nftVersion.stdout.trim() : null,
        firewallSnapshots: { ipv4Sha256: results.iptables?.code === 0 ? createHash('sha256').update(results.iptables.stdout).digest('hex') : null,
          ipv6Sha256: results.ip6tables?.code === 0 ? createHash('sha256').update(results.ip6tables.stdout).digest('hex') : null,
          nftSha256: results.nftRules?.code === 0 ? createHash('sha256').update(results.nftRules.stdout).digest('hex') : null },
        firewallInventory: { ipv4: ipv4Firewall, ipv6: ipv6Firewall },
        killswitchProfile: killswitchProfile(ipv4Firewall, ipv6Firewall), legacyClientProfile,
        plannedUnits, existingServices, firewallManagers },
      commandStatus: Object.fromEntries(Object.entries(results).map(([name, result]) => [name, status(result)])),
      limitations: ['no-network-probes', 'no-provider-firewall-or-console-proof', 'no-host-integrity-proof',
        'no-firewall-mutation-simulation', 'point-in-time-state-only', 'not-an-apply-or-cleanup-command'] };
    Object.assign(report, assessNativeSandboxPreflight(report)); return report;
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}
