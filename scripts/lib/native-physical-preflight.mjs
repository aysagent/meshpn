/** Read-only physical-host inventory and exact offline combo site plan.
 * No probes, TUN, firewall writes, systemd mutations or installed-file writes. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { runCommand } from './transparent-acceptance.mjs';
import { DIAGNOSTIC_ENV } from './dns-diagnostic.mjs';
import { nativeNetworkPlan, assertEmptyNativeTables } from './native-network-profile.mjs';
import { nativeSitePlan } from './native-site-plan.mjs';
import { installNative } from './native-install.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const hash = value => createHash('sha256').update(value).digest('hex');
const pathPattern = /^\/[A-Za-z0-9_./-]+$/;
const requiredTools = ['git', 'ip', 'ss', 'systemctl', 'sysctl', 'iptables', 'ip6tables',
  'iptables-save', 'ip6tables-save', 'iptables-restore', 'ip6tables-restore'];
const archMachines = { x64: 62, arm64: 183 };

function absolute(value) {
  assert.ok(pathPattern.test(value ?? '') && path.normalize(value) === value, 'absolute safe path required');
  return value;
}
export function parseNativePhysicalPreflightArgs(args) {
  if (args.length === 1 && args[0] === '--help') return { help: true };
  const out = {}, seen = new Set();
  for (const arg of args) {
    const m = /^--(role|name|binary|config|site-profile)=(.+)$/.exec(arg);
    assert.ok(m && !seen.has(m[1]), 'invalid or duplicate argument'); seen.add(m[1]);
    const key = m[1] === 'site-profile' ? 'siteProfile' : m[1];
    out[key] = m[1] === 'role' || m[1] === 'name' ? m[2] : absolute(m[2]);
  }
  assert.ok(['client', 'exit'].includes(out.role), 'explicit client or exit role required');
  assert.match(out.name ?? '', /^[a-z][a-z0-9-]{0,31}$/, 'safe instance name required');
  for (const key of ['binary', 'config', 'siteProfile']) assert.ok(out[key], `${key} required`);
  return out;
}

function metadata(io, file, { secret = false, executable = false, limit }) {
  const s = io.lstatSync(file);
  assert.ok(s.isFile() && !s.isSymbolicLink?.(), 'regular source required');
  assert.ok(io.realpathSync(file) === file, 'symlink source refused');
  assert.equal(s.uid, process.getuid?.(), 'source owner must match collector uid');
  assert.ok(s.size > 0 && s.size <= limit, 'source size refused');
  assert.ok(!(s.mode & 0o022), 'group/other writable source refused');
  if (secret) assert.equal(s.mode & 0o077, 0, 'secret source must be owner-only');
  if (executable) assert.ok(s.mode & 0o100, 'owner executable bit required');
  const bytes = io.readFileSync(file);
  assert.equal(bytes.length, s.size, 'short source read');
  return { bytes, evidence: { path: file, size: s.size, uid: s.uid, gid: s.gid,
    mode: (s.mode & 0o777).toString(8).padStart(3, '0'), sha256: hash(bytes),
    mtime: s.mtime?.toISOString?.() ?? null, ctime: s.ctime?.toISOString?.() ?? null,
    birthtime: s.birthtime?.toISOString?.() ?? null } };
}
function elfMachine(bytes) {
  if (bytes.length < 20 || bytes.subarray(0, 4).toString('hex') !== '7f454c46') return null;
  const little = bytes[5] === 1;
  if (![1, 2].includes(bytes[5])) return null;
  return little ? bytes.readUInt16LE(18) : bytes.readUInt16BE(18);
}
function commandStatus(result) {
  return { status: result?.code === 0 && !result?.reason && !result?.signal ? 'ok' : 'failed',
    code: result?.code ?? null, reason: result?.reason ?? null, signal: result?.signal ?? null,
    durationMs: result?.durationMs ?? null };
}
function parseJson(result, fallback = null) {
  if (result?.code !== 0 || result.reason || result.signal) return fallback;
  try { return JSON.parse(result.stdout); } catch { return fallback; }
}
function unitProperties(result) {
  if (result?.code !== 0 || result.reason || result.signal) return null;
  const out = {};
  for (const line of result.stdout.split('\n')) {
    const at = line.indexOf('='); if (at > 0) out[line.slice(0, at)] = line.slice(at + 1);
  }
  return out;
}
function emptyTables(text) {
  try { assertEmptyNativeTables(text); return true; } catch { return false; }
}
function linkByName(report, name) { return report.host.links?.find(link => link?.ifname === name); }
function addresses(report, name) {
  const link = report.host.addresses?.find(item => item?.ifname === name);
  return link?.addr_info?.filter(a => a?.family === 'inet').map(a => `${a.local}/${a.prefixlen}`) ?? [];
}
function portBusy(listeners, port, protocol) {
  if (typeof listeners !== 'string') return true;
  return listeners.split('\n').some(line => line.startsWith(protocol) && new RegExp(`:${port}(?:\\s|$)`).test(line));
}

export function assessNativePhysicalPreflight(report) {
  const issues = new Set(), warnings = new Set();
  if (report.runtime.platform !== 'linux' || report.runtime.uid !== 0 || report.host.pid1 !== 'systemd' || !report.host.sameNetworkNamespace)
    issues.add('root-systemd-host-network-namespace-required');
  if (report.aborted) issues.add('collection-aborted');
  if (Object.values(report.tools).some(value => value === null)) issues.add('required-tools-missing');
  if (!report.host.tunDevice) issues.add('tun-device-unavailable');
  if (report.engine.architectureMatchesHost !== true) issues.add('engine-architecture-mismatch');
  if (report.engine.capabilitiesStatus !== 'ok' || report.engine.configCheck !== 'ok') issues.add('engine-capability-or-config-check-failed');
  if (report.offlineInstallDryRun?.status !== 'eligible') issues.add('offline-installer-dry-run-failed');
  if (report.engine.role !== report.request.role || report.site.role !== report.request.role || report.engine.transport !== 'combo-tls')
    issues.add('role-or-transport-mismatch');
  for (const [name, state] of Object.entries(report.plannedUnitState)) {
    if (!state || state.LoadState !== 'not-found' || state.ActiveState !== 'inactive') issues.add(`planned-unit-conflict:${name}`);
  }
  if (report.host.bundlePathState !== 'absent') issues.add('native-instance-bundle-already-present');
  if (!report.host.firewall.every(item => item.empty === true)) issues.add('dedicated-empty-firewall-contract-not-met');
  if (report.host.forwarding !== '0') issues.add('fresh-forwarding-must-be-disabled');
  if (report.host.links?.some(link => link?.ifname === report.site.tun || link?.linkinfo?.info_kind === 'tun')) issues.add('existing-tun-refused');
  for (const name of [report.site.uplink, ...(report.site.lan ? [report.site.lan.interface] : [])]) {
    const link = linkByName(report, name);
    if (!link) issues.add(`required-link-missing:${name}`);
    else if (link.flags?.includes('UP')) issues.add(`fresh-contract-requires-link-down:${name}`);
  }
  const linkUnit = report.linkUnit;
  if (!linkUnit || linkUnit.LoadState !== 'loaded') issues.add('external-link-owner-unit-not-loaded');
  if (report.request.role === 'client') {
    if (report.host.endpointRoute?.[0]?.dev !== report.site.uplink) issues.add('client-endpoint-route-does-not-use-profile-uplink');
    if (!report.site.lan || addresses(report, report.site.lan.interface).length === 0) warnings.add('lan-address-not-currently-observed');
    for (const [protocol, port] of [['tcp', report.site.listenPort], ['tcp', 1053], ['udp', 1053]])
      if (portBusy(report.host.listeners, port, protocol)) issues.add(`listener-port-in-use:${protocol}:${port}`);
  } else {
    if (!addresses(report, report.site.uplink).some(value => value.split('/')[0] === report.site.endpoint))
      issues.add('exit-endpoint-not-owned-by-uplink');
    if (portBusy(report.host.listeners, report.site.port, 'tcp')) issues.add(`listener-port-in-use:tcp:${report.site.port}`);
  }
  if (report.host.defaultRoutes6 > 0) warnings.add('ipv6-default-present-profile-will-block-non-loopback-ipv6');
  if (report.host.earlyNetworkParameters === null) warnings.add('kernel-command-line-unavailable');
  else if (report.host.earlyNetworkParameters.length) issues.add('early-boot-network-parameters-require-review');
  return { status: issues.size ? 'blocked' : 'ready-for-reviewed-trial-plan', observedIssues: [...issues], warnings: [...warnings],
    mutationAllowed: false, installationAttempted: false,
    requiredOperatorDecisions: ['independent-console-or-rescue-access', 'approved-management-policy-before-filter-DROP',
      'dedicated-host-or-reviewed-transient-integration', 'approved-client-and-exit-pair', 'bounded-maintenance-window-and-rollback',
      'independent-egress-capture-interface', 'do-not-activate-over-the-only-SSH-session'],
    next: issues.size ? 'review-blockers-and-design-transient-integration; do-not-apply-site-profile' : 'human-review-before-separate-transient-trial' };
}

export async function collectNativePhysicalPreflight(options, {
  io = fs, run = runCommand, dryRun = input => installNative(input), signal,
  runtime = { node: process.version, platform: process.platform, arch: process.arch, uid: process.getuid?.() },
  hostFacts, tools: injectedTools, deadlineMs = 45000,
} = {}) {
  assert.ok(['client', 'exit'].includes(options.role));
  const binary = metadata(io, options.binary, { executable: true, limit: 64 * 1024 * 1024 });
  const configFile = metadata(io, options.config, { secret: true, limit: 16384 });
  const siteFile = metadata(io, options.siteProfile, { secret: true, limit: 16384 });
  const engineConfig = JSON.parse(configFile.bytes), siteInput = JSON.parse(siteFile.bytes);
  assert.deepEqual(Object.keys(siteInput).sort(), ['link_unit', 'profile']);
  assert.equal(engineConfig.role, options.role); assert.equal(siteInput.profile.role, options.role);
  assert.equal(engineConfig.transport, 'combo-tls'); assert.equal(siteInput.profile.transport, 'combo-tls');
  const controller = new AbortController(), abort = () => controller.abort();
  const timer = setTimeout(abort, deadlineMs);
  signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
  const command = async (file, args, { maxBytes = 256 * 1024, timeoutMs = 5000 } = {}) => {
    try { return await run(file, args, { cwd: ROOT, env: DIAGNOSTIC_ENV, signal: controller.signal, timeoutMs, maxBytes }); }
    catch { return { code: null, reason: 'unavailable', signal: null, stdout: '', stderr: '', durationMs: null }; }
  };
  try {
    const capabilityResult = await command(options.binary, ['--capabilities'], { maxBytes: 16384 });
    const capability = parseJson(capabilityResult, {});
    const checkResult = await command(options.binary, ['--check-config', options.config], { maxBytes: 16384, timeoutMs: 10000 });
    const sitePlan = nativeSitePlan({ name: options.name, target: `/opt/clean-vpn-native/${options.name}`,
      site: siteInput, engine: engineConfig, capability });
    const networkPlan = nativeNetworkPlan(siteInput.profile);
    let offlineInstallDryRun;
    try { offlineInstallDryRun = dryRun({ name: options.name, binary: options.binary, config: options.config, siteProfile: options.siteProfile, apply: false }); }
    catch (error) { offlineInstallDryRun = { status: 'failed', reason: /^[a-z0-9_-]+$/.test(error?.message ?? '') ? error.message : 'validation_failed' }; }
    const facts = hostFacts ?? (() => {
      const read = file => { try { return io.readFileSync(file, 'utf8'); } catch { return null; } };
      let sameNetworkNamespace = null;
      try { sameNetworkNamespace = io.readlinkSync('/proc/1/ns/net') === io.readlinkSync('/proc/self/ns/net'); } catch {}
      let tunDevice = false; try { tunDevice = io.statSync('/dev/net/tun').isCharacterDevice(); } catch {}
      const cmdline = read('/proc/cmdline');
      return { pid1: read('/proc/1/comm')?.trim() ?? null, sameNetworkNamespace, tunDevice,
        earlyNetworkParameters: cmdline === null ? null : cmdline.trim().split(/\s+/).map(v => v.split('=')[0]).filter(v => ['ip', 'nfsroot', 'netroot', 'rd.neednet', 'BOOTIF'].includes(v)) };
    })();
    const tools = injectedTools ?? Object.fromEntries(requiredTools.map(name => {
      for (const dir of ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin']) {
        try { io.accessSync(`${dir}/${name}`, io.constants.X_OK); return [name, `${dir}/${name}`]; } catch {}
      }
      return [name, null];
    }));
    const commandResults = {};
    for (const [name, file, args] of [
      ['revision', 'git', ['rev-parse', '--short', 'HEAD']], ['links', 'ip', ['-j', '-d', 'link', 'show']],
      ['addresses', 'ip', ['-j', 'address', 'show']], ['routes4', 'ip', ['-j', '-4', 'route', 'show', 'table', 'all']],
      ['routes6', 'ip', ['-j', '-6', 'route', 'show', 'table', 'all']], ['rules4', 'ip', ['-j', '-4', 'rule', 'show']],
      ['endpointRoute', 'ip', ['-j', '-4', 'route', 'get', siteInput.profile.endpoint]], ['listeners', 'ss', ['-H', '-lntu']],
      ['forwarding', 'sysctl', ['-n', 'net.ipv4.ip_forward']],
      ['ipv4Filter', 'iptables-save', ['-t', 'filter']], ['ipv4Nat', 'iptables-save', ['-t', 'nat']],
      ['ipv4Mangle', 'iptables-save', ['-t', 'mangle']], ['ipv6Filter', 'ip6tables-save', ['-t', 'filter']],
      ['ipv4All', 'iptables-save', []], ['ipv6All', 'ip6tables-save', []],
    ]) commandResults[name] = await command(file, args);
    const plannedUnits = [...sitePlan.units].map(([name, body]) => ({ name, sha256: hash(body), content: body }));
    const plannedUnitState = {};
    for (const { name } of plannedUnits) plannedUnitState[name] = unitProperties(await command('systemctl', ['--no-pager', 'show', name,
      '--property=LoadState,ActiveState,UnitFileState,FragmentPath']));
    const linkUnit = unitProperties(await command('systemctl', ['--no-pager', 'show', siteInput.link_unit,
      '--property=LoadState,ActiveState,UnitFileState,FragmentPath']));
    let bundlePathState = 'absent'; try { io.lstatSync(`/opt/clean-vpn-native/${options.name}`); bundlePathState = 'present'; }
    catch (error) { if (error.code !== 'ENOENT') bundlePathState = 'unknown'; }
    const machine = elfMachine(binary.bytes), expected = archMachines[runtime.arch] ?? null;
    const report = { schema: 1, kind: 'clean-vpn-native-physical-preflight', timestamp: new Date().toISOString(),
      mode: 'read-only-offline-plan', systemSettingsChanged: false, networkProbesSent: 0, installationAttempted: false,
      request: { role: options.role, name: options.name }, runtime, tools, aborted: controller.signal.aborted,
      privacy: 'Contains IPs, interface names, unit contents and source paths; no key/certificate bytes, environment, packet payload or raw config.',
      evidence: { binary: binary.evidence, config: configFile.evidence, siteProfile: siteFile.evidence },
      engine: { role: engineConfig.role, transport: engineConfig.transport, publicName: engineConfig.transparent?.public_name ?? null,
        peerCount: engineConfig.boring?.peers?.length ?? (engineConfig.boring?.secret_path ? 1 : 0), elfMachine: machine,
        hostElfMachine: expected, architectureMatchesHost: machine !== null && expected !== null && machine === expected,
        capabilitiesStatus: commandStatus(capabilityResult).status, configCheck: commandStatus(checkResult).status,
        capability: { engine: capability.engine ?? null, packet_ipc: capability.packet_ipc ?? null,
          service_mode: capability.service_mode ?? null, dns_socket_mark: capability.dns_socket_mark ?? null,
          combo: capability.experimental_transports?.['combo-tls'] ?? null } },
      site: { role: siteInput.profile.role, transport: siteInput.profile.transport, tun: siteInput.profile.tun,
        tunAddress: siteInput.profile.tun_address, mtu: siteInput.profile.mtu, uplink: siteInput.profile.uplink,
        endpoint: siteInput.profile.endpoint, port: siteInput.profile.port, listenPort: siteInput.profile.listen_port,
        lan: siteInput.profile.lan, denyIpv4: siteInput.profile.deny_ipv4 },
      linkUnit, offlineInstallDryRun, plannedUnitState,
      plan: { activation: sitePlan.activation, dependencies: sitePlan.dependencies, units: plannedUnits,
        network: networkPlan, fingerprints: { config: hash(configFile.bytes), siteProfile: hash(siteFile.bytes),
          ipv4Filter: hash(networkPlan.ipv4), ipv4Nat: hash(networkPlan.nat), ipv4Mangle: hash(networkPlan.mangle), ipv6Filter: hash(networkPlan.ipv6) } },
      host: { ...facts, bundlePathState, links: parseJson(commandResults.links, null), addresses: parseJson(commandResults.addresses, null),
        routes4: parseJson(commandResults.routes4, null), routes6: parseJson(commandResults.routes6, null), rules4: parseJson(commandResults.rules4, null),
        endpointRoute: parseJson(commandResults.endpointRoute, null), listeners: commandResults.listeners?.code === 0 ? commandResults.listeners.stdout : null,
        forwarding: commandResults.forwarding?.code === 0 ? commandResults.forwarding.stdout.trim() : null,
        defaultRoutes6: (parseJson(commandResults.routes6, []) ?? []).filter(route => route?.dst === 'default').length,
        firewall: [['ipv4-filter', 'ipv4Filter'], ['ipv4-nat', 'ipv4Nat'], ['ipv4-mangle', 'ipv4Mangle'], ['ipv6-filter', 'ipv6Filter'],
          ['ipv4-all-tables', 'ipv4All'], ['ipv6-all-tables', 'ipv6All']]
          .map(([name, key]) => ({ name, command: commandStatus(commandResults[key]), empty: commandResults[key]?.code === 0 ? emptyTables(commandResults[key].stdout) : null,
            sha256: commandResults[key]?.code === 0 ? hash(commandResults[key].stdout) : null })) },
      commandStatus: Object.fromEntries(Object.entries(commandResults).map(([name, result]) => [name, commandStatus(result)])),
      limitations: ['read-only-not-activation-authority', 'no-network-probes', 'no-provider-firewall-or-console-evidence',
        'no-packet-capture-or-leak-proof', 'point-in-time-listener-and-route-state', 'fresh-dedicated-site-contract-not-existing-host-migration'] };
    Object.assign(report, assessNativePhysicalPreflight(report));
    return report;
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}
