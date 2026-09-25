/** Bounded support report. No setters, shell, sudo, explicit service starts or file writes. */
import { access, readdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import { release, arch } from 'node:os';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { inspectSystemDns, boundedInspectRead } from './dns-inspect.mjs';
import { runCommand } from './transparent-acceptance.mjs';
import { filterDnsmasqDiagnostic, summarizeDnsmasqDiagnostic } from './dnsmasq-config.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const DIAGNOSTIC_ENV = Object.freeze({ PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C',
  SYSTEMD_PAGER: 'cat', SYSTEMD_COLORS: '0', SYSTEMD_URLIFY: '0',
  GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' });
export function parseDiagnosticArgs(args) {
  if (args.length === 0) return { probe: false };
  if (args.length === 1 && args[0] === '--probe') return { probe: true };
  if (args.length === 1 && args[0] === '--help') return { help: true };
  throw new Error('Usage: node scripts/dns-diagnostic.mjs [--probe]');
}

// Keep only DNS/routing ownership fields; never dump arbitrary configuration or comments.
const INI_KEYS = {
  Resolve: ['DNS', 'FallbackDNS', 'Domains', 'DNSSEC', 'DNSOverTLS', 'DNSStubListener',
    'DNSStubListenerExtra', 'LLMNR', 'MulticastDNS', 'Cache', 'ReadEtcHosts'],
  Match: ['Name', 'OriginalName', 'Type', 'Kind'],
  Network: ['DNS', 'Domains', 'DNSDefaultRoute', 'DHCP', 'IPv6AcceptRA', 'DNSSEC', 'DNSOverTLS', 'LLMNR', 'MulticastDNS'],
  DHCP: ['UseDNS', 'UseDomains'], DHCPv4: ['UseDNS', 'UseDomains'], DHCPv6: ['UseDNS', 'UseDomains'],
  IPv6AcceptRA: ['UseDNS', 'UseDomains'], main: ['dns', 'rc-manager', 'systemd-resolved'],
};
export function filterDiagnosticIni(text) {
  let section = ''; const entries = [];
  for (const line of text.split('\n')) {
    const header = /^\s*\[([\w-]+)\]\s*$/.exec(line);
    if (header) { section = header[1]; continue; }
    const field = /^\s*([\w-]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (field && INI_KEYS[section]?.includes(field[1])) {
      entries.push({ section, key: field[1], value: field[2].replace(/\s+[#;].*$/, '') });
    }
  }
  return entries;
}

async function systemExecutable(name) {
  for (const directory of ['/usr/bin', '/usr/sbin', '/bin', '/sbin']) {
    const path = join(directory, name);
    try { await access(path, constants.X_OK); return path; } catch {}
  }
  return null;
}
async function batch(items, fn) {
  const out = [];
  for (let offset = 0; offset < items.length; offset += 4) out.push(...await Promise.all(items.slice(offset, offset + 4).map(fn)));
  return out;
}
const unavailable = (error) => ({ status: 'unavailable', reason: error?.code ?? 'read-failed' });

export async function collectDnsDiagnostic({ probe = false } = {}, {
  inspect = inspectSystemDns, read = boundedInspectRead, list = readdir,
  find = systemExecutable, run = runCommand, budgetMs = 60000,
} = {}) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), budgetMs);
  // Nested link/property batches must share one limit, not multiply it to 16.
  let active = 0;
  const waiting = [];
  const limited = async (fn) => {
    if (active >= 4) await new Promise((resolve) => waiting.push(resolve));
    else active++;
    try { return await fn(); }
    finally { const next = waiting.shift(); if (next) next(); else active--; }
  };
  const report = { schema: 1, kind: 'clean-vpn-dns-diagnostic', timestamp: new Date().toISOString(),
    mode: probe ? 'inspection-with-dns-probes' : 'inspection-only', systemSettingsChanged: false,
    privacy: 'Contains IP addresses, interface names and DNS domains. No credentials, process argv or journals collected.',
    runtime: { node: process.version, kernel: release(), arch: arch(), uid: process.getuid?.() },
    commands: {}, files: {}, resolved: {}, probes: [], limitations: [
      'point-in-time-not-ownership-proof', 'not-a-DNS-leak-test', 'not-a-live-installer',
      'filtered-config-inventory-not-an-effective-config-parser', 'no-process-argv-or-VPN-role-detection',
      'non-systemd-PID1-system-bus-not-probed', 'limits-8-resolved-links-48-network-config-files',
    ] };
  const command = (name, args) => limited(async () => {
    if (controller.signal.aborted) return { status: 'unavailable', reason: 'report-deadline' };
    try {
      const file = await find(name);
      if (!file) return { status: 'unavailable', reason: 'command-not-found' };
      if (controller.signal.aborted) return { status: 'unavailable', reason: 'report-deadline' };
      const r = await run(file, args, { cwd: ROOT, env: { ...DIAGNOSTIC_ENV }, signal: controller.signal,
        timeoutMs: 3000, maxBytes: 8192 });
      return { status: r.reason === null && r.code === 0 ? 'ok' : 'unavailable', code: r.code, reason: r.reason,
        stdout: r.stdout, stderr: r.stderr, durationMs: r.durationMs };
    } catch (error) { return unavailable(error); }
  });
  const file = async (path, filter) => {
    try {
      const data = filter(await read(path, 32768));
      if (Buffer.byteLength(JSON.stringify(data)) > 8192) return { status: 'unavailable', reason: 'filtered-output-limit' };
      return { status: 'ok', data };
    }
    catch (error) { return unavailable(error); }
  };
  const busArgs = ['--system', '--no-pager', '--auto-start=no', '--allow-interactive-authorization=no', '--timeout=2s', '--json=short'];
  const bus = async (args) => {
    const result = await command('busctl', [...busArgs, ...args]);
    if (result.status !== 'ok') return result;
    try {
      const parsed = JSON.parse(result.stdout);
      if (!Object.hasOwn(parsed, 'data')) throw new Error('missing data');
      return { status: 'ok', value: parsed.data };
    }
    catch { return { status: 'unavailable', reason: 'invalid-bus-json' }; }
  };
  try {
    try { report.inspection = await inspect(); }
    catch (error) { report.inspection = { ...unavailable(error), environment: { pid1: 'unknown' } }; }
    report.files.osRelease = await file('/etc/os-release', (s) => s.split('\n').filter((l) => /^(ID|VERSION_ID|PRETTY_NAME)=/.test(l)));
    report.files.resolvConf = await file('/etc/resolv.conf', (s) => s.split('\n')
      .filter((l) => /^\s*(nameserver|search|domain|options)\s/.test(l)).map((l) => l.split(/[#;]/)[0].trim()));
    report.files.nssHosts = await file('/etc/nsswitch.conf', (s) => s.split('\n').filter((l) => /^\s*hosts\s*:/.test(l)).map((l) => l.split('#')[0]));
    const plan = [
      ['revision', 'git', ['-c', `safe.directory=${ROOT.replace(/\/$/, '')}`, 'rev-parse', '--short', 'HEAD']],
      ['systemdVersion', 'systemctl', ['--version']],
      ['links', 'ip', ['-j', 'link', 'show']], ['addresses', 'ip', ['-j', 'address', 'show']],
      ['routes4', 'ip', ['-4', 'route', 'show', 'table', 'all']], ['routes6', 'ip', ['-6', 'route', 'show', 'table', 'all']],
      ['rules4', 'ip', ['-4', 'rule', 'show']], ['rules6', 'ip', ['-6', 'rule', 'show']],
      ['dnsListeners', 'ss', ['-lntup', '( sport = :53 )']],
    ];
    if (report.inspection.environment.pid1 === 'systemd') plan.push(['units', 'systemctl', ['--system', '--no-pager',
      'show', 'systemd-resolved.service', 'systemd-networkd.service', 'NetworkManager.service', 'resolvconf.service',
      'dnsmasq.service',
      '-p', 'Id', '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState', '-p', 'UnitFileState']]);
    await batch(plan, async ([id, name, args]) => { report.commands[id] = await command(name, args); });

    // Inventory sources separately: do not pretend this implements systemd's precedence/masking rules.
    const configs = ['/etc/systemd/resolved.conf', '/etc/NetworkManager/NetworkManager.conf'];
    report.configDirectories = {};
    for (const directory of ['/usr/lib/systemd/resolved.conf.d', '/run/systemd/resolved.conf.d', '/etc/systemd/resolved.conf.d']) {
      try {
        const names = (await list(directory)).filter((n) => /^[\w.-]+\.conf$/.test(n)).sort();
        report.configDirectories[directory] = { count: names.length, truncated: names.length > 16 };
        configs.push(...names.slice(0, 16).map((n) => join(directory, n)));
      } catch (error) { report.configDirectories[directory] = unavailable(error); }
    }
    let networkFiles = 0;
    for (const directory of ['/etc/systemd/network', '/run/systemd/network', '/usr/lib/systemd/network']) {
      try {
        const listing = await list(directory);
        const names = listing.filter((n) => /^[\w.-]+\.network$/.test(n)).sort();
        const selected = names.slice(0, Math.max(0, 48 - networkFiles)); networkFiles += selected.length;
        report.configDirectories[directory] = { count: names.length, truncated: names.length > selected.length };
        configs.push(...selected.map((n) => join(directory, n)));
        const dropins = listing.filter((n) => /^[\w.-]+\.network\.d$/.test(n)).sort();
        report.configDirectories[directory].dropinDirectoriesTruncated = dropins.length > 16;
        for (const dropin of dropins.slice(0, 16)) {
          const path = join(directory, dropin);
          try {
            const entries = (await list(path)).filter((n) => /^[\w.-]+\.conf$/.test(n)).sort();
            const chosen = entries.slice(0, Math.max(0, 48 - networkFiles)); networkFiles += chosen.length;
            report.configDirectories[path] = { count: entries.length, truncated: entries.length > chosen.length };
            configs.push(...chosen.map((n) => join(path, n)));
          } catch (error) { report.configDirectories[path] = unavailable(error); }
        }
      } catch (error) { report.configDirectories[directory] = unavailable(error); }
    }
    report.configs = {};
    await batch(configs, async (path) => { report.configs[path] = await file(path, filterDiagnosticIni); });
    report.limitations.push('NetworkManager-connection-profiles-not-collected', 'at-most-16-network-dropin-directories-per-location');

    // Inventory only fixed conventional locations. Includes and executable hooks
    // are never followed; this is not the daemon's effective configuration.
    report.dnsmasq = { configs: {}, directory: {}, effectiveConfigKnown: false };
    const dnsmasqPaths = ['/etc/dnsmasq.conf'];
    try {
      const names = (await list('/etc/dnsmasq.d')).filter((n) => /^[\w.-]+$/.test(n) && !n.startsWith('.')).sort();
      report.dnsmasq.directory = { count: names.length, truncated: names.length > 16 };
      dnsmasqPaths.push(...names.slice(0, 16).map((n) => join('/etc/dnsmasq.d', n)));
    } catch (error) { report.dnsmasq.directory = unavailable(error); }
    await batch(dnsmasqPaths, async (path) => { report.dnsmasq.configs[path] = await file(path, filterDnsmasqDiagnostic); });
    report.dnsmasq.assessment = summarizeDnsmasqDiagnostic(report.dnsmasq);
    report.limitations.push('dnsmasq-fixed-location-inventory-not-effective-config-no-include-or-hook-execution');

    if (report.inspection.environment.pid1 !== 'systemd') report.resolved.status = 'not-probed-non-systemd';
    else {
      const owner = await bus(['call', 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus',
        'GetNameOwner', 's', 'org.freedesktop.resolve1']);
      report.resolved.owner = owner;
      const name = owner.value?.[0];
      if (owner.status === 'ok' && typeof name === 'string' && /^:\d+\.\d+$/.test(name)) {
        const properties = async (path, iface, names) => Object.fromEntries(await batch(names,
          async (property) => [property, await bus(['get-property', name, path, iface, property])]));
        report.resolved.manager = await properties('/org/freedesktop/resolve1', 'org.freedesktop.resolve1.Manager',
          ['DNS', 'DNSEx', 'FallbackDNS', 'FallbackDNSEx', 'Domains', 'DNSSEC', 'DNSOverTLS', 'ResolvConfMode']);
        let links = [];
        try { links = JSON.parse(report.commands.links.stdout).filter((l) => Number.isSafeInteger(l.ifindex) && l.ifindex > 1); }
        catch { report.resolved.linkList = 'unavailable'; }
        report.resolved.linksTruncated = links.length > 8;
        report.resolved.links = await batch(links.slice(0, 8), async (link) => {
          const result = { name: link.ifname, ifindex: link.ifindex };
          const path = await bus(['call', name, '/org/freedesktop/resolve1', 'org.freedesktop.resolve1.Manager', 'GetLink', 'i', String(link.ifindex)]);
          if (path.status !== 'ok' || !/^\/org\/freedesktop\/resolve1\/link\/[\w]+$/.test(path.value?.[0] ?? '')) return { ...result, error: path };
          return { ...result, settings: await properties(path.value[0], 'org.freedesktop.resolve1.Link',
            ['DNS', 'DNSEx', 'Domains', 'DefaultRoute', 'DNSSEC', 'DNSOverTLS']) };
        });
      } else report.resolved.status = 'unavailable-owner';
    }
    if (probe) {
      // Fixed public name, existing resolver, no arbitrary server or resolver replacement.
      report.probeNotice = 'Real example.com queries through current settings; may use direct DNS. No leak-freedom claim.';
      report.probes.push({ kind: 'system-nss-A', result: await command('getent', ['ahostsv4', 'example.com']) });
      for (const type of ['A', 'AAAA']) for (const transport of ['udp', 'tcp']) report.probes.push({ type, transport,
        result: await command('dig', ['+time=2', '+tries=1', ...(transport === 'udp' ? ['+notcp', '+ignore'] : ['+tcp']),
          '+noall', '+comments', '+answer', '+stats', 'example.com', type]) });
    }
    report.deadlineExceeded = controller.signal.aborted;
    return report;
  } finally { clearTimeout(timer); }
}
