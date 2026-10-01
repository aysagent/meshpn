/** Read-only inventory before a human-reviewed host installation. No probes,
 * journal locks, VPN argv, network config contents, or systemctl mutations. */
import * as fs from 'node:fs';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { runCommand } from './transparent-acceptance.mjs';
import { DIAGNOSTIC_ENV } from './dns-diagnostic.mjs';
import { networkdGatePaths } from './host-networkd-gate.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const PREFLIGHT_UNITS = ['systemd-networkd.service', 'systemd-networkd.socket', 'NetworkManager.service', 'networking.service', 'connman.service', 'wicked.service', 'wpa_supplicant.service', 'systemd-resolved.service', 'dnsmasq.service', 'clean-vpn.service', 'clean-vpn-killswitch.service'];
const TOOLS = ['ip', 'iptables', 'ip6tables', 'iptables-restore', 'ip6tables-restore', 'sysctl', 'openssl', 'conntrack', 'systemctl', 'curl', 'tcpdump', 'dig', 'getent'];
const PATHS = ['/etc/systemd/system/clean-vpn.service', '/etc/systemd/system/clean-vpn-killswitch.service', '/usr/local/bin/clean-vpn-run.sh', '/usr/local/bin/clean-vpn-killswitch.sh', ...networkdGatePaths('clean-vpn')];
export function parseHostPreflightArgs(args) {
  if (args.length === 1 && args[0] === '--help') return { help: true };
  if (args.length !== 1 || !args[0].startsWith('--exit-ip=') || isIP(args[0].slice(10)) !== 4) throw Error('one numeric IPv4 exit required');
  return { exitIp: args[0].slice(10) };
}
function good(r) { return r?.code === 0 && !r.reason && !r.signal; }
function json(r) { try { const v = JSON.parse(r.stdout); return good(r) && Array.isArray(v) ? v : null; } catch { return null; } }
function properties(r) {
  if (!good(r)) return null;
  const allowed = new Set(['LoadState', 'ActiveState', 'UnitFileState']);
  const value = {};
  for (const line of r.stdout.split('\n')) {
    const [key, ...rest] = line.split('=');
    if (allowed.has(key)) value[key] = rest.join('=');
  }
  return allowed.size === Object.keys(value).length ? value : null;
}
export function assessHostPreflight(r) {
  const issues = [];
  if (r.runtime.uid !== 0 || r.pid1 !== 'systemd' || r.sameNetworkNamespace !== true) issues.push('root-systemd-host-namespace-required');
  if (r.units['systemd-networkd.service']?.ActiveState !== 'active') issues.push('networkd-not-confirmed-active');
  if (r.units['systemd-networkd.socket']?.LoadState !== 'loaded') issues.push('networkd-socket-not-confirmed');
  for (const name of ['NetworkManager.service', 'networking.service', 'connman.service', 'wicked.service']) {
    const u = r.units[name];
    if (!u || !(['not-found', 'masked'].includes(u.LoadState) || u.LoadState === 'loaded' && u.ActiveState === 'inactive' && ['disabled', 'masked'].includes(u.UnitFileState))) issues.push(`network-manager-review:${name}`);
  }
  const links = json(r.commands.links), route = json(r.commands.exitRoute);
  if (!links || links.some(l => !l || typeof l.ifname !== 'string')) issues.push('link-inventory-unavailable');
  else if (links.some(l => l.ifname === 'tun0' || l.linkinfo?.info_kind === 'tun')) issues.push('manual-TUN-present-stop-before-install');
  if (!route?.[0]?.dev || route[0].dev === 'lo' || route[0].dev === 'tun0') issues.push('exit-uplink-not-confirmed');
  const setup = [r.uplinkNetworkd?.SETUP_STATE, r.uplinkNetworkd?.ADMIN_STATE].filter(v => v !== undefined);
  if (!r.uplinkNetworkd?.NETWORK_FILE || !setup.length || !setup.every(v => v === 'configured')) issues.push('uplink-networkd-ownership-review');
  for (const name of ['clean-vpn.service', 'clean-vpn-killswitch.service']) {
    const u = r.units[name];
    if (!u || u.LoadState !== 'not-found' || u.ActiveState !== 'inactive') issues.push(`existing-or-uncertain-unit:${name}`);
  }
  if (Object.values(r.installationPaths).some(v => v !== 'absent')) issues.push('existing-or-uncertain-installation-files');
  if (Object.values(r.tools).some(v => !v)) issues.push('required-tools-missing');
  if (r.tunDevice !== true || r.tunAddon !== 'present') issues.push('TUN-prerequisites-review');
  if (r.earlyNetworkParameters === null || r.earlyNetworkParameters.length) issues.push('early-boot-network-review');
  if (r.aborted) issues.push('collection-aborted');
  return { status: issues.length ? 'review-required' : 'inventory-ready-for-review', issues,
    requiredHumanReview: ['local-console-recovery-access', 'no-network-configured-before-systemd-guard', 'WiFi-association-and-DHCP-on-real-cold-boot', 'SSH-port-and-management-access', 'install-stop-restart-reboot-plan-before-changes'] };
}
export async function collectHostPreflight({ exitIp }, { io = fs, run = runCommand, signal, deadlineMs = 45000, runtime = { node: process.version, platform: process.platform, uid: process.getuid?.() } } = {}) {
  if (isIP(exitIp) !== 4) throw Error('invalid exit');
  const controller = new AbortController(), abort = () => controller.abort();
  const timer = setTimeout(abort, deadlineMs);
  signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
  const report = { schema: 1, kind: 'clean-vpn-host-preflight', timestamp: new Date().toISOString(), systemSettingsChanged: false, networkProbesSent: 0, exitIp, runtime, commands: {}, units: {}, tools: {}, installationPaths: {},
    privacy: 'IP addresses, interfaces, unit states and networkd file path only. No config contents, WiFi passwords, VPN argv, keys or journals.',
    limitations: ['read-only-not-an-installer', 'no-firewall-or-leak-proof', 'no-initramfs-audit', 'no-WiFi-reboot-test', 'not-production-acceptance', 'default-clean-vpn-service-name-only'] };
  const read = path => { try { const s = io.statSync(path); if (s.size > 65536 || !s.isFile()) return null; const text = io.readFileSync(path, 'utf8'); return text.length <= 65536 ? text : null; } catch { return null; } };
  const command = async (file, args) => {
    try { return await run(file, args, { cwd: ROOT, env: DIAGNOSTIC_ENV, signal: controller.signal, timeoutMs: 4000, maxBytes: 65536 }); }
    catch { return { code: null, reason: 'unavailable', stdout: '', stderr: '' }; }
  };
  try {
    report.pid1 = read('/proc/1/comm')?.trim() ?? null;
    try { report.sameNetworkNamespace = io.readlinkSync('/proc/1/ns/net') === io.readlinkSync('/proc/self/ns/net'); } catch { report.sameNetworkNamespace = null; }
    const cmdline = read('/proc/cmdline');
    report.earlyNetworkParameters = cmdline === null ? null : cmdline.trim().split(/\s+/).map(s => s.split('=')[0]).filter(k => ['ip', 'nfsroot', 'netroot', 'rd.neednet', 'BOOTIF'].includes(k));
    for (const path of PATHS) { try { io.lstatSync(path); report.installationPaths[path] = 'present'; } catch (e) { report.installationPaths[path] = e.code === 'ENOENT' ? 'absent' : 'unknown'; } }
    for (const name of TOOLS) {
      report.tools[name] = null;
      for (const dir of ['/usr/sbin', '/usr/bin', '/sbin', '/bin']) { try { io.accessSync(`${dir}/${name}`, io.constants.X_OK); report.tools[name] = `${dir}/${name}`; break; } catch {} }
    }
    try { report.tunDevice = io.statSync('/dev/net/tun').isCharacterDevice(); } catch { report.tunDevice = false; }
    try { report.tunAddon = io.statSync(`${ROOT}native/tun_linux/build/Release/tun_linux.node`).isFile() ? 'present' : 'unknown'; } catch { report.tunAddon = 'missing'; }
    // Only fixed read-only commands. No shell, systemctl status/journal, or user args.
    const commands = [['revision', 'git', ['rev-parse', '--short', 'HEAD']], ['links', 'ip', ['-j', '-d', 'link', 'show']], ['addresses', 'ip', ['-j', 'address', 'show']], ['exitRoute', 'ip', ['-j', '-4', 'route', 'get', exitIp]], ['routes4', 'ip', ['-j', '-4', 'route', 'show', 'table', 'all']], ['routes6', 'ip', ['-j', '-6', 'route', 'show', 'table', 'all']]];
    for (const [name, file, args] of commands) report.commands[name] = await command(file, args);
    for (const unit of PREFLIGHT_UNITS) report.units[unit] = properties(await command('systemctl', ['--no-pager', 'show', unit, '--property=LoadState,ActiveState,UnitFileState']));
    const uplink = json(report.commands.exitRoute)?.[0]?.dev;
    const index = json(report.commands.links)?.find(l => l?.ifname === uplink)?.ifindex;
    report.uplink = typeof uplink === 'string' ? uplink : null;
    report.uplinkNetworkd = {};
    if (Number.isSafeInteger(index) && index > 0) for (const line of (read(`/run/systemd/netif/links/${index}`) ?? '').split('\n')) {
      const m = /^(NETWORK_FILE|SETUP_STATE|OPER_STATE|ADDRESS_STATE|ADMIN_STATE)=(.*)$/.exec(line);
      if (m) report.uplinkNetworkd[m[1]] = m[2];
    }
    report.aborted = controller.signal.aborted;
    Object.assign(report, assessHostPreflight(report));
    return report;
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}
