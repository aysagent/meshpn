/** Bounded, read-only host-client smoke. Never starts/stops VPN or repairs networking. */
import { isIPv4 } from 'node:net';
import { arch, release } from 'node:os';
import { fileURLToPath } from 'node:url';
import { runCommand } from './transparent-acceptance.mjs';
import { DIAGNOSTIC_ENV } from './dns-diagnostic.mjs';
import { isPublicRelayAddress } from './transparent-tls-destination.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const ENDPOINTS = Object.freeze({ trace: 'https://1.1.1.1/cdn-cgi/trace', downloadHost: 'speed.cloudflare.com' });
const MARKER = '\nCLEAN_VPN_CURL_STATS\t';
const FORMAT = `${MARKER}%{http_code}\t%{remote_ip}\t%{local_ip}\t%{size_download}\t%{time_total}\t%{ssl_verify_result}\t%{http_version}\n`;
const good = r => r?.code === 0 && r.reason === null;
function json(r) { try { return good(r) ? JSON.parse(r.stdout) : null; } catch { return null; } }

export function parseClientCheckArgs(args) {
  const options = { probe: false, tun: 'tun0', expectedExitIp: null }, seen = new Set();
  for (const arg of args) {
    const key = arg.split('=')[0];
    if (seen.has(key)) throw Error('duplicate option'); seen.add(key);
    if (arg === '--help') options.help = true;
    else if (arg === '--probe') options.probe = true;
    else if (/^--tun=[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$/.test(arg) && !arg.endsWith('=lo')) options.tun = arg.slice(6);
    else if (key === '--expect-exit-ip' && isIPv4(arg.slice(17)) && isPublicRelayAddress(arg.slice(17))) options.expectedExitIp = arg.slice(17);
    else throw Error('Use --probe, --tun=NAME, --expect-exit-ip=PUBLIC_IPV4 or --help');
  }
  return options;
}

export function parseClientCurl(result, { trace = false, remoteIp, size } = {}) {
  const at = result.stdout.lastIndexOf(MARKER), fields = result.stdout.slice(at + MARKER.length).trim().split('\t');
  const valid = at >= 0 && fields.length === 7 && /^\d{3}$/.test(fields[0]) && isIPv4(fields[1]) && isIPv4(fields[2]) &&
    /^\d+$/.test(fields[3]) && /^\d+(?:\.\d+)?$/.test(fields[4]) && /^\d+$/.test(fields[5]) && /^[\d.]+$/.test(fields[6]);
  const out = { status: 'failed', code: result.code, reason: result.reason, durationMs: result.durationMs };
  // Do not include remote bodies, arbitrary headers, environment, or tool stderr in a copyable report.
  if (!valid) return { ...out, detail: 'missing-or-invalid-curl-metrics' };
  Object.assign(out, { httpStatus: Number(fields[0]), remoteIp: fields[1], localIp: fields[2],
    downloadedBytes: Number(fields[3]), seconds: Number(fields[4]), tlsVerifyResult: Number(fields[5]), httpVersion: fields[6] });
  if (trace) {
    const ip = /^ip=([^\r\n]+)$/m.exec(result.stdout.slice(0, at))?.[1];
    out.observedExitIp = isIPv4(ip) && isPublicRelayAddress(ip) ? ip : null;
  }
  if (good(result) && out.httpStatus === 200 && out.tlsVerifyResult === 0 && out.remoteIp === remoteIp &&
      (!trace || out.observedExitIp) && (size === undefined || out.downloadedBytes === size)) out.status = 'passed';
  return out;
}

function viaTun(result, tun) {
  const rows = json(result);
  return Array.isArray(rows) && rows.length === 1 && rows[0].dev === tun && (!rows[0].type || rows[0].type === 'unicast');
}

// Exported for a real curl/loopback TLS contract test; CLI endpoints remain fixed.
export function clientCurlArgs({ tun, url, ip, host, trace = false }) {
  const args = ['-q', '--silent', '--show-error', '--ipv4', '--noproxy', '*', '--proxy', '',
    '--proto', '=https', '--connect-timeout', '5', '--max-time', '20', '--max-redirs', '0',
    '--interface', `if!${tun}`, '--max-filesize', String(trace ? 16384 : 1048576),
    '--limit-rate', trace ? '16K' : '128K', '--output', trace ? '-' : '/dev/null', '--write-out', FORMAT];
  if (host) args.push('--resolve', `${host}:443:${ip}`);
  args.push(url);
  return args;
}

export async function collectClientCheck(options, { run = runCommand, signal, onProgress = () => {} } = {}) {
  options = parseClientCheckArgs([...(options.probe ? ['--probe'] : []), `--tun=${options.tun ?? 'tun0'}`,
    ...(options.expectedExitIp ? [`--expect-exit-ip=${options.expectedExitIp}`] : [])]);
  const controller = new AbortController(), abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
  const timer = setTimeout(abort, 90000);
  const report = { schema: 1, kind: 'clean-vpn-client-check', timestamp: new Date().toISOString(),
    mode: options.probe ? 'active-client-probes' : 'inspection-only', systemSettingsChanged: false,
    runtime: { node: process.version, kernel: release(), arch: arch() }, tun: options.tun,
    expectedExitIp: options.expectedExitIp,
    privacy: 'Includes network addresses/routes and observed egress IP. No keys, VPN argv, response bodies or journals.',
    networkNotice: 'With --probe: real DNS queries, HTTPS to Cloudflare, and a requested 1 MiB download. No upload of user files.',
    checks: {}, commands: {}, probes: {}, limitations: ['host-client-only-not-forwarded-peers',
      'not-a-packet-capture-or-leak-test', 'not-a-kill-switch-or-crash-recovery-test',
      'no-VPN-certificate-or-bearer-inspection', 'not-a-throughput-benchmark', 'no-upload-or-long-lived-connection-test',
      'IPv6-routing-evidence-not-effective-firewall-policy', 'DNS-may-be-cached-or-use-current-direct-path'] };
  const exec = async (name, args, timeoutMs = 3000, maxBytes = 32768) => {
    const result = await run(name, args, { cwd: ROOT, env: DIAGNOSTIC_ENV, signal: controller.signal, timeoutMs, maxBytes });
    return result;
  };
  const recorded = async (key, name, args) => {
    const r = await exec(name, args); report.commands[key] = r; return r;
  };
  try {
    onProgress('Снимок интерфейсов и маршрутов; настройки не меняются');
    const commands = [
      ['revision', 'git', ['rev-parse', '--short', 'HEAD']], ['curlVersion', 'curl', ['-q', '--version']],
      ['addresses', 'ip', ['-j', 'addr', 'show']], ['rules4', 'ip', ['-j', '-4', 'rule', 'show']],
      ['routes4', 'ip', ['-j', '-4', 'route', 'show', 'table', 'all']],
      ['rules6', 'ip', ['-j', '-6', 'rule', 'show']], ['routes6', 'ip', ['-j', '-6', 'route', 'show', 'table', 'all']],
      ['internetRoute', 'ip', ['-j', '-4', 'route', 'get', '1.0.0.1']],
      ['traceRoute', 'ip', ['-j', '-4', 'route', 'get', '1.1.1.1']],
      ['ipv6Route', 'ip', ['-j', '-6', 'route', 'get', '2606:4700:4700::1111']],
    ];
    // Sequential commands avoid signal listener fan-out and keep report ordering stable.
    for (const [key, file, args] of commands) { if (controller.signal.aborted) break; await recorded(key, file, args); }
    const links = json(report.commands.addresses), link = Array.isArray(links) ? links.find(l => l.ifname === options.tun) : null;
    const addresses = link?.addr_info?.filter(a => a.family === 'inet').map(a => a.local) ?? [];
    report.checks.tun = link?.flags?.includes('UP') && addresses.length ? 'passed' : 'missing-or-not-ready';
    report.checks.internetRoute = viaTun(report.commands.internetRoute, options.tun) ? 'passed' : 'not-confirmed-through-tun';
    report.checks.traceRoute = viaTun(report.commands.traceRoute, options.tun) ? 'passed' : 'not-confirmed-through-tun';
    const v6 = json(report.commands.ipv6Route);
    report.checks.ipv6 = Array.isArray(v6) && v6.length === 1 && v6[0].dev && v6[0].dev !== options.tun && (!v6[0].type || v6[0].type === 'unicast')
      ? 'direct-route-present-review-required' : 'not-established';
    const eligible = report.checks.tun === 'passed' && report.checks.internetRoute === 'passed' && report.checks.traceRoute === 'passed';
    if (!options.probe) report.probes.status = 'not-requested';
    else if (!eligible) {
      report.probes.status = 'skipped-no-confirmed-host-tunnel-route';
      report.next = 'Review running client and --split-default; do not enable over public SSH without independent access. This script changes no routes.';
    }
    else {
      onProgress('Проверяю DNS и HTTPS через существующий TUN');
      const nss = await exec('getent', ['ahostsv4', 'example.com'], 5000, 8192);
      report.probes.nss = { status: good(nss) && nss.stdout.split('\n').some(l => isIPv4(l.trim().split(/\s/)[0])) ? 'passed' : 'failed',
        code: nss.code, reason: nss.reason, durationMs: nss.durationMs };
      report.probes.dns = [];
      for (const type of ['A', 'AAAA']) for (const transport of ['udp', 'tcp']) {
        const r = await exec('dig', ['example.com', type, transport === 'tcp' ? '+tcp' : '+notcp', '+ignore', '+time=2', '+tries=1', '+noall', '+comments', '+answer'], 4000, 8192);
        const status = /status: ([A-Z]+),/.exec(r.stdout)?.[1] ?? null;
        report.probes.dns.push({ type, transport, status: good(r) && status === 'NOERROR' && new RegExp(`\\sIN\\s+${type}\\s`).test(r.stdout) ? 'passed' : 'failed',
          dnsStatus: status, code: r.code, reason: r.reason, durationMs: r.durationMs });
      }
      const curl = async ({ url, ip, host, trace = false, size }) => {
        const before = await exec('ip', ['-j', '-4', 'route', 'get', ip]);
        if (!viaTun(before, options.tun)) return { status: 'skipped', detail: 'destination-route-not-through-tun' };
        const args = clientCurlArgs({ tun: options.tun, url, ip, host, trace });
        const r = parseClientCurl(await exec('curl', args, 23000, 24576), { trace, remoteIp: ip, size });
        const after = await exec('ip', ['-j', '-4', 'route', 'get', ip]);
        if (!viaTun(after, options.tun) || r.status === 'passed' && !addresses.includes(r.localIp)) {
          r.status = 'failed'; r.detail = 'route-or-source-changed';
        }
        return r;
      };
      report.probes.egress = await curl({ url: ENDPOINTS.trace, ip: '1.1.1.1', trace: true });
      report.probes.repeatHttps = await curl({ url: ENDPOINTS.trace, ip: '1.1.1.1', trace: true });
      const observed = report.probes.egress.observedExitIp;
      report.checks.egress = report.probes.egress.status !== 'passed' ? 'failed'
        : !options.expectedExitIp ? 'expected-IP-not-specified' : observed === options.expectedExitIp ? 'passed' : 'mismatch';
      onProgress('Проверяю загрузку 1 MiB; скорость здесь не является бенчмарком');
      const resolved = await exec('getent', ['ahostsv4', ENDPOINTS.downloadHost], 5000, 8192);
      const ip = good(resolved) ? resolved.stdout.split('\n').map(l => l.trim().split(/\s/)[0]).find(a => isIPv4(a) && isPublicRelayAddress(a)) : null;
      report.probes.download = ip ? await curl({ url: `https://${ENDPOINTS.downloadHost}/__down?bytes=1048576`,
        host: ENDPOINTS.downloadHost, ip, size: 1048576 }) : { status: 'failed', detail: 'download-name-resolution-failed' };
      report.checks.ipv4Smoke = report.probes.nss.status === 'passed' && report.probes.dns.every(p => p.status === 'passed') && report.checks.egress === 'passed' &&
        report.probes.repeatHttps.status === 'passed' && report.probes.repeatHttps.observedExitIp === options.expectedExitIp &&
        report.probes.download.status === 'passed' ? 'passed' : 'incomplete-or-failed';
    }
    report.deadlineOrSignalAborted = controller.signal.aborted;
    report.status = controller.signal.aborted ? 'aborted' : !options.probe ? 'inspection-only'
      : report.checks.ipv4Smoke === 'passed' ? 'ipv4-smoke-passed' : 'incomplete-or-failed';
    return report;
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}
