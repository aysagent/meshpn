/** Bounded observations only. Never changes networking or starts/stops VPN. */
import { randomBytes } from 'node:crypto';
import { isIPv6 } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { child } from './browser-lab-driver.mjs';
import { runCommand } from './transparent-acceptance.mjs';
import { DIAGNOSTIC_ENV } from './dns-diagnostic.mjs';
import { parseClientCheckArgs } from './client-check.mjs';

export const V6_TARGET = '2606:4700:4700::1111';
const IFACE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$/;
const good = r => r?.code === 0 && r.reason === null;
function rows(r) { try { const v = JSON.parse(r.stdout); return good(r) && Array.isArray(v) ? v : []; } catch { return []; } }
const route = r => { const v = rows(r); return v.length === 1 && (!v[0].type || v[0].type === 'unicast') ? v[0] : null; };

export function parseLeakCheckArgs(args) {
  const options = { probe: false, tun: 'tun0', exitIp: null }, seen = new Set();
  for (const arg of args) {
    const key = arg.split('=')[0];
    if (seen.has(key)) throw Error('duplicate option'); seen.add(key);
    if (arg === '--help') options.help = true;
    else if (arg === '--probe') options.probe = true;
    else if (key === '--tun') options.tun = parseClientCheckArgs([arg]).tun;
    else if (key === '--exit-ip') options.exitIp = parseClientCheckArgs([arg.replace('--exit-ip=', '--expect-exit-ip=')]).expectedExitIp;
    else throw Error('unknown option');
  }
  if (!options.help && !options.exitIp) throw Error('--exit-ip=PUBLIC_IPV4 required');
  return options;
}

export function captureSummary({ stdout, stderr, code, signal, reason }, names) {
  const captured = /(?:^|\n)(\d+) packets captured\n/.exec(stderr);
  const dropped = /(?:^|\n)(\d+) packets dropped by kernel(?:\n|$)/.exec(stderr);
  return { healthy: code === 0 && signal === null && !reason && !!captured && !!dropped && Number(dropped[1]) === 0,
    code, signal, reason, capturedPackets: captured ? Number(captured[1]) : null,
    droppedPackets: dropped ? Number(dropped[1]) : null,
    dnsOutboundPackets: (stdout.match(/> [^\s]+\.53:/g) ?? []).length,
    ipv6TargetOutboundPackets: (stdout.match(/> 2606:4700:4700::1111\.443:/g) ?? []).length,
    // Only generated names are reported, never unrelated DNS names or raw packets.
    observedNames: names.filter(name => stdout.includes(`${name}.`)) };
}

export async function startLeakCapture(iface, filter, signal, direction = 'out') {
  if (!IFACE.test(iface)) throw Error('invalid interface');
  if (!['out', 'inout'].includes(direction)) throw Error('invalid direction');
  const p = child('tcpdump', ['-nn', '-l', '-vv', '-p', '--immediate-mode', '-s', '512', '-Q', direction, '-i', iface, filter], { env: DIAGNOSTIC_ENV });
  let stdout = '', stderr = '', bytes = 0, reason = null, stopping = false;
  const stop = () => { stopping = true; return p.stop('SIGINT'); };
  const abort = () => { reason ??= 'aborted'; void stop(); };
  const timer = setTimeout(() => { reason ??= 'capture-deadline'; void stop(); }, 75000);
  for (const [stream, append] of [[p.proc.stdout, t => { stdout += t; }], [p.proc.stderr, t => { stderr += t; }]]) {
    stream.on('data', b => { bytes += b.length; if (bytes > 512 * 1024) { reason ??= 'capture-output-limit'; void stop(); } else append(b.toString()); });
  }
  p.proc.on('error', () => { reason ??= 'capture-spawn-error'; });
  const closed = new Promise(resolve => p.proc.once('close', (code, sig) => {
    if (!stopping) reason ??= 'capture-ended-early';
    clearTimeout(timer); signal?.removeEventListener('abort', abort);
    resolve({ stdout, stderr, code, signal: sig, reason });
  }));
  signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
  try { await p.waitFor(/listening on /, 4000); }
  catch { await stop(); throw Error('capture-unavailable'); }
  return { async finish() { await stop(); return closed; } };
}

export function ipv6CurlArgs() {
  return ['-q', '--silent', '--show-error', '--ipv6', '--proxy', '', '--noproxy', '*', '--proto', '=https',
    '--connect-timeout', '5', '--max-time', '10', '--max-filesize', '16384', '--max-redirs', '0',
    '--resolve', `cloudflare-dns.com:443:[${V6_TARGET}]`, '--write-out',
    '\nLEAK_CHECK_METRICS\t%{http_code}\t%{remote_ip}\t%{local_ip}\t%{ssl_verify_result}\n',
    'https://cloudflare-dns.com/cdn-cgi/trace'];
}

export function parseIpv6Probe(r) {
  const m = /\nLEAK_CHECK_METRICS\t(\d{3})\t([^\t]*)\t([^\t]*)\t(\d+)\s*$/.exec(r.stdout);
  const ip = /^ip=([^\r\n]+)$/m.exec(r.stdout)?.[1];
  return { status: good(r) && m?.[1] === '200' && m[2] === V6_TARGET && isIPv6(m[3]) && m[4] === '0' && isIPv6(ip)
    ? 'https-connected' : 'not-established', code: r.code, reason: r.reason,
  localIp: m && isIPv6(m[3]) ? m[3] : null, observedIp: isIPv6(ip) ? ip : null,
  httpStatus: m ? Number(m[1]) : null, tlsVerifyResult: m ? Number(m[4]) : null };
}

export async function collectLeakCheck(options, { run = runCommand, capture = startLeakCapture, signal,
  settle = () => delay(1200), onProgress = () => {} } = {}) {
  options = parseLeakCheckArgs([`--exit-ip=${options.exitIp}`, `--tun=${options.tun ?? 'tun0'}`, ...(options.probe ? ['--probe'] : [])]);
  const controller = new AbortController(), abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
  const timer = setTimeout(abort, 65000), captures = [], raw = [];
  const report = { schema: 1, kind: 'clean-vpn-client-leak-check', timestamp: new Date().toISOString(),
    systemSettingsChanged: false, exitIp: options.exitIp, tun: options.tun, status: 'inconclusive', commands: {}, dns: [],
    privacy: 'Only generated probe names, network addresses and packet counts; no raw capture, other DNS names, credentials or VPN argv.',
    notice: 'Explicit --probe sends DNS and one IPv6 HTTPS request which may intentionally bypass the IPv4 VPN. No traffic blocking or repair.',
    limitations: ['single-uplink-host-only', 'port-53-only-not-DoH-DoT', 'bounded-window-not-leak-freedom',
      'tcpdump-text-no-TCP-reassembly', 'NXDOMAIN-can-be-synthesized-positive-TUN-observation-required',
      'not-kill-switch-or-crash-test', 'failed-IPv6-request-does-not-prove-blocking'] };
  const exec = (file, args, timeoutMs = 3000) => run(file, args, { env: DIAGNOSTIC_ENV, signal: controller.signal, timeoutMs, maxBytes: 32768 });
  const record = async (key, args) => { const r = await exec('ip', args); report.commands[key] = r; return r; };
  try {
    onProgress('Проверяю TUN и внешний интерфейс; настройки не меняются');
    report.commands.revision = await exec('git', ['rev-parse', '--short', 'HEAD']);
    const links = rows(await record('addresses', ['-j', 'addr', 'show']));
    const up = route(await record('exitRoute', ['-j', '-4', 'route', 'get', options.exitIp]));
    const internet = route(await record('internetRoute', ['-j', '-4', 'route', 'get', '1.0.0.1']));
    const v6 = route(await record('ipv6Route', ['-j', '-6', 'route', 'get', V6_TARGET]));
    const link = links.find(l => l.ifname === options.tun);
    const eligible = link?.flags?.includes('UP') && link.addr_info?.some(a => a.family === 'inet') &&
      internet?.dev === options.tun && up && typeof up.dev === 'string' && IFACE.test(up.dev) && ![options.tun, 'lo'].includes(up.dev) &&
      links.find(l => l.ifname === up.dev)?.flags?.includes('UP');
    report.uplink = up?.dev ?? null;
    if (!options.probe) { report.status = 'inspection-only'; return report; }
    if (!eligible) { report.detail = 'host-tunnel-and-distinct-uplink-required'; return report; }
    report.commands.tcpdumpVersion = await exec('tcpdump', ['--version']);
    if (!good(report.commands.tcpdumpVersion)) { report.detail = 'tcpdump-required-no-probes-sent'; return report; }
    onProgress('Запускаю ограниченный захват DNS на TUN/uplink; нужен tcpdump');
    captures.push(await capture(options.tun, '(udp or tcp) and dst port 53', controller.signal));
    captures.push(await capture(up.dev, `((udp or tcp) and dst port 53) or (tcp and host ${options.exitIp} and port 443) or (ip6 and tcp and dst host ${V6_TARGET} and dst port 443)`, controller.signal));
    const nonce = randomBytes(10).toString('hex');
    for (const resolver of ['system', '1.1.1.1']) for (const type of ['A', 'AAAA']) for (const transport of ['udp', 'tcp']) {
      if (controller.signal.aborted) break;
      const name = `cv-${nonce}-${report.dns.length}.example.com`;
      const r = await exec('dig', [...(resolver === 'system' ? [] : [`@${resolver}`]), `${name}.`, type,
        transport === 'tcp' ? '+tcp' : '+notcp', '+ignore', '+time=2', '+tries=1', '+noall', '+comments'], 3500);
      const dnsStatus = /status: ([A-Z]+),/.exec(r.stdout)?.[1] ?? null;
      report.dns.push({ name, resolver, type, transport, answered: good(r) && ['NOERROR', 'NXDOMAIN'].includes(dnsStatus), dnsStatus, code: r.code, reason: r.reason });
    }
    onProgress('Проверяю прямой IPv6 HTTPS: запрос может выйти вне VPN');
    const v6Before = route(await record('ipv6Before', ['-j', '-6', 'route', 'get', V6_TARGET]));
    if (v6?.dev === up.dev && v6Before?.dev === up.dev && !controller.signal.aborted) {
      report.ipv6 = parseIpv6Probe(await exec('curl', ipv6CurlArgs(), 12000));
      const after = route(await record('ipv6After', ['-j', '-6', 'route', 'get', V6_TARGET]));
      const sourceOnUplink = links.find(l => l.ifname === up.dev)?.addr_info?.some(a => a.family === 'inet6' && a.local === report.ipv6.localIp);
      report.ipv6.status = report.ipv6.status === 'https-connected' && after?.dev === up.dev && sourceOnUplink
        ? 'bypass-confirmed' : 'not-established';
    } else report.ipv6 = { status: 'not-tested', detail: 'no-matching-uplink-IPv6-route-or-aborted' };
    const endInternet = route(await record('internetAfter', ['-j', '-4', 'route', 'get', '1.0.0.1']));
    const endExit = route(await record('exitAfter', ['-j', '-4', 'route', 'get', options.exitIp]));
    if (endInternet?.dev !== options.tun || endExit?.dev !== up.dev) report.detail = 'routes-changed-during-check';
    await settle(); // Drain line-buffered capture; no changes to DNS caches or networking.
  } catch { report.detail = 'collection-or-capture-unavailable-check-tcpdump-and-permissions'; }
  finally {
    for (const cap of captures) { try { raw.push(await cap.finish()); } catch { raw.push({ stdout: '', stderr: '', reason: 'capture-cleanup-failed' }); } }
    clearTimeout(timer); signal?.removeEventListener('abort', abort);
    report.aborted = controller.signal.aborted;
    if (report.aborted) report.status = 'aborted';
  }
  const names = report.dns.map(d => d.name);
  report.captures = raw.map(r => captureSummary(r, names));
  const [tun, uplink] = report.captures;
  const leak = uplink?.observedNames.length > 0;
  const complete = report.dns.length === 8 && report.dns.every(d => d.answered) && tun?.healthy && uplink?.healthy &&
    tun.observedNames.length === 8 && uplink.capturedPackets > 0 && !report.aborted && !report.detail;
  report.dnsObservation = leak ? 'probe-DNS-on-uplink' : uplink?.dnsOutboundPackets > 0 ? 'other-port53-traffic-on-uplink-review'
    : complete ? 'probes-seen-on-TUN-not-on-uplink' : 'inconclusive';
  if (!report.aborted) report.status = leak || uplink?.dnsOutboundPackets > 0 || report.ipv6?.status === 'bypass-confirmed' || uplink?.ipv6TargetOutboundPackets > 0
    ? 'bypass-or-uplink-traffic-observed' : 'inconclusive';
  return report;
}
