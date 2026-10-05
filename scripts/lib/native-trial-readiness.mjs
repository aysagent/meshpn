/** Bounded read-only readiness gate. Rules alone do not prove a working VPN. */
import { setTimeout as delay } from 'node:timers/promises';

const requireReady = (ok, code) => { if (!ok) throw Error(code); };
export async function waitLegacyReady({ run, inspectIpv6, node = process.execPath,
  now = () => performance.now(), sleep = delay, timeoutMs = 60000 }) {
  const started = now(), deadline = started + timeoutMs;
  let attempts = 0, consecutive = 0, identity = null, lastCheck = 'service';
  const boundedRun = async (file, args) => {
    const remaining = deadline - now();
    requireReady(remaining > 0, 'old_ready_timeout');
    const result = await run(file, args, Math.max(1, Math.min(3500, Math.floor(remaining))));
    requireReady(now() < deadline, 'old_ready_timeout');
    return result;
  };
  const service = async () => {
    const raw = await boundedRun('systemctl', ['show', 'clean-vpn.service', '--property=ActiveState,SubState,MainPID']);
    const p = Object.fromEntries(raw.trim().split('\n').map(line => line.split('=')));
    requireReady(p.ActiveState === 'active' && p.SubState === 'running' && /^[1-9]\d*$/.test(p.MainPID), 'service');
    return p.MainPID;
  };
  const tun = async () => {
    const links = JSON.parse(await boundedRun('ip', ['-j', 'address', 'show', 'dev', 'tun0']));
    const link = links.find(l => l.ifname === 'tun0');
    requireReady(Number.isSafeInteger(link?.ifindex) && link.flags?.includes('UP')
      && link.addr_info?.some(a => a.family === 'inet' && a.local === '10.99.0.2'), 'tun');
    return link.ifindex;
  };
  while (now() < deadline) {
    attempts++;
    try {
      lastCheck = 'service'; const pid = await service();
      lastCheck = 'tun'; const index = await tun();
      lastCheck = 'routes';
      for (const target of ['1.0.0.1', '1.1.1.1', '154.62.226.216']) {
        const routes = JSON.parse(await boundedRun('ip', ['-j', '-4', 'route', 'get', target]));
        requireReady(routes.length === 1 && routes[0].dev === (target === '154.62.226.216' ? 'wlan0' : 'tun0'), 'routes');
      }
      lastCheck = 'snat_mss';
      const snat = JSON.parse(await boundedRun(node, ['/usr/local/bin/clean-vpn-usb-snat.mjs', '--status']));
      requireReady(snat.status === 'ready' && snat.mss?.present === 2, 'snat_mss');
      if (inspectIpv6) { lastCheck = 'ipv6_policy'; await inspectIpv6({ run: boundedRun }); }
      lastCheck = 'https';
      // No DNS, proxy, curlrc, insecure TLS or direct-uplink fallback. Retain
      // only success metadata, never this response body in the trial report.
      const trace = await boundedRun('curl', ['-q', '-4', '-f', '-sS', '--noproxy', '*', '--interface', 'tun0',
        '--connect-timeout', '2', '--max-time', '3', '--max-filesize', '4096', 'https://1.1.1.1/cdn-cgi/trace']);
      requireReady(trace.split(/\r?\n/).filter(l => l.startsWith('ip=')).join('') === 'ip=154.62.226.216', 'https');
      lastCheck = 'identity';
      requireReady(await service() === pid && await tun() === index, 'identity');
      const current = `${pid}:${index}`;
      consecutive = current === identity ? consecutive + 1 : 1; identity = current;
      if (consecutive >= 2) return { status: 'ready', attempts, consecutive, seconds: (now() - started) / 1000 };
    } catch {
      // Caller/command errors may contain credentials. Keep only our fixed
      // check label; do not echo arbitrary exception text.
      consecutive = 0; identity = null;
    }
    if (now() < deadline) await sleep(Math.min(250, deadline - now()));
  }
  throw Error(`old_ready_timeout_${lastCheck}`);
}
