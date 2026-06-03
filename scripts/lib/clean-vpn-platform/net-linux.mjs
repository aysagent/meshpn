import { execFileSync } from 'child_process';
import { IP_CLIENT, IP_EXIT, TUN_MTU } from './constants.mjs';

export function execIpFileSync(args, execOpts = {}) {
  const candidates = ['/sbin/ip', '/usr/sbin/ip', 'ip'];
  let lastEnoent = null;
  for (const file of candidates) {
    try {
      return execFileSync(file, args, execOpts);
    } catch (e) {
      if (typeof e === 'object' && e && /** @type {NodeJS.ErrnoException} */ (e).code === 'ENOENT') {
        lastEnoent = e;
        continue;
      }
      throw e;
    }
  }
  if (lastEnoent) throw lastEnoent;
  throw new Error('execIpFileSync failed');
}

function ip(args) {
  execIpFileSync(args, { stdio: 'inherit' });
}

export function findFreeTunNameLinux() {
  try {
    const out = execIpFileSync(['link', 'show'], { encoding: 'utf8' });
    const used = new Set();
    for (const m of out.matchAll(/tun(\d+):/g)) used.add(parseInt(m[1], 10));
    let i = 0;
    while (used.has(i)) i += 1;
    return `tun${i}`;
  } catch {
    return 'tun0';
  }
}

/**
 * @param {'exit'|'client'} role
 * @param {string} ifname
 */
export function setupTunIpLinux(role, ifname) {
  if (role === 'exit') {
    ip(['addr', 'flush', 'dev', ifname]);
    ip(['addr', 'add', `${IP_EXIT}/32`, 'peer', `${IP_CLIENT}/32`, 'dev', ifname]);
  } else {
    ip(['addr', 'flush', 'dev', ifname]);
    ip(['addr', 'add', `${IP_CLIENT}/32`, 'peer', `${IP_EXIT}/32`, 'dev', ifname]);
  }
  ip(['link', 'set', 'dev', ifname, 'mtu', String(TUN_MTU), 'up']);
}

export function getDefaultRouteLinux() {
  try {
    const out = execIpFileSync(['-4', 'route', 'show', 'default'], { encoding: 'utf8' });
    const line = out.trim().split('\n')[0] || '';
    const via = line.match(/default via (\S+)/);
    const dev = line.match(/dev (\S+)/);
    if (via && dev) return { gw: via[1], dev: dev[1] };
    if (dev) return { gw: null, dev: dev[1] };
  } catch {
    /* ignore */
  }
  return null;
}

export function defaultLoopbackExtLinux() {
  return 'lo';
}
