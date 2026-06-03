import { execFileSync } from 'child_process';

const IP_EXIT = '10.99.0.1';
const IP_CLIENT = '10.99.0.2';

/** @returns {string[]} */
export function listTunInterfaces() {
  if (process.platform === 'linux') {
    try {
      const out = execFileSync('ip', ['-br', 'link', 'show', 'type', 'tun'], { encoding: 'utf8' });
      return out
        .trim()
        .split('\n')
        .filter(Boolean)
        .map((line) => line.split(/\s+/)[0])
        .filter(Boolean);
    } catch {
      return [];
    }
  }
  if (process.platform === 'darwin') {
    try {
      const out = execFileSync('ifconfig', ['-l'], { encoding: 'utf8' });
      return out.trim().split(/\s+/).filter((n) => /^utun\d+$/.test(n));
    } catch {
      return [];
    }
  }
  return [];
}

/**
 * @param {string} ifname
 * @returns {{ local: string, remote: string } | null}
 */
export function darwinUtunInet(ifname) {
  try {
    const out = execFileSync('ifconfig', [ifname], { encoding: 'utf8' });
    const m = out.match(/inet\s+(\d+\.\d+\.\d+\.\d+)\s+-->?\s+(\d+\.\d+\.\d+\.\d+)/);
    if (!m) return null;
    return { local: m[1], remote: m[2] };
  } catch {
    return null;
  }
}

/**
 * Find Linux tun/tap or macOS utun whose local VPN address matches.
 * @param {string} localIp — 10.99.0.1 (exit) or 10.99.0.2 (client)
 * @returns {string|null}
 */
export function findTunByLocalIp(localIp) {
  if (process.platform === 'linux') {
    try {
      const out = execFileSync('ip', ['-o', '-4', 'addr', 'show'], { encoding: 'utf8' });
      for (const line of out.split('\n')) {
        if (!line.includes(localIp)) continue;
        const m = line.match(/:\s(tun\d+)/);
        if (m) return m[1];
      }
    } catch {
      /* ignore */
    }
    return null;
  }
  if (process.platform === 'darwin') {
    for (const name of listTunInterfaces()) {
      const inet = darwinUtunInet(name);
      if (inet?.local === localIp) return name;
    }
  }
  return null;
}

/**
 * @param {number} [timeoutMs]
 * @returns {Promise<{ exitTun: string, clientTun: string }>}
 */
export async function waitForVpnTunPair(timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const exitTun = findTunByLocalIp(IP_EXIT);
    const clientTun = findTunByLocalIp(IP_CLIENT);
    if (exitTun && clientTun && exitTun !== clientTun) {
      return { exitTun, clientTun };
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  const exitTun = findTunByLocalIp(IP_EXIT);
  const clientTun = findTunByLocalIp(IP_CLIENT);
  throw new Error(
    `VPN TUN pair not found (exit=${exitTun ?? '—'} client=${clientTun ?? '—'}; want ${IP_EXIT} and ${IP_CLIENT})`,
  );
}

/**
 * @param {string[]} before
 * @param {string[]} after
 */
export function diffNewTun(before, after) {
  const set = new Set(before);
  return after.filter((n) => !set.has(n));
}

export function defaultLoopbackExt() {
  return process.platform === 'darwin' ? 'lo0' : 'lo';
}

import { cleanupStaleVpnUtunsDarwin } from './cleanup-darwin.mjs';

export function cleanupStaleVpnUtuns(opts = {}) {
  if (process.platform !== 'darwin') {
    return { ok: true, remaining: [], killed: { cleanVpn: [], utunHelper: [] } };
  }
  return cleanupStaleVpnUtunsDarwin(opts);
}
